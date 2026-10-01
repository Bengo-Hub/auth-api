package platformbackup

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	sharedcache "github.com/Bengo-Hub/cache"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/modules/platformbackup/destination"
)

// schedulerLockPrefix keys the Redis lease that makes each hourly tick run on ONE replica.
// It replaced a session pg_try_advisory_lock, which is unreliable through PgBouncer's
// transaction pooling (lock and unlock can land on different server connections, leaking the
// lock or letting a second replica in).
const schedulerLockPrefix = "auth:platformbackup:tick"

// SchedulerConfig configures the platform-wide pg_dumpall auto-backup + retention churn.
// Enabled is a MASTER switch (BACKUP_SCHEDULE_ENABLED, default true); the actual backup run
// is still gated by the DB-stored auto_enabled flag (opt-in, default OFF).
type SchedulerConfig struct {
	Enabled   bool   // BACKUP_SCHEDULE_ENABLED (default true)
	BackupDir string // BACKUP_DIR (where platform_dumpall_*.sql.gz files are written)
	DSN       string // Postgres connection string passed to pg_dumpall
}

// Scheduler runs a daily platform-wide pg_dumpall DR backup + retention churn. It uses a
// time-until-next-hour timer loop (no external cron dep) and a once-per-hour Redis lease so
// only one replica performs each tick. The backup ONLY runs when the DB-stored
// auto_enabled flag is true (opt-in; default OFF).
type Scheduler struct {
	svc      *Service
	rdb      redis.UniversalClient
	cfg      SchedulerConfig
	log      *zap.Logger
	uploader *destination.Uploader // optional; mirrors each dump to a configured remote
}

// NewScheduler builds the platform backup scheduler.
func NewScheduler(svc *Service, rdb redis.UniversalClient, cfg SchedulerConfig, log *zap.Logger) *Scheduler {
	if cfg.BackupDir == "" {
		cfg.BackupDir = "/data/backups"
	}
	return &Scheduler{svc: svc, rdb: rdb, cfg: cfg, log: log.Named("platformbackup.Scheduler")}
}

// WithUploader attaches a best-effort remote mirror for each written dump. When
// set, the local PVC copy remains the durable primary + fallback. Returns the
// scheduler for chaining.
func (sc *Scheduler) WithUploader(u *destination.Uploader) *Scheduler {
	sc.uploader = u
	return sc
}

// Start launches the scheduler goroutine. It runs a churn-only pass immediately on startup,
// then wakes hourly and runs the backup+churn when the activated hour matches. Stops when
// ctx is cancelled.
func (sc *Scheduler) Start(ctx context.Context) {
	if !sc.cfg.Enabled {
		sc.log.Info("platform backup scheduler disabled (BACKUP_SCHEDULE_ENABLED=false)")
		return
	}
	sc.log.Info("platform backup scheduler started", zap.String("backup_dir", sc.cfg.BackupDir))

	go func() {
		// Startup churn (replica-guarded, backupHour=-1) so stale files are pruned even
		// between scheduled runs.
		sc.runGuarded(ctx, -1)

		for {
			next := nextTopOfHour(time.Now())
			timer := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				sc.runGuarded(ctx, time.Now().Hour())
			}
		}
	}()
}

// runGuarded runs the tick on one replica: the platform backup (only when the DB
// auto_enabled flag is true AND backupHour matches the activated schedule hour) then the
// retention churn. Hourly ticks run once per hour fleet-wide (RunOnce keyed by the hour); the
// startup churn (backupHour -1) only needs mutual exclusion.
func (sc *Scheduler) runGuarded(ctx context.Context, backupHour int) {
	var ran bool
	var err error
	if backupHour < 0 {
		ran, err = sharedcache.RunExclusive(ctx, sc.rdb, sc.log, schedulerLockPrefix+":startup", 30*time.Minute, sc.tick(backupHour))
	} else {
		ran, err = sharedcache.RunOnce(ctx, sc.rdb, sc.log, sharedcache.PeriodKey(schedulerLockPrefix, time.Hour), time.Hour, sc.tick(backupHour))
	}
	if err != nil {
		sc.log.Warn("scheduler: tick not run", zap.Bool("ran", ran), zap.Error(err))
	} else if !ran {
		sc.log.Debug("scheduler: another replica owns this tick; skipping")
	}
}

func (sc *Scheduler) tick(backupHour int) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		return sc.runTick(ctx, backupHour)
	}
}

func (sc *Scheduler) runTick(ctx context.Context, backupHour int) error {
	settings, err := sc.svc.Get(ctx)
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}

	// OPT-IN gate: never run the platform backup unless explicitly activated.
	if !settings.AutoEnabled {
		sc.log.Debug("platform auto-backup inactive (auto_enabled=false); skipping backup")
	} else if backupHour >= 0 && settings.ScheduleHour == backupHour {
		if err := sc.runPlatformBackup(ctx); err != nil {
			sc.log.Warn("scheduler: platform backup failed", zap.Error(err))
		}
	}

	// Always run retention churn so stale files are pruned regardless of the activation state.
	sc.churn(settings.RetentionDays)
	return nil
}

// runPlatformBackup executes pg_dumpall for the whole cluster and writes a gzipped dump to
// {BackupDir}/platform_dumpall_<UTC timestamp>.sql.gz. If pg_dumpall is not on PATH it logs a
// warning and returns nil (does NOT crash). All failures are logged; never panics.
func (sc *Scheduler) runPlatformBackup(ctx context.Context) error {
	if _, err := exec.LookPath("pg_dumpall"); err != nil {
		sc.log.Warn("pg_dumpall not found on PATH; skipping platform backup", zap.Error(err))
		return nil
	}

	if err := os.MkdirAll(sc.cfg.BackupDir, 0o750); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	outPath := filepath.Join(sc.cfg.BackupDir, fmt.Sprintf("platform_dumpall_%s.sql.gz", ts))
	tmpPath := outPath + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	gz := gzip.NewWriter(f)

	// #nosec G204 -- DSN is operator-provided config, not user input.
	cmd := exec.CommandContext(ctx, "pg_dumpall", "--dbname="+sc.cfg.DSN)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = gz.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = gz.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("start pg_dumpall: %w", err)
	}

	if _, copyErr := io.Copy(gz, stdout); copyErr != nil {
		_ = cmd.Wait()
		_ = gz.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("copy dump: %w", copyErr)
	}

	if waitErr := cmd.Wait(); waitErr != nil {
		_ = gz.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("pg_dumpall exited with error: %w", waitErr)
	}

	if err := gz.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close gzip: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close file: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("finalize backup file: %w", err)
	}

	sc.log.Info("platform backup written", zap.String("file", outPath))

	// Best-effort mirror to a configured remote destination. The PVC copy above
	// is the durable primary + fallback; a mirror failure never fails the backup.
	if sc.uploader != nil {
		_ = sc.uploader.Mirror(ctx, outPath, filepath.Base(outPath))
	}
	return nil
}

// churn deletes *.sql.gz platform backups older than retentionDays. All failures are logged.
func (sc *Scheduler) churn(retentionDays int) {
	if retentionDays <= 0 {
		retentionDays = DefaultRetentionDays
	}
	entries, err := os.ReadDir(sc.cfg.BackupDir)
	if err != nil {
		// Missing dir is fine — nothing to churn yet.
		if !os.IsNotExist(err) {
			sc.log.Warn("scheduler: read backup dir failed", zap.Error(err))
		}
		return
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			p := filepath.Join(sc.cfg.BackupDir, e.Name())
			if err := os.Remove(p); err != nil {
				sc.log.Warn("scheduler: prune failed", zap.String("file", p), zap.Error(err))
				continue
			}
			sc.log.Info("pruned stale platform backup", zap.String("file", p))
		}
	}
}

// nextTopOfHour returns the next HH:00 strictly after now (service-local time).
func nextTopOfHour(now time.Time) time.Time {
	return now.Truncate(time.Hour).Add(time.Hour)
}
