package platformbackup

import (
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// schedulerAdvisoryLockKey is a fixed, service-unique key for the Postgres session
// advisory lock that guards the daily run so only ONE replica executes it. The value is
// arbitrary but stable; it differs per service to avoid cross-service contention on a
// shared cluster. ("AUTB" — auth backup)
const schedulerAdvisoryLockKey int64 = 0x4155_5442 // 'A','U','T','B'

// SchedulerConfig configures the platform-wide pg_dumpall auto-backup + retention churn.
// Enabled is a MASTER switch (BACKUP_SCHEDULE_ENABLED, default true); the actual backup run
// is still gated by the DB-stored auto_enabled flag (opt-in, default OFF).
type SchedulerConfig struct {
	Enabled   bool   // BACKUP_SCHEDULE_ENABLED (default true)
	BackupDir string // BACKUP_DIR (where platform_dumpall_*.sql.gz files are written)
	DSN       string // Postgres connection string passed to pg_dumpall
}

// Scheduler runs a daily platform-wide pg_dumpall DR backup + retention churn. It uses a
// time-until-next-hour timer loop (no external cron dep) and a Postgres advisory lock so
// only one replica performs the work. The backup ONLY runs when the DB-stored
// auto_enabled flag is true (opt-in; default OFF).
type Scheduler struct {
	svc *Service
	db  *sql.DB
	cfg SchedulerConfig
	log *zap.Logger
}

// NewScheduler builds the platform backup scheduler.
func NewScheduler(svc *Service, db *sql.DB, cfg SchedulerConfig, log *zap.Logger) *Scheduler {
	if cfg.BackupDir == "" {
		cfg.BackupDir = "/data/backups"
	}
	return &Scheduler{svc: svc, db: db, cfg: cfg, log: log.Named("platformbackup.Scheduler")}
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

// runGuarded acquires the advisory lock and, if won, runs the platform backup (only when
// the DB auto_enabled flag is true AND backupHour matches the activated schedule hour) then
// runs the retention churn. One replica per tick.
func (sc *Scheduler) runGuarded(ctx context.Context, backupHour int) {
	conn, err := sc.db.Conn(ctx)
	if err != nil {
		sc.log.Warn("scheduler: acquire conn failed", zap.Error(err))
		return
	}
	defer func() { _ = conn.Close() }()

	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, schedulerAdvisoryLockKey).Scan(&got); err != nil {
		sc.log.Warn("scheduler: advisory lock failed", zap.Error(err))
		return
	}
	if !got {
		sc.log.Debug("scheduler: another replica holds the lock; skipping")
		return
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schedulerAdvisoryLockKey)
	}()

	settings, err := sc.svc.Get(ctx)
	if err != nil {
		sc.log.Warn("scheduler: load settings failed", zap.Error(err))
		return
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
