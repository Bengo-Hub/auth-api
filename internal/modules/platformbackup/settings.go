package platformbackup

import (
	"context"

	"github.com/bengobox/auth-api/internal/ent"
	entpbs "github.com/bengobox/auth-api/internal/ent/platformbackupsetting"
)

// DefaultRetentionDays is the fallback retention window for platform backups.
const DefaultRetentionDays = 4

// singletonKey is the fixed key value enforcing a single platform-wide settings row.
const singletonKey = "platform"

// Settings is the platform-wide auto-backup activation configuration (single row).
type Settings struct {
	AutoEnabled   bool `json:"auto_enabled"`
	ScheduleHour  int  `json:"schedule_hour"`
	RetentionDays int  `json:"retention_days"`
}

// DefaultSettings returns the inactive (opt-in OFF) defaults used when no row exists.
func DefaultSettings() Settings {
	return Settings{AutoEnabled: false, ScheduleHour: 2, RetentionDays: DefaultRetentionDays}
}

// Service reads and writes the single-row platform backup settings via the ent client.
type Service struct {
	orm *ent.Client
}

// NewService builds a platform backup settings service.
func NewService(orm *ent.Client) *Service { return &Service{orm: orm} }

// Get returns the current platform backup settings, or inactive defaults when no row exists.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	row, err := s.orm.PlatformBackupSetting.Query().Where(entpbs.Singleton(singletonKey)).Only(ctx)
	if err != nil {
		return DefaultSettings(), nil //nolint:nilerr // no row = inactive defaults
	}
	return Settings{AutoEnabled: row.AutoEnabled, ScheduleHour: row.ScheduleHour, RetentionDays: row.RetentionDays}, nil
}

// Upsert creates or updates the single platform backup settings row.
func (s *Service) Upsert(ctx context.Context, in Settings) (Settings, error) {
	if in.ScheduleHour < 0 || in.ScheduleHour > 23 {
		in.ScheduleHour = 2
	}
	if in.RetentionDays <= 0 {
		in.RetentionDays = DefaultRetentionDays
	}
	existing, err := s.orm.PlatformBackupSetting.Query().Where(entpbs.Singleton(singletonKey)).Only(ctx)
	if err == nil {
		_, err = existing.Update().SetAutoEnabled(in.AutoEnabled).SetScheduleHour(in.ScheduleHour).SetRetentionDays(in.RetentionDays).Save(ctx)
		return in, err
	}
	_, err = s.orm.PlatformBackupSetting.Create().SetSingleton(singletonKey).SetAutoEnabled(in.AutoEnabled).SetScheduleHour(in.ScheduleHour).SetRetentionDays(in.RetentionDays).Save(ctx)
	return in, err
}
