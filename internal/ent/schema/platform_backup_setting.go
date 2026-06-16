package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// PlatformBackupSetting is the SINGLE-ROW platform-wide auto-backup (pg_dumpall DR)
// activation setting. Platform backups run ONLY when auto_enabled=true (default false —
// activated by a platform admin from the UI). Singleton enforced by a unique `singleton` key.
type PlatformBackupSetting struct {
	ent.Schema
}

func (PlatformBackupSetting) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Immutable(),
		field.String("singleton").Unique().Immutable().Comment("Fixed key enforcing a single platform-wide settings row (always 'platform')"),
		field.Bool("auto_enabled").Default(false).Comment("Platform backup runs ONLY when true (default off — activate from UI)"),
		field.Int("schedule_hour").Default(2).Comment("Service-local hour 0-23 for the daily platform backup"),
		field.Int("retention_days").Default(4).Comment("Delete platform backups older than this many days"),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}
