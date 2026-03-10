package database

import (
	"context"
	"database/sql"
	"fmt"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/migrate"
	_ "github.com/jackc/pgx/v5/stdlib" // register pgx driver
)

// NewClient initialises an Ent client backed by PostgreSQL.
// Returns both the Ent client and the underlying *sql.DB for use by the outbox repository.
func NewClient(ctx context.Context, cfg config.DatabaseConfig) (*ent.Client, *sql.DB, error) {
	db, err := sql.Open("pgx", cfg.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("open postgres connection: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	if err := db.PingContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("ping postgres: %w", err)
	}

	drv := entsql.OpenDB(dialect.Postgres, db)
	client := ent.NewClient(ent.Driver(drv))
	return client, db, nil
}

// RunMigrations executes Atlas versioned migrations.
func RunMigrations(ctx context.Context, client *ent.Client) error {
	return client.Schema.Create(ctx, 
		schema.WithDir(migrate.Dir),
	)
}
