package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx := context.Background()
	client, err := database.NewClient(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer client.Close()

	// Ensure schema exists
	if err := database.RunMigrations(ctx, client); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	// Create or fetch default tenant
	tenantEntity, err := client.Tenant.Query().Where(tenant.SlugEQ("codevertex")).Only(ctx)
	if err != nil {
		tenantEntity, err = client.Tenant.Create().
			SetName("CodeVertex").
			SetSlug("codevertex").
			SetStatus("active").
			Save(ctx)
		if err != nil {
			log.Fatalf("create tenant: %v", err)
		}
	}

	// Seed admin user
	adminEmail := "admin@codevertexitsolutions.com"
	adminPassword := os.Getenv("SEED_ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "ChangeMe123!"
	}
	hasher := password.NewHasher(cfg.Security)
	hash, err := hasher.Hash(adminPassword)
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}

	userEntity, err := client.User.Create().
		SetEmail(adminEmail).
		SetPasswordHash(hash).
		SetStatus("active").
		SetPrimaryTenantID(tenantEntity.ID.String()).
		Save(ctx)
	if err != nil {
		// Try to fetch existing
		userEntity, err = client.User.Query().Where(user.EmailEQ(adminEmail)).Only(ctx)
		if err != nil {
			log.Fatalf("seed user: %v", err)
		}
	}

	// Add membership with superuser role
	_, _ = client.TenantMembership.Create().
		SetUserID(userEntity.ID).
		SetTenantID(tenantEntity.ID).
		SetRoles([]string{"superuser"}).
		Save(ctx)

	log.Printf("seed completed: admin=%s tenant=%s password=%s\n", adminEmail, tenantEntity.Slug, adminPassword)
	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
	_ = uuid.New()
}
