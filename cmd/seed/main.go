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

	log.Println("Starting seed process...")

	// Create or fetch default tenants
	tenants := []struct {
		name string
		slug string
	}{
		{"CodeVertex", "codevertex"},
		{"Kura Weigh", "kura"},
	}

	var tenantEntities []*struct {
		ID   uuid.UUID
		Name string
		Slug string
	}

	for _, t := range tenants {
		tenantEntity, err := client.Tenant.Query().Where(tenant.SlugEQ(t.slug)).Only(ctx)
		if err != nil {
			tenantEntity, err = client.Tenant.Create().
				SetName(t.name).
				SetSlug(t.slug).
				SetStatus("active").
				Save(ctx)
			if err != nil {
				log.Fatalf("create tenant %s: %v", t.slug, err)
			}
			log.Printf("✓ Created tenant: %s (%s)", t.name, t.slug)
		} else {
			log.Printf("✓ Tenant exists: %s (%s)", t.name, t.slug)
		}

		tenantEntities = append(tenantEntities, &struct {
			ID   uuid.UUID
			Name string
			Slug string
		}{
			ID:   tenantEntity.ID,
			Name: tenantEntity.Name,
			Slug: tenantEntity.Slug,
		})
	}

	// Seed admin user (for all tenants)
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
		SetPrimaryTenantID(tenantEntities[0].ID.String()).
		Save(ctx)
	if err != nil {
		// Try to fetch existing
		userEntity, err = client.User.Query().Where(user.EmailEQ(adminEmail)).Only(ctx)
		if err != nil {
			log.Fatalf("seed user: %v", err)
		}
		log.Printf("✓ Admin user exists: %s", adminEmail)
	} else {
		log.Printf("✓ Created admin user: %s", adminEmail)
	}

	// Add superuser membership to all tenants
	for _, tenantEnt := range tenantEntities {
		_, err = client.TenantMembership.Create().
			SetUserID(userEntity.ID).
			SetTenantID(tenantEnt.ID).
			SetRoles([]string{"superuser"}).
			Save(ctx)
		if err != nil {
			// Might already exist, that's okay
			log.Printf("  (membership for %s may already exist)", tenantEnt.Slug)
		} else {
			log.Printf("  ✓ Added superuser role in %s", tenantEnt.Slug)
		}
	}

	log.Printf("")
	log.Printf("========================================")
	log.Printf("✅ Seeding completed successfully!")
	log.Printf("========================================")
	log.Printf("Admin Email: %s", adminEmail)
	log.Printf("Password: %s", adminPassword)
	log.Printf("Tenants seeded: %d", len(tenants))
	for _, te := range tenantEntities {
		log.Printf("  - %s (%s)", te.Name, te.Slug)
	}
	log.Printf("========================================")

	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
	_ = uuid.New()
}
