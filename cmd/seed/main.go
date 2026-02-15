package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	// Load minimal config for seeding (no OAuth validation needed)
	cfg, err := config.LoadForSeed()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	client, _, err := database.NewClient(ctx, cfg.Database)
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
		{"Urban Loft Cafe", "urban-cafe"},
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

	hasher := password.NewHasher(cfg.Security)

	// Seed demo user with publicly safe credentials (for development/testing only)
	// These credentials are intentionally public and should NEVER be used in production
	const (
		demoEmail    = "demo@bengobox.dev"
		demoPassword = "DemoUser2024!" // Safe to expose - demo account only
	)

	demoHash, err := hasher.Hash(demoPassword)
	if err != nil {
		log.Fatalf("hash demo password: %v", err)
	}

	demoUser, err := client.User.Create().
		SetEmail(demoEmail).
		SetPasswordHash(demoHash).
		SetStatus("active").
		SetPrimaryTenantID(tenantEntities[0].ID.String()).
		SetProfile(map[string]any{
			"name":       "Demo User",
			"is_demo":    true,
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		demoUser, err = client.User.Query().Where(user.EmailEQ(demoEmail)).Only(ctx)
		if err != nil {
			log.Fatalf("seed demo user: %v", err)
		}
		log.Printf("✓ Demo user exists: %s", demoEmail)
	} else {
		log.Printf("✓ Created demo user: %s", demoEmail)
	}

	// Add demo user membership to all tenants with 'member' role (not superuser)
	for _, tenantEnt := range tenantEntities {
		// Check if membership already exists to prevent duplicates
		exists, err := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(demoUser.ID),
				tenantmembership.TenantID(tenantEnt.ID),
			).
			Exist(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error checking membership for %s: %v", tenantEnt.Slug, err)
			continue
		}
		if exists {
			log.Printf("  ✓ Demo membership exists for %s", tenantEnt.Slug)
			continue
		}

		_, err = client.TenantMembership.Create().
			SetUserID(demoUser.ID).
			SetTenantID(tenantEnt.ID).
			SetRoles([]string{"member"}).
			Save(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error creating demo membership for %s: %v", tenantEnt.Slug, err)
		} else {
			log.Printf("  ✓ Added demo member role in %s", tenantEnt.Slug)
		}
	}

	// Seed admin user from environment (required for real admin access)
	// Admin credentials MUST come from environment variables - never hardcoded
	adminEmail := os.Getenv("SEED_ADMIN_EMAIL")
	adminPassword := os.Getenv("SEED_ADMIN_PASSWORD")

	if adminEmail != "" && adminPassword != "" {
		adminHash, err := hasher.Hash(adminPassword)
		if err != nil {
			log.Fatalf("hash admin password: %v", err)
		}

		adminUser, err := client.User.Create().
			SetEmail(adminEmail).
			SetPasswordHash(adminHash).
			SetStatus("active").
			SetPrimaryTenantID(tenantEntities[0].ID.String()).
			Save(ctx)
		if err != nil {
			adminUser, err = client.User.Query().Where(user.EmailEQ(adminEmail)).Only(ctx)
			if err != nil {
				log.Fatalf("seed admin user: %v", err)
			}
			log.Printf("✓ Admin user exists: %s", adminEmail)
		} else {
			log.Printf("✓ Created admin user: %s", adminEmail)
		}

		// Add superuser membership to all tenants
		for _, tenantEnt := range tenantEntities {
			// Check if membership already exists to prevent duplicates
			exists, err := client.TenantMembership.Query().
				Where(
					tenantmembership.UserID(adminUser.ID),
					tenantmembership.TenantID(tenantEnt.ID),
				).
				Exist(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error checking admin membership for %s: %v", tenantEnt.Slug, err)
				continue
			}
			if exists {
				log.Printf("  ✓ Admin membership exists for %s", tenantEnt.Slug)
				continue
			}

			_, err = client.TenantMembership.Create().
				SetUserID(adminUser.ID).
				SetTenantID(tenantEnt.ID).
				SetRoles([]string{"superuser"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating admin membership for %s: %v", tenantEnt.Slug, err)
			} else {
				log.Printf("  ✓ Added superuser role in %s", tenantEnt.Slug)
			}
		}
	} else {
		log.Printf("⚠️  No admin credentials provided (set SEED_ADMIN_EMAIL and SEED_ADMIN_PASSWORD)")
	}

	log.Printf("")
	log.Printf("========================================")
	log.Printf("✅ Seeding completed successfully!")
	log.Printf("========================================")
	log.Printf("Demo Account (safe to share):")
	log.Printf("  Email: %s", demoEmail)
	log.Printf("  Password: %s", demoPassword)
	log.Printf("  Role: member (limited access)")
	log.Printf("")
	if adminEmail != "" {
		log.Printf("Admin Account (from environment):")
		log.Printf("  Email: %s", adminEmail)
		log.Printf("  Role: superuser (full access)")
	}
	log.Printf("")
	log.Printf("Tenants seeded: %d", len(tenants))
	for _, te := range tenantEntities {
		log.Printf("  - %s (%s)", te.Name, te.Slug)
	}
	log.Printf("========================================")

	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
	_ = uuid.New()
}
