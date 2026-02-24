package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
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
		{"Masterspace Solutions", "mss"},
		{"Urban Loft Cafe", "urban-loft"},
		{"Kenya Urban Roads Authority", "kura"},
		{"UltiChange", "ultichange"},
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

	// Seed tenant-specific admin for Urban Loft Cafe
	urbanLoftTenant := tenantEntities[2] // "Urban Loft Cafe" / "urban-loft"
	tenantAdminEmail := "admin@theurbanloftcafe.com"
	tenantAdminPassword := "TenantAdmin2024!"
	tenantAdminHash, _ := hasher.Hash(tenantAdminPassword)

	tenantAdmin, err := client.User.Create().
		SetEmail(tenantAdminEmail).
		SetPasswordHash(tenantAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(urbanLoftTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "Urban Loft Admin",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		tenantAdmin, err = client.User.Query().Where(user.EmailEQ(tenantAdminEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed tenant admin: %v", err)
		} else {
			log.Printf("✓ Tenant admin exists: %s", tenantAdminEmail)
		}
	} else {
		log.Printf("✓ Created tenant admin: %s", tenantAdminEmail)
	}

	if tenantAdmin != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(tenantAdmin.ID),
				tenantmembership.TenantID(urbanLoftTenant.ID),
			).Exist(ctx)
		if !exists {
			_, err = client.TenantMembership.Create().
				SetUserID(tenantAdmin.ID).
				SetTenantID(urbanLoftTenant.ID).
				SetRoles([]string{"admin"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating tenant admin membership: %v", err)
			} else {
				log.Printf("  ✓ Added admin role in %s", urbanLoftTenant.Slug)
			}
		}
	}

	// Seed demo customer
	customerEmail := "customer@demo.com"
	customerPassword := "Customer2024!"
	customerHash, _ := hasher.Hash(customerPassword)

	customerUser, err := client.User.Create().
		SetEmail(customerEmail).
		SetPasswordHash(customerHash).
		SetStatus("active").
		SetPrimaryTenantID(urbanLoftTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "Demo Customer",
			"phone":      "+254700000001",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		customerUser, err = client.User.Query().Where(user.EmailEQ(customerEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed customer: %v", err)
		} else {
			log.Printf("✓ Customer exists: %s", customerEmail)
		}
	} else {
		log.Printf("✓ Created customer: %s", customerEmail)
	}

	if customerUser != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(customerUser.ID),
				tenantmembership.TenantID(urbanLoftTenant.ID),
			).Exist(ctx)
		if !exists {
			_, _ = client.TenantMembership.Create().
				SetUserID(customerUser.ID).
				SetTenantID(urbanLoftTenant.ID).
				SetRoles([]string{"member"}).
				Save(ctx)
			log.Printf("  ✓ Added member role in %s", urbanLoftTenant.Slug)
		}
	}

	// Seed demo rider
	riderEmail := "rider@demo.com"
	riderPassword := "Rider2024!"
	riderHash, _ := hasher.Hash(riderPassword)

	riderUser, err := client.User.Create().
		SetEmail(riderEmail).
		SetPasswordHash(riderHash).
		SetStatus("active").
		SetPrimaryTenantID(urbanLoftTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "Demo Rider",
			"phone":      "+254700000002",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		riderUser, err = client.User.Query().Where(user.EmailEQ(riderEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed rider: %v", err)
		} else {
			log.Printf("✓ Rider exists: %s", riderEmail)
		}
	} else {
		log.Printf("✓ Created rider: %s", riderEmail)
	}

	if riderUser != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(riderUser.ID),
				tenantmembership.TenantID(urbanLoftTenant.ID),
			).Exist(ctx)
		if !exists {
			_, _ = client.TenantMembership.Create().
				SetUserID(riderUser.ID).
				SetTenantID(urbanLoftTenant.ID).
				SetRoles([]string{"member"}).
				Save(ctx)
			log.Printf("  ✓ Added member role in %s", urbanLoftTenant.Slug)
		}
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

	// Seed OAuth Clients (upsert — always update redirect_uris so seed stays authoritative)
	log.Println("Seeding OAuth Clients...")
	type oauthClientSpec struct {
		ID           string
		Name         string
		RedirectURIs []string
		Public       bool
	}
	oauthClients := []oauthClientSpec{
		{
			// notifications-ui: callback at /{orgSlug}/auth/callback
			ID:   "notifications-ui",
			Name: "BengoBox Notifications UI",
			RedirectURIs: []string{
				"https://notifications.codevertexitsolutions.com/urban-loft/auth/callback",
				"http://localhost:3000/urban-loft/auth/callback",
				"http://localhost:3000/codevertex/auth/callback",
			},
			Public: true,
		},
		{
			// ordering-ui: callback at /{orgSlug}/auth/callback (tenant-aware)
			ID:   "ordering-ui",
			Name: "BengoBox Ordering UI",
			RedirectURIs: []string{
				"https://ordersapp.codevertexitsolutions.com/urban-loft/auth/callback",
				"http://localhost:3001/urban-loft/auth/callback",
				"http://localhost:3001/codevertex/auth/callback",
			},
			Public: true,
		},
		{
			// rider-app: fixed callback at /auth/callback (not tenant-aware)
			ID:   "rider-app",
			Name: "BengoBox Rider App",
			RedirectURIs: []string{
				"https://rider.codevertexitsolutions.com/auth/callback",
				"http://localhost:3002/auth/callback",
			},
			Public: true,
		},
		{
			// cafe-website: uses NextAuth; callback at /api/auth/callback/bengobox-auth
			ID:   "cafe-website",
			Name: "Urban Loft Cafe Website",
			RedirectURIs: []string{
				"https://theurbanloftcafe.com/api/auth/callback/bengobox-auth",
				"http://localhost:3000/api/auth/callback/bengobox-auth",
			},
			Public: false,
		},
	}

	for _, c := range oauthClients {
		existing, queryErr := client.OAuthClient.Query().Where(oauthclient.ClientID(c.ID)).Only(ctx)
		if queryErr != nil && !ent.IsNotFound(queryErr) {
			log.Printf("  ⚠️  Error checking client %s: %v", c.ID, queryErr)
			continue
		}

		if existing != nil {
			// Upsert: update redirect_uris so re-seeding fixes misconfigured clients
			_, err = existing.Update().
				SetName(c.Name).
				SetRedirectUris(c.RedirectURIs).
				SetPublic(c.Public).
				SetAllowedScopes([]string{"openid", "profile", "email", "offline_access"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error updating client %s: %v", c.ID, err)
			} else {
				log.Printf("  ✓ Updated client: %s", c.ID)
			}
			continue
		}

		_, err = client.OAuthClient.Create().
			SetClientID(c.ID).
			SetName(c.Name).
			SetRedirectUris(c.RedirectURIs).
			SetPublic(c.Public).
			SetAllowedScopes([]string{"openid", "profile", "email", "offline_access"}).
			Save(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error creating client %s: %v", c.ID, err)
		} else {
			log.Printf("  ✓ Created client: %s", c.ID)
		}
	}

	log.Printf("========================================")

	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
	_ = uuid.New()
}
