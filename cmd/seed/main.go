package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/password"
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

	// 1. Seed tenants
	tenantEntities, err := seedTenants(ctx, client)
	if err != nil {
		log.Fatalf("seed tenants: %v", err)
	}

	// 2. Seed outlets
	log.Println("Seeding outlets...")
	for _, te := range tenantEntities {
		if err := seedOutletsForTenant(ctx, client, te.ID, te.Slug); err != nil {
			log.Printf("  ⚠️  outlets for %s: %v", te.Slug, err)
		}
	}

	hasher := password.NewHasher(cfg.Security)

	// Targeted run: provision ONLY the Masterspace (mss) staff for SSO, then exit.
	// Used in-cluster: `SEED_ONLY=mss-users SEED_MSS_PASSWORD=... /app/seed`.
	if os.Getenv("SEED_ONLY") == "mss-users" {
		if err := seedMasterspaceUsers(ctx, client, hasher, tenantEntities); err != nil {
			log.Fatalf("seed masterspace users: %v", err)
		}
		log.Println("✅ Masterspace users seeded.")
		return
	}

	// 3. Seed demo user (primary tenant = codevertex-demo, last in list)
	if err := seedDemoUser(ctx, client, hasher, tenantEntities); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	// 4. Seed platform super admin
	if err := seedAdminUser(ctx, client, hasher, tenantEntities); err != nil {
		log.Fatalf("seed admin user: %v", err)
	}

	// 5. Seed codevertex-demo tenant admin (last in list)
	demoTenant := tenantEntities[len(tenantEntities)-1]
	if err := seedDemoTenantAdmin(ctx, client, hasher, demoTenant); err != nil {
		log.Printf("⚠️  seed demo tenant admin: %v", err)
	}

	// 6. Seed cross-platform demo staff under codevertex-demo
	if err := seedDemoStaff(ctx, client, hasher, demoTenant); err != nil {
		log.Printf("⚠️  seed demo staff: %v", err)
	}

	// 6b. Seed ERP demo staff (one user per ERP service role) under codevertex-demo.
	// These carry ERP role names (hr_manager, ceo, ict_officer, …) as global roles so
	// the erp-api JIT mapping (authmanagement/sso.py) can be exercised end-to-end.
	if err := seedERPDemoStaff(ctx, client, hasher, demoTenant); err != nil {
		log.Printf("⚠️  seed erp demo staff: %v", err)
	}

	// 7. Seed KURA admin (index 2)
	if err := seedKURAAdmin(ctx, client, hasher, tenantEntities[2]); err != nil {
		log.Printf("⚠️  seed kura admin: %v", err)
	}

	// 9. Seed generic staff users for all tenants
	if err := seedTenantStaffUsers(ctx, client, hasher, tenantEntities); err != nil {
		log.Printf("⚠️  seed tenant staff users: %v", err)
	}

	// 9b. Seed real Masterspace (mss) staff for SSO.
	if err := seedMasterspaceUsers(ctx, client, hasher, tenantEntities); err != nil {
		log.Printf("⚠️  seed masterspace users: %v", err)
	}

	// 10. Seed permissions and role-permission mappings
	permissionIDs, err := seedPermissions(ctx, client)
	if err != nil {
		log.Printf("⚠️  seed permissions: %v", err)
	}
	if err := seedRoles(ctx, client, permissionIDs); err != nil {
		log.Printf("⚠️  seed roles: %v", err)
	}

	// 12. Seed platform-level OAuth integration configurations (social logins)
	if err := seedIntegrations(ctx, client, cfg.Token.Issuer); err != nil {
		log.Printf("⚠️  Failed to seed integrations: %v", err)
	}

	// 13. Seed OAuth clients
	if err := seedOAuthClients(ctx, client, tenantEntities); err != nil {
		log.Printf("⚠️  seed oauth clients: %v", err)
	}

	// 13b. Backfill redirect URIs for tenants created after the seed (e.g. via admin UI).
	// seedOAuthClients only covers the 5 hard-coded seed tenants; this step ensures
	// every other active tenant in the DB also gets its /{slug}/auth/callback URIs registered.
	log.Println("Backfilling redirect URIs for post-seed tenants...")
	seedSlugSet := make(map[string]bool, len(tenantEntities))
	for _, te := range tenantEntities {
		seedSlugSet[te.Slug] = true
	}
	if err := backfillTenantRedirectURIs(ctx, client, seedSlugSet); err != nil {
		log.Printf("⚠️  backfill redirect URIs: %v", err)
	}

	// 14. Seed legacy platform API key
	log.Println("Seeding platform API key (legacy)...")
	if err := seedPlatformAPIKey(ctx, client, tenantEntities[0].ID); err != nil {
		log.Printf("⚠️  Failed to seed platform API key: %v", err)
	}

	// 15. Seed platform App token (new S2S mechanism)
	log.Println("Seeding platform App token...")
	if err := seedPlatformApp(ctx, client); err != nil {
		log.Printf("⚠️  Failed to seed platform App: %v", err)
	}

	log.Println("✅ Seeding completed successfully!")
	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
}
