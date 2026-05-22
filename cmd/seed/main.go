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

	// 3. Seed demo user (primary tenant = codevertex-demo, last in list)
	if err := seedDemoUser(ctx, client, hasher, tenantEntities); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	// 4. Seed platform super admin
	if err := seedAdminUser(ctx, client, hasher, tenantEntities); err != nil {
		log.Fatalf("seed admin user: %v", err)
	}

	// 5. Seed codevertex-demo tenant admin (index 6 / last)
	demoTenant := tenantEntities[len(tenantEntities)-1]
	if err := seedDemoTenantAdmin(ctx, client, hasher, demoTenant); err != nil {
		log.Printf("⚠️  seed demo tenant admin: %v", err)
	}

	// 6. Seed Urban Loft Cafe tenant admin (index 2)
	if err := seedUrbanLoftAdmin(ctx, client, hasher, tenantEntities[2]); err != nil {
		log.Printf("⚠️  seed urban loft admin: %v", err)
	}

	// 7. Seed cross-platform demo staff under codevertex-demo
	if err := seedDemoStaff(ctx, client, hasher, demoTenant); err != nil {
		log.Printf("⚠️  seed demo staff: %v", err)
	}

	// 8. Seed TruLoad demo admin (index 5)
	if err := seedTruLoadAdmin(ctx, client, hasher, tenantEntities[5]); err != nil {
		log.Printf("⚠️  seed truload admin: %v", err)
	}

	// 9. Seed KURA admin (index 3)
	if err := seedKURAAdmin(ctx, client, hasher, tenantEntities[3]); err != nil {
		log.Printf("⚠️  seed kura admin: %v", err)
	}

	// 10. Seed generic staff users for all tenants
	if err := seedTenantStaffUsers(ctx, client, hasher, tenantEntities); err != nil {
		log.Printf("⚠️  seed tenant staff users: %v", err)
	}

	// 11. Seed permissions and role-permission mappings
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
