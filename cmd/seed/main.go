package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	"github.com/bengobox/auth-api/internal/ent/permission"
	"github.com/bengobox/auth-api/internal/ent/rolepermission"
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

	// Default tenants (align with notifications-api and all SSO-integrating services).
	// 1. Codevertex = platform owner (not a business tenant; default super_admin scope).
	// 2–5. Masterspace, Urban Loft, KURA, UltiChange = tenants with base domains.
	// All tenants use DB-generated UUIDs (no SetID); tenant slug must be consistent across auth and all services.
	tenants := []struct {
		name            string
		slug            string
		baseDomain      string
		isPlatformOwner bool
	}{
		{"CodeVertex", "codevertex", "codevertexitsolutions.com", true},
		{"Masterspace Solutions", "mss", "masterspace.co.ke", false},
		{"Urban Loft Cafe", "urban-loft", "theurbanloftcafe.com", false},
		{"Kenya Urban Roads Authority (KURA)", "kura", "kura.go.ke", false},
		{"UltiChange", "ultichange", "ultichange.org", false},
	}

	var tenantEntities []*struct {
		ID   uuid.UUID
		Name string
		Slug string
	}

	for _, t := range tenants {
		meta := map[string]any{"base_domain": t.baseDomain}
		if t.isPlatformOwner {
			meta["is_platform_owner"] = true
			meta["scope"] = "platform"
		}
		tenantEntity, err := client.Tenant.Query().Where(tenant.SlugEQ(t.slug)).Only(ctx)
		if err != nil {
			tenantEntity, err = client.Tenant.Create().
				SetName(t.name).
				SetSlug(t.slug).
				SetStatus("active").
				SetMetadata(meta).
				Save(ctx)
			if err != nil {
				log.Fatalf("create tenant %s: %v", t.slug, err)
			}
			log.Printf("✓ Created tenant: %s (%s) base_domain=%s", t.name, t.slug, t.baseDomain)
		} else {
			_, _ = tenantEntity.Update().SetMetadata(meta).Save(ctx)
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

	// Seed platform owner / default super admin (full access across all services).
	// Prefer SEED_SUPER_ADMIN_* then SEED_ADMIN_*; fallback to defaults when env not set.
	adminEmail := os.Getenv("SEED_SUPER_ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = os.Getenv("SEED_ADMIN_EMAIL")
	}
	if adminEmail == "" {
		adminEmail = "admin@codevertexitsolutions.com"
	}
	adminPassword := os.Getenv("SEED_SUPER_ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = os.Getenv("SEED_ADMIN_PASSWORD")
	}
	if adminPassword == "" {
		adminPassword = "ChangeMe123!"
	}

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

	// Seed staff users for each tenant (for testing order processing workflows)
	log.Println("Seeding staff users for all tenants...")
	for _, te := range tenantEntities {
		staffEmail := fmt.Sprintf("staff@%s.com", te.Slug)
		staffPassword := fmt.Sprintf("Staff%s2024!", te.Slug)
		staffHash, _ := hasher.Hash(staffPassword)

		staffUser, err := client.User.Create().
			SetEmail(staffEmail).
			SetPasswordHash(staffHash).
			SetStatus("active").
			SetPrimaryTenantID(te.ID.String()).
			SetProfile(map[string]any{
				"name":       fmt.Sprintf("%s Staff", te.Name),
				"phone":      "+254700000003",
				"created_by": "seed",
				"role":       "staff",
			}).
			Save(ctx)
		if err != nil {
			staffUser, err = client.User.Query().Where(user.EmailEQ(staffEmail)).Only(ctx)
			if err != nil {
				log.Printf("  ⚠️  seed staff for %s: %v", te.Slug, err)
			} else {
				log.Printf("  ✓ Staff exists for %s: %s", te.Slug, staffEmail)
			}
		} else {
			log.Printf("  ✓ Created staff for %s: %s", te.Slug, staffEmail)
		}

		if staffUser != nil {
			exists, _ := client.TenantMembership.Query().
				Where(
					tenantmembership.UserID(staffUser.ID),
					tenantmembership.TenantID(te.ID),
				).Exist(ctx)
			if !exists {
				_, _ = client.TenantMembership.Create().
					SetUserID(staffUser.ID).
					SetTenantID(te.ID).
					SetRoles([]string{"staff"}).
					Save(ctx)
				log.Printf("    ✓ Added staff role in %s", te.Slug)
			}
		}
	}

	// Seed permissions and role-permission mapping (MVP RBAC). Include canonical codes used by ordering-backend (catalog:view, catalog:manage).
	log.Println("Seeding permissions and role-permission mapping...")
	actions := []string{"add", "read", "read_own", "change", "change_own", "delete", "manage", "manage_own", "view"}
	resources := []string{"orders", "menu", "users", "tenants", "riders", "inventory", "settings", "gateways", "catalog"}
	permissionIDs := make(map[string]int)
	for _, res := range resources {
		for _, act := range actions {
			code := res + ":" + act
			perm, err := client.Permission.Query().Where(permission.CodeEQ(code)).Only(ctx)
			if err != nil {
				perm, err = client.Permission.Create().
					SetCode(code).
					SetResource(res).
					SetAction(act).
					Save(ctx)
				if err != nil {
					log.Printf("  ⚠️  Error creating permission %s: %v", code, err)
					continue
				}
				log.Printf("  ✓ Created permission: %s", code)
			}
			permissionIDs[code] = perm.ID
		}
	}
	// Assign permissions to roles. Use canonical codes matching ordering-backend (catalog:view, catalog:manage).
	rolePerms := map[string][]string{
		"superuser": {},
		"admin":     {},
		"staff":     {"orders:read", "orders:change", "orders:add", "menu:read", "menu:change", "menu:add", "catalog:view", "catalog:manage", "riders:read", "inventory:read", "inventory:change"},
		"member":    {"orders:read_own", "orders:change_own", "orders:add", "menu:read", "catalog:view"},
		"rider":     {"riders:read_own", "riders:change_own", "orders:read"},
	}
	for roleName, codes := range rolePerms {
		if len(codes) == 0 {
			codes = make([]string, 0, len(permissionIDs))
			for code := range permissionIDs {
				codes = append(codes, code)
			}
		}
		for _, code := range codes {
			pid, ok := permissionIDs[code]
			if !ok {
				continue
			}
			exists, _ := client.RolePermission.Query().
				Where(rolepermission.RoleNameEQ(roleName), rolepermission.PermissionIDEQ(pid)).
				Exist(ctx)
			if exists {
				continue
			}
			_, err = client.RolePermission.Create().
				SetRoleName(roleName).
				SetPermissionID(pid).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating role_permission %s/%s: %v", roleName, code, err)
			}
		}
		log.Printf("  ✓ Role %s: %d permissions", roleName, len(codes))
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
		log.Printf("Platform / Admin Account (from SEED_SUPER_ADMIN_* or SEED_ADMIN_*):")
		log.Printf("  Email: %s", adminEmail)
		log.Printf("  Role: superuser (platform owner scope)")
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
	var tenantSlugs []string
	for _, te := range tenantEntities {
		tenantSlugs = append(tenantSlugs, te.Slug)
	}

	notificationsRedirects := []string{}
	orderingRedirects := []string{}
	for _, slug := range tenantSlugs {
		notificationsRedirects = append(notificationsRedirects,
			"https://notifications.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3000/"+slug+"/auth/callback",
		)
		orderingRedirects = append(orderingRedirects,
			"https://ordersapp.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3001/"+slug+"/auth/callback",
		)
	}

	oauthClients := []oauthClientSpec{
		{
			ID:           "notifications-ui",
			Name:         "BengoBox Notifications UI",
			RedirectURIs: notificationsRedirects,
			Public:       true,
		},
		{
			ID:           "ordering-ui",
			Name:         "BengoBox Ordering UI",
			RedirectURIs: orderingRedirects,
			Public:       true,
		},
		{
			ID:   "rider-app",
			Name: "BengoBox Rider App",
			RedirectURIs: []string{
				"https://riderapp.codevertexitsolutions.com/auth/callback",
				"https://rider.codevertexitsolutions.com/auth/callback",
				"http://localhost:3002/auth/callback",
			},
			Public: true,
		},
		{
			ID:   "cafe-website",
			Name: "Urban Loft Cafe Website",
			RedirectURIs: []string{
				"https://theurbanloftcafe.com/auth/callback",
				"http://localhost:3000/auth/callback",
			},
			Public: true,
		},
		// ── Additional Frontend Clients ───────────────────────────────────────
		// Added: subscriptions-ui, treasury-ui, pos-frontend, auth-ui, logistics-ui
		{
			ID:   "subscriptions-ui",
			Name: "BengoBox Subscriptions UI",
			RedirectURIs: []string{
				"https://subscriptions.codevertexitsolutions.com/auth/callback",
				"http://localhost:3010/auth/callback",
			},
			Public: true,
		},
		{
			ID:   "treasury-ui",
			Name: "BengoBox Treasury UI",
			RedirectURIs: []string{
				"https://treasury.codevertexitsolutions.com/auth/callback",
				"http://localhost:3011/auth/callback",
			},
			Public: true,
		},
		{
			ID:   "pos-frontend",
			Name: "BengoBox POS Frontend",
			RedirectURIs: []string{
				"https://pos.codevertexitsolutions.com/auth/callback",
				"http://localhost:3012/auth/callback",
			},
			Public: true,
		},
		{
			ID:   "logistics-ui",
			Name: "BengoBox Logistics UI",
			RedirectURIs: []string{
				"https://logistics.codevertexitsolutions.com/auth/callback",
				"http://localhost:3013/auth/callback",
			},
			Public: true,
		},
		{
			ID:   "auth-ui",
			Name: "BengoBox Auth UI (Platform Admin)",
			RedirectURIs: []string{
				"https://accounts.codevertexitsolutions.com/auth/callback",
				"https://sso.codevertexitsolutions.com/auth/callback",
				"http://localhost:3014/auth/callback",
			},
			Public: true,
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
