package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/apikey"
	"github.com/bengobox/auth-api/internal/ent/integrationconfig"
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
	// Media base URL for tenant logos — points to the SSO/accounts CDN host.
	const mediaBase = "https://accounts.codevertexitsolutions.com"

	tenants := []struct {
		name            string
		slug            string
		baseDomain      string
		isPlatformOwner bool
		useCases        []string
		logoURL         string
		website         string
		contactEmail    string
		contactPhone    string
		brandColors     map[string]any
	}{
		{
			name: "CodeVertex", slug: "codevertex", baseDomain: "codevertexitsolutions.com",
			isPlatformOwner: true, useCases: nil,
			logoURL: mediaBase + "/images/logo/codevertex.png", website: "https://codevertexitsolutions.com",
			contactEmail: "support@codevertexitsolutions.com", contactPhone: "+254 743 793 901",
			brandColors: map[string]any{"primary": "#5B1C4D", "secondary": "#ea8022", "accent": "#f36a0c"},
		},
		{
			name: "Masterspace Solutions", slug: "mss", baseDomain: "masterspace.co.ke",
			useCases: []string{"services"},
			logoURL: mediaBase + "/images/logo/mss.jpeg", website: "https://masterspace.co.ke",
			contactEmail: "info@masterspace.co.ke",
			brandColors: map[string]any{"primary": "#1e3a5f", "secondary": "#4a90d9", "accent": "#f0ad4e"},
		},
		{
			name: "Urban Loft Cafe", slug: "urban-loft", baseDomain: "theurbanloftcafe.com",
			useCases: []string{"hospitality"},
			logoURL: mediaBase + "/images/logo/urban-loft.png", website: "https://theurbanloftcafe.com",
			contactEmail: "info@theurbanloftcafe.com",
			brandColors: map[string]any{"primary": "#6b2a1b", "secondary": "#f36a0c", "accent": "#ea8022"},
		},
		{
			name: "Kenya Urban Roads Authority (KURA)", slug: "kura", baseDomain: "kura.go.ke",
			useCases: []string{"logistics"},
			logoURL: mediaBase + "/images/logo/kura.png", website: "https://kura.go.ke",
			contactEmail: "info@kura.go.ke",
			brandColors: map[string]any{"primary": "#006633", "secondary": "#bb0000", "accent": "#000000"},
		},
		{
			name: "UltiChange", slug: "ultichange", baseDomain: "ultichange.org",
			useCases: []string{"services", "e_commerce"},
			logoURL: mediaBase + "/images/logo/ultichange.svg", website: "https://ultichange.org",
			contactEmail: "info@ultichange.org",
			brandColors: map[string]any{"primary": "#2d3436", "secondary": "#0984e3", "accent": "#00cec9"},
		},
		{
			name: "TruLoad", slug: "truload", baseDomain: "codevertexitsolutions.com",
			useCases: []string{"weighbridge", "logistics"},
			logoURL: mediaBase + "/images/logo/truload.svg", website: "https://truload.codevertexitsolutions.com",
			contactEmail: "truload@codevertexitsolutions.com",
			brandColors: map[string]any{"primary": "#1a237e", "secondary": "#ff6f00", "accent": "#00c853"},
		},
	}

	var tenantEntities []*struct {
		ID   uuid.UUID
		Name string
		Slug string
	}

	for _, t := range tenants {
		meta := map[string]any{
			"base_domain": t.baseDomain,
		}
		if t.isPlatformOwner {
			meta["is_platform_owner"] = true
			meta["scope"] = "platform"
		}
		tenantEntity, err := client.Tenant.Query().Where(tenant.SlugEQ(t.slug)).Only(ctx)
		if err != nil {
			create := client.Tenant.Create().
				SetName(t.name).
				SetSlug(t.slug).
				SetStatus("active").
				SetMetadata(meta).
				SetNillableLogoURL(&t.logoURL).
				SetBrandColors(t.brandColors)
			if t.website != "" {
				create = create.SetNillableWebsite(&t.website)
			}
			if t.contactEmail != "" {
				create = create.SetNillableContactEmail(&t.contactEmail)
			}
			if t.contactPhone != "" {
				create = create.SetNillableContactPhone(&t.contactPhone)
			}
			if len(t.useCases) > 0 {
				create = create.SetUseCase(t.useCases[0]).SetUseCases(t.useCases)
			}
			tenantEntity, err = create.Save(ctx)
			if err != nil {
				log.Fatalf("create tenant %s: %v", t.slug, err)
			}
			log.Printf("✓ Created tenant: %s (%s) base_domain=%s", t.name, t.slug, t.baseDomain)
		} else {
			upd := tenantEntity.Update().
				SetMetadata(meta).
				SetNillableLogoURL(&t.logoURL).
				SetBrandColors(t.brandColors)
			if t.website != "" {
				upd = upd.SetNillableWebsite(&t.website)
			}
			if t.contactEmail != "" {
				upd = upd.SetNillableContactEmail(&t.contactEmail)
			}
			if t.contactPhone != "" {
				upd = upd.SetNillableContactPhone(&t.contactPhone)
			}
			if len(t.useCases) > 0 {
				upd = upd.SetUseCase(t.useCases[0]).SetUseCases(t.useCases)
			}
			_, _ = upd.Save(ctx)
			log.Printf("✓ Tenant exists (updated): %s (%s)", t.name, t.slug)
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

	// Seed demo user
	demoEmail := "demo@bengobox.dev"
	demoPassword := os.Getenv("SEED_DEMO_PASSWORD")
	if demoPassword == "" {
		demoPassword = "DemoUser2024!" // default for local dev; override via env in production
	}

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

	// Add demo user membership to all tenants
	for _, tenantEnt := range tenantEntities {
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

	// Seed platform owner / default super admin
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
		log.Println("⚠️  No SEED_SUPER_ADMIN_PASSWORD or SEED_ADMIN_PASSWORD set — using default seed password")
		adminPassword = "ChangeMe123!" // default for local dev; override via env in production
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
	}

	// Seed tenant-specific admin for Urban Loft Cafe
	urbanLoftTenant := tenantEntities[2]
	tenantAdminEmail := "admin@theurbanloftcafe.com"
	tenantAdminPassword := os.Getenv("SEED_TENANT_ADMIN_PASSWORD")
	if tenantAdminPassword == "" {
		tenantAdminPassword = "TenantAdmin2024!" // default for local dev; override via env in production
	}
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

	// Seed demo admin for TruLoad commercial weighing tenant
	// truload tenant is the last entry in the tenants slice
	truloadTenant := tenantEntities[len(tenantEntities)-1] // "truload"
	truloadAdminEmail := "admin@truload.codevertexitsolutions.com"
	truloadAdminPassword := os.Getenv("SEED_TRULOAD_ADMIN_PASSWORD")
	if truloadAdminPassword == "" {
		truloadAdminPassword = "ChangeMe123!" // default for local dev; override via env in production
	}
	truloadAdminHash, _ := hasher.Hash(truloadAdminPassword)

	truloadAdmin, err := client.User.Create().
		SetEmail(truloadAdminEmail).
		SetPasswordHash(truloadAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(truloadTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "TruLoad Demo Admin",
			"phone":      "+254700000010",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		truloadAdmin, err = client.User.Query().Where(user.EmailEQ(truloadAdminEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed truload admin: %v", err)
		} else {
			log.Printf("✓ TruLoad admin exists: %s", truloadAdminEmail)
		}
	} else {
		log.Printf("✓ Created TruLoad admin: %s", truloadAdminEmail)
	}

	if truloadAdmin != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(truloadAdmin.ID),
				tenantmembership.TenantID(truloadTenant.ID),
			).Exist(ctx)
		if !exists {
			_, err = client.TenantMembership.Create().
				SetUserID(truloadAdmin.ID).
				SetTenantID(truloadTenant.ID).
				SetRoles([]string{"admin"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating truload admin membership: %v", err)
			} else {
				log.Printf("  ✓ Added admin role in %s", truloadTenant.Slug)
			}
		}
	}

	// Seed staff users for all tenants
	log.Println("Seeding staff users for all tenants...")
	for _, te := range tenantEntities {
		staffEmail := fmt.Sprintf("staff@%s.com", te.Slug)
		staffPassword := os.Getenv("SEED_STAFF_PASSWORD")
		if staffPassword == "" {
			staffPassword = fmt.Sprintf("Staff%s2024!", te.Slug) // default for local dev
		}
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

	// Seed permissions and role-permission mapping
	// Uses Django-style format: {service}.{module}.{action}
	// Standard actions: add, view, view_own, change, change_own, delete, delete_own, manage, manage_own
	// See: shared-docs/TRINITY-AUTHORIZATION-PATTERN.md
	log.Println("Seeding permissions (Django-style: service.module.action)...")

	// All service permissions in {service}.{module}.{action} format
	servicePerms := map[string][]string{
		// Ordering service
		"ordering": {
			"ordering.orders.add", "ordering.orders.view", "ordering.orders.view_own",
			"ordering.orders.change", "ordering.orders.change_own", "ordering.orders.delete",
			"ordering.orders.manage", "ordering.orders.manage_own",
			"ordering.catalog.add", "ordering.catalog.view", "ordering.catalog.change",
			"ordering.catalog.delete", "ordering.catalog.manage",
			"ordering.outlets.add", "ordering.outlets.view", "ordering.outlets.change",
			"ordering.outlets.delete", "ordering.outlets.manage",
			"ordering.promotions.add", "ordering.promotions.view", "ordering.promotions.change",
			"ordering.promotions.delete", "ordering.promotions.manage",
			"ordering.analytics.view", "ordering.analytics.manage",
			"ordering.config.view", "ordering.config.manage",
			"ordering.users.view", "ordering.users.manage",
		},
		// Inventory service
		"inventory": {
			"inventory.items.add", "inventory.items.view", "inventory.items.change",
			"inventory.items.delete", "inventory.items.manage",
			"inventory.categories.add", "inventory.categories.view", "inventory.categories.change",
			"inventory.categories.delete", "inventory.categories.manage",
			"inventory.warehouses.add", "inventory.warehouses.view", "inventory.warehouses.change",
			"inventory.warehouses.delete", "inventory.warehouses.manage",
			"inventory.stock.add", "inventory.stock.view", "inventory.stock.change",
			"inventory.stock.manage",
			"inventory.recipes.add", "inventory.recipes.view", "inventory.recipes.change",
			"inventory.recipes.delete", "inventory.recipes.manage",
			"inventory.units.add", "inventory.units.view", "inventory.units.change",
			"inventory.units.manage",
			"inventory.config.view", "inventory.config.manage",
			"inventory.users.view", "inventory.users.manage",
		},
		// Logistics service
		"logistics": {
			"logistics.tasks.add", "logistics.tasks.view", "logistics.tasks.view_own",
			"logistics.tasks.change", "logistics.tasks.change_own",
			"logistics.tasks.delete", "logistics.tasks.manage", "logistics.tasks.manage_own",
			"logistics.fleet.add", "logistics.fleet.view", "logistics.fleet.change",
			"logistics.fleet.delete", "logistics.fleet.manage",
			"logistics.vehicles.add", "logistics.vehicles.view", "logistics.vehicles.change",
			"logistics.vehicles.delete", "logistics.vehicles.manage",
			"logistics.zones.add", "logistics.zones.view", "logistics.zones.change",
			"logistics.zones.delete", "logistics.zones.manage",
			"logistics.earnings.view", "logistics.earnings.manage",
			"logistics.config.view", "logistics.config.manage",
			"logistics.users.view", "logistics.users.manage",
		},
		// Treasury / Finance service
		"treasury": {
			"treasury.payments.add", "treasury.payments.view", "treasury.payments.view_own",
			"treasury.payments.change", "treasury.payments.manage",
			"treasury.transactions.view", "treasury.transactions.view_own",
			"treasury.transactions.manage",
			"treasury.ledger.view", "treasury.ledger.manage",
			"treasury.gateways.add", "treasury.gateways.view", "treasury.gateways.change",
			"treasury.gateways.manage",
			"treasury.config.view", "treasury.config.manage",
			"treasury.users.view", "treasury.users.manage",
		},
		// Auth service (platform-level)
		"auth": {
			"auth.users.add", "auth.users.view", "auth.users.view_own",
			"auth.users.change", "auth.users.change_own", "auth.users.delete",
			"auth.users.manage", "auth.users.manage_own",
			"auth.tenants.add", "auth.tenants.view", "auth.tenants.change",
			"auth.tenants.delete", "auth.tenants.manage",
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
			"auth.notifications.view", "auth.notifications.manage",
		},
	}

	permissionIDs := make(map[string]int)
	for svc, codes := range servicePerms {
		for _, code := range codes {
			perm, err := client.Permission.Query().Where(permission.CodeEQ(code)).Only(ctx)
			if err != nil {
				// Extract module and action from {service}.{module}.{action}
				parts := strings.SplitN(code, ".", 3)
				resource := svc
				action := code
				if len(parts) == 3 {
					resource = parts[1]
					action = parts[2]
				}
				perm, err = client.Permission.Create().
					SetCode(code).
					SetResource(resource).
					SetAction(action).
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

	rolePerms := map[string][]string{
		"superuser": {}, // all permissions (populated below)
		"admin":     {}, // all permissions (populated below)
		"staff": {
			// Ordering
			"ordering.orders.add", "ordering.orders.view", "ordering.orders.change", "ordering.orders.manage",
			"ordering.catalog.view", "ordering.catalog.add", "ordering.catalog.change", "ordering.catalog.manage",
			"ordering.analytics.view",
			// Inventory
			"inventory.items.view", "inventory.items.change",
			"inventory.stock.view", "inventory.stock.change",
			"inventory.recipes.view",
			// Logistics
			"logistics.fleet.view",
			// Treasury
			"treasury.payments.view", "treasury.transactions.view",
			// Auth
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
			"auth.notifications.view",
		},
		"member": {
			"ordering.orders.view_own", "ordering.orders.change_own", "ordering.orders.add",
			"ordering.catalog.view",
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
		"rider": {
			"logistics.tasks.view_own", "logistics.tasks.change_own",
			"logistics.fleet.view",
			"logistics.earnings.view",
			"ordering.orders.view",
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
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

	// Seed platform-level integration configurations (social logins)
	if err := seedIntegrations(ctx, client, cfg.Token.Issuer); err != nil {
		log.Printf("⚠️  Failed to seed integrations: %v", err)
	}

	// Seed OAuth Clients
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

	// clientProductionHosts maps each OAuth client to its production hostname.
	// Used for building redirect URIs: production uses HTTPS with the hostname,
	// local dev always uses http://localhost:3000 (standardized port for all frontends).
	type clientDef struct {
		ID             string
		Name           string
		ProductionHost string // e.g. "books.codevertexitsolutions.com"
		Public         bool
	}
	clients := []clientDef{
		{ID: "notifications-ui", Name: "BengoBox Notifications UI", ProductionHost: "notifications.codevertexitsolutions.com", Public: true},
		{ID: "ordering-ui", Name: "BengoBox Ordering UI", ProductionHost: "ordersapp.codevertexitsolutions.com", Public: true},
		{ID: "rider-app", Name: "BengoBox Rider App", ProductionHost: "riderapp.codevertexitsolutions.com", Public: true},
		{ID: "cafe-website", Name: "Urban Loft Cafe Website", ProductionHost: "theurbanloftcafe.com", Public: true},
		{ID: "subscriptions-ui", Name: "BengoBox Subscriptions UI", ProductionHost: "pricing.codevertexitsolutions.com", Public: true},
		{ID: "treasury-ui", Name: "BengoBox Treasury UI", ProductionHost: "books.codevertexitsolutions.com", Public: true},
		{ID: "pos-ui", Name: "BengoBox POS UI", ProductionHost: "pos.codevertexitsolutions.com", Public: true},
		{ID: "inventory-ui", Name: "BengoBox Inventory UI", ProductionHost: "inventory.codevertexitsolutions.com", Public: true},
		{ID: "logistics-ui", Name: "BengoBox Logistics UI", ProductionHost: "logistics.codevertexitsolutions.com", Public: true},
		{ID: "auth-ui", Name: "BengoBox Auth UI (Platform Admin)", ProductionHost: "accounts.codevertexitsolutions.com", Public: true},
		{ID: "truload-ui", Name: "TruLoad UI", ProductionHost: "truload.codevertexitsolutions.com", Public: true},
	}

	// Collect all tenant slugs (seeded tenants + TruLoad org slugs).
	allSlugs := append(tenantSlugs, "truload-demo", "danka")

	// buildRedirects generates the full redirect URI list for a client.
	// Each client gets: base production callback, base localhost callback,
	// plus per-tenant-slug variants of both.
	buildRedirects := func(productionHost string) []string {
		seen := map[string]bool{}
		var uris []string
		add := func(u string) {
			if !seen[u] {
				seen[u] = true
				uris = append(uris, u)
			}
		}
		// Non-tenant (base) callbacks
		add("https://" + productionHost + "/auth/callback")
		add("http://localhost:3000/auth/callback")
		// Per-tenant callbacks
		for _, slug := range allSlugs {
			add("https://" + productionHost + "/" + slug + "/auth/callback")
			add("http://localhost:3000/" + slug + "/auth/callback")
		}
		return uris
	}

	// auth-ui also needs the SSO domain as a redirect
	authUIExtra := []string{"https://sso.codevertexitsolutions.com/auth/callback"}

	oauthClients := make([]oauthClientSpec, 0, len(clients))
	for _, c := range clients {
		uris := buildRedirects(c.ProductionHost)
		if c.ID == "auth-ui" {
			uris = append(uris, authUIExtra...)
		}
		oauthClients = append(oauthClients, oauthClientSpec{
			ID:           c.ID,
			Name:         c.Name,
			RedirectURIs: uris,
			Public:       c.Public,
		})
	}

	for _, c := range oauthClients {
		existing, queryErr := client.OAuthClient.Query().Where(oauthclient.ClientID(c.ID)).Only(ctx)
		if queryErr != nil && !ent.IsNotFound(queryErr) {
			log.Printf("  ⚠️  Error checking client %s: %v", c.ID, queryErr)
			continue
		}

		if existing != nil {
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

	// Seed platform API key for service-to-service integrations
	// This key is used by other services (auth-api → subscriptions-api, etc.) for S2S calls.
	// Set PLATFORM_API_KEY env var to use a specific key; otherwise one is generated and printed.
	log.Println("Seeding platform API key...")
	if err := seedPlatformAPIKey(ctx, client, tenantEntities[0].ID); err != nil {
		log.Printf("⚠️  Failed to seed platform API key: %v", err)
	}

	log.Println("✅ Seeding completed successfully!")
	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
}

func seedPlatformAPIKey(ctx context.Context, client *ent.Client, platformTenantID uuid.UUID) error {
	const keyName = "platform-internal-service-key"

	// Check if platform API key already exists
	existingCount, err := client.APIKey.Query().
		Where(
			apikey.TenantIDEQ(platformTenantID),
			apikey.ServiceEQ("platform"),
			apikey.StatusEQ(apikey.StatusActive),
		).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("check existing keys: %w", err)
	}

	if existingCount > 0 {
		log.Printf("  ✓ Platform API key already exists")
		return nil
	}

	// Generate a new API key or use one provided via env
	var plainKey, keyPrefix, keyHash string

	if envKey := os.Getenv("PLATFORM_API_KEY"); envKey != "" {
		// Use the provided key
		plainKey = envKey
		if len(plainKey) >= 8 {
			keyPrefix = plainKey[:8]
		} else {
			keyPrefix = plainKey
		}
		hashBytes := sha256.Sum256([]byte(plainKey))
		keyHash = hex.EncodeToString(hashBytes[:])
		log.Printf("  ℹ️  Using PLATFORM_API_KEY from environment")
	} else {
		// Generate a new key
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate random bytes: %w", err)
		}
		plainKey = "bng_" + base64.URLEncoding.EncodeToString(b)
		keyPrefix = plainKey[:8]
		hashBytes := sha256.Sum256([]byte(plainKey))
		keyHash = hex.EncodeToString(hashBytes[:])
	}

	_, err = client.APIKey.Create().
		SetName(keyName).
		SetKeyHash(keyHash).
		SetKeyPrefix(keyPrefix).
		SetTenantID(platformTenantID).
		SetService("platform").
		SetScopes([]string{"*"}).
		SetStatus(apikey.StatusActive).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("create platform API key: %w", err)
	}

	// Also store the plain key in integration_configs so auth-api can resolve it
	// dynamically at runtime without a pod restart (superusers rotate via auth-ui).
	// Stored as plain JSON here; the running app's integrations.Service will
	// re-encrypt it on first SaveConfig call from auth-ui.
	credsJSON, _ := json.Marshal(map[string]string{"key": plainKey})
	icExists, _ := client.IntegrationConfig.Query().
		Where(integrationconfig.Name("subscription_api_key"), integrationconfig.TenantIDIsNil()).
		Exist(ctx)
	var icErr error
	if !icExists {
		icErr = client.IntegrationConfig.Create().
			SetName("subscription_api_key").
			SetDisplayName("Subscription Service API Key").
			SetDescription("Platform API key for auth-api → subscriptions-api S2S JWT enrichment. Rotate via auth-ui without pod restart.").
			SetEncryptedCredentials(string(credsJSON)).
			SetIsActive(true).
			SetStatus("active").
			Exec(ctx)
	}
	if icErr != nil {
		// Non-fatal: app falls back to AUTH_SUBSCRIPTION_API_KEY env var
		log.Printf("  ⚠️  Could not store key in integration_configs (app will use env fallback): %v", icErr)
	} else {
		log.Printf("  ✓ Platform API key stored in integration_configs as 'subscription_api_key'")
	}

	log.Printf("  ✅ Platform API key created!")
	log.Printf("  ⚠️  IMPORTANT: Save this key — it will NOT be shown again:")
	log.Printf("  PLATFORM_API_KEY=%s", plainKey)
	log.Printf("  Set this in auth-api-secrets as PLATFORM_API_KEY for initial deployment.")
	return nil
}

func seedIntegrations(ctx context.Context, client *ent.Client, apiBaseURL string) error {
	log.Println("Seeding platform integrations...")
	oauthApps := []struct {
		name        string
		displayName string
		description string
	}{
		{"google", "Google OAuth", "Google Social Login integration"},
		{"github", "GitHub OAuth", "GitHub Social Login integration"},
		{"microsoft", "Microsoft OAuth", "Microsoft Social Login integration"},
	}

	for _, app := range oauthApps {
		clientID := os.Getenv(fmt.Sprintf("%s_CLIENT_ID", strings.ToUpper(app.name)))
		clientSecret := os.Getenv(fmt.Sprintf("%s_CLIENT_SECRET", strings.ToUpper(app.name)))
		// GitHub: accept GIT_APP_ID / GIT_APP_SECRET as alternative env names
		if app.name == "github" {
			if clientID == "" {
				clientID = os.Getenv("GIT_APP_ID")
			}
			if clientSecret == "" {
				clientSecret = os.Getenv("GIT_APP_SECRET")
			}
		}
		if clientID == "" {
			clientID = fmt.Sprintf("demo_%s_client_id", app.name)
		}
		if clientSecret == "" {
			clientSecret = fmt.Sprintf("demo_%s_client_secret", app.name)
		}

		creds := map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
		}
		if apiBaseURL != "" {
			creds["redirect_url"] = fmt.Sprintf("%s/api/v1/auth/oauth/%s/callback", strings.TrimRight(apiBaseURL, "/"), app.name)
		}
		// Microsoft: seed tenant_id for tenant-specific auth URL (default common)
		if app.name == "microsoft" {
			if t := os.Getenv("MICROSOFT_TENANT_ID"); t != "" {
				creds["tenant_id"] = t
			} else {
				creds["tenant_id"] = "common"
			}
		}

		credsJSON, _ := json.Marshal(creds)

		exists, err := client.IntegrationConfig.Query().
			Where(integrationconfig.Name(app.name), integrationconfig.TenantIDIsNil()).
			Exist(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error checking integration %s: %v", app.name, err)
			continue
		}

		if exists {
			_, err = client.IntegrationConfig.Update().
				Where(integrationconfig.Name(app.name), integrationconfig.TenantIDIsNil()).
				SetEncryptedCredentials(string(credsJSON)).
				SetIsActive(true).
				SetStatus("active").
				Save(ctx)
		} else {
			err = client.IntegrationConfig.Create().
				SetName(app.name).
				SetDisplayName(app.displayName).
				SetDescription(app.description).
				SetEncryptedCredentials(string(credsJSON)).
				SetIsActive(true).
				SetStatus("active").
				Exec(ctx)
		}
		if err != nil {
			log.Printf("  ⚠️  Error seeding integration %s: %v", app.name, err)
		} else {
			log.Printf("  ✓ Seeded integration: %s", app.name)
		}
	}
	return nil
}
