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
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/ent/integrationconfig"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	entoutlet "github.com/bengobox/auth-api/internal/ent/outlet"
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
		{
			// Cross-platform demo tenant — covers all use-cases for platform demos.
			// Staff accounts are seeded under this tenant; demo user gets admin role here.
			name: "CodeVertex Demo", slug: "codevertex-demo", baseDomain: "demo.codevertexitsolutions.com",
			useCases: []string{"hospitality", "retail", "quick_service", "pharmacy", "services", "logistics"},
			logoURL: mediaBase + "/images/logo/codevertex.png", website: "https://demo.codevertexitsolutions.com",
			contactEmail: "demo@codevertexitsolutions.com",
			brandColors: map[string]any{"primary": "#5B1C4D", "secondary": "#ea8022", "accent": "#f36a0c"},
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

	// Seed outlets for tenants that operate physical/logical branches.
	// Auth-api is the source of truth for outlet UUIDs — all downstream services
	// sync these UUIDs via JIT login sync or NATS auth.outlet.* events.
	log.Println("Seeding outlets...")
	for _, te := range tenantEntities {
		if err := seedOutletsForTenant(ctx, client, te.ID, te.Slug); err != nil {
			log.Printf("  ⚠️  outlets for %s: %v", te.Slug, err)
		}
	}

	hasher := password.NewHasher(cfg.Security)

	// Seed demo user.
	// Primary tenant must be codevertex-demo, NOT codevertex (platform owner).
	// Using codevertex as primary would mint is_platform_owner=true in the JWT,
	// giving the demo user full platform-admin access — a confirmed prod bug.
	demoPrimaryTenant := tenantEntities[len(tenantEntities)-1] // codevertex-demo

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
		SetPrimaryTenantID(demoPrimaryTenant.ID.String()).
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
		// Patch existing demo user if its primary_tenant still points to codevertex.
		if demoUser.PrimaryTenantID != demoPrimaryTenant.ID.String() {
			_, _ = demoUser.Update().SetPrimaryTenantID(demoPrimaryTenant.ID.String()).Save(ctx)
			log.Printf("  ✓ Fixed demo user primary_tenant → %s", demoPrimaryTenant.Slug)
		}
		log.Printf("✓ Demo user exists: %s", demoEmail)
	} else {
		log.Printf("✓ Created demo user: %s", demoEmail)
	}

	// Add demo user membership to all tenants except the platform-owner (codevertex).
	// Membership in codevertex would not elevate the JWT (primary_tenant drives
	// is_platform_owner), but it's still incorrect for a demo/client account.
	for _, tenantEnt := range tenantEntities {
		if tenantEnt.Slug == "codevertex" {
			continue // demo user must never be a member of the platform-owner tenant
		}
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

	// Seed demo tenant admin (codevertex-demo — index 6, last added)
	demoTenant := tenantEntities[len(tenantEntities)-1] // codevertex-demo
	demoTenantAdminEmail := "admin@demo.codevertexitsolutions.com"
	demoTenantAdminPassword := os.Getenv("SEED_DEMO_TENANT_ADMIN_PASSWORD")
	if demoTenantAdminPassword == "" {
		demoTenantAdminPassword = "DemoAdmin2024!"
	}
	demoTenantAdminHash, _ := hasher.Hash(demoTenantAdminPassword)

	demoTenantAdmin, err := client.User.Create().
		SetEmail(demoTenantAdminEmail).
		SetPasswordHash(demoTenantAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(demoTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "CodeVertex Demo Admin",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		demoTenantAdmin, _ = client.User.Query().Where(user.EmailEQ(demoTenantAdminEmail)).Only(ctx)
		log.Printf("✓ Demo tenant admin exists: %s", demoTenantAdminEmail)
	} else {
		log.Printf("✓ Created demo tenant admin: %s", demoTenantAdminEmail)
	}
	if demoTenantAdmin != nil {
		exists, _ := client.TenantMembership.Query().Where(
			tenantmembership.UserID(demoTenantAdmin.ID),
			tenantmembership.TenantID(demoTenant.ID),
		).Exist(ctx)
		if !exists {
			_, _ = client.TenantMembership.Create().
				SetUserID(demoTenantAdmin.ID).SetTenantID(demoTenant.ID).SetRoles([]string{"admin"}).Save(ctx)
			log.Printf("  ✓ Added admin role in %s", demoTenant.Slug)
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

	// Seed cross-platform demo staff under codevertex-demo tenant.
	// These accounts cover every POS role so PIN login works for demos on any outlet.
	// urban-loft staff emails have been migrated here; the urban-loft tenant now has
	// only its real admin user (admin@theurbanloftcafe.com).
	demoStaff := []struct {
		email string
		name  string
		role  string
	}{
		{"manager@demo.codevertexitsolutions.com", "Demo Manager", "manager"},
		{"cashier@demo.codevertexitsolutions.com", "Demo Cashier", "cashier"},
		{"waiter@demo.codevertexitsolutions.com", "Demo Waiter", "waiter"},
		{"kitchen@demo.codevertexitsolutions.com", "Demo Kitchen", "kitchen"},
		{"bar@demo.codevertexitsolutions.com", "Demo Bar Staff", "bar"},
		{"receptionist@demo.codevertexitsolutions.com", "Demo Receptionist", "receptionist"},
	}
	demoStaffPassword := os.Getenv("SEED_DEMO_STAFF_PASSWORD")
	if demoStaffPassword == "" {
		demoStaffPassword = "DemoStaff2024!"
	}
	for _, s := range demoStaff {
		staffHash, hashErr := hasher.Hash(demoStaffPassword)
		if hashErr != nil {
			log.Printf("  ⚠️  hash password for %s: %v", s.email, hashErr)
			continue
		}
		staffUser, createErr := client.User.Create().
			SetEmail(s.email).
			SetPasswordHash(staffHash).
			SetStatus("active").
			SetPrimaryTenantID(demoTenant.ID.String()).
			SetProfile(map[string]any{
				"name":       s.name,
				"created_by": "seed",
				"role":       s.role,
			}).
			Save(ctx)
		if createErr != nil {
			staffUser, createErr = client.User.Query().Where(user.EmailEQ(s.email)).Only(ctx)
			if createErr != nil {
				log.Printf("  ⚠️  seed demo staff %s: %v", s.email, createErr)
				continue
			}
			log.Printf("  ✓ Demo staff exists: %s (%s)", s.email, s.role)
		} else {
			log.Printf("  ✓ Created demo staff: %s (%s)", s.email, s.role)
		}

		memberExists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(staffUser.ID),
				tenantmembership.TenantID(demoTenant.ID),
			).Exist(ctx)
		if !memberExists {
			_, _ = client.TenantMembership.Create().
				SetUserID(staffUser.ID).
				SetTenantID(demoTenant.ID).
				SetRoles([]string{s.role}).
				Save(ctx)
			log.Printf("    ✓ Added %s role in %s", s.role, demoTenant.Slug)
		}
	}

	// Seed demo admin for TruLoad commercial weighing tenant (index 5 in tenants slice)
	truloadTenant := tenantEntities[5] // "truload"
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

	// Seed kura (Kenya Urban Roads Authority) admin user.
	// All previous kura users were removed via kubectl SQL (database-maintenance.md).
	// This seeds the canonical kura admin: axleload@kura.go.ke
	kuraTenant := tenantEntities[3] // "kura"
	kuraAdminEmail := "axleload@kura.go.ke"
	kuraAdminPassword := os.Getenv("SEED_KURA_ADMIN_PASSWORD")
	if kuraAdminPassword == "" {
		kuraAdminPassword = "Admin312$"
	}
	kuraAdminHash, _ := hasher.Hash(kuraAdminPassword)

	kuraAdmin, err := client.User.Create().
		SetEmail(kuraAdminEmail).
		SetPasswordHash(kuraAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(kuraTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "AxleLoad KURA Admin",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		kuraAdmin, err = client.User.Query().Where(user.EmailEQ(kuraAdminEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed kura admin: %v", err)
		} else {
			log.Printf("✓ KURA admin exists: %s", kuraAdminEmail)
		}
	} else {
		log.Printf("✓ Created KURA admin: %s", kuraAdminEmail)
	}

	if kuraAdmin != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(kuraAdmin.ID),
				tenantmembership.TenantID(kuraTenant.ID),
			).Exist(ctx)
		if !exists {
			_, err = client.TenantMembership.Create().
				SetUserID(kuraAdmin.ID).
				SetTenantID(kuraTenant.ID).
				SetRoles([]string{"admin"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating kura admin membership: %v", err)
			} else {
				log.Printf("  ✓ Added admin role in %s", kuraTenant.Slug)
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
	// NOTE: pos.*.* permissions are NOT seeded here.
	// Per Trinity Authorization Pattern: pos-service owns its own fine-grained RBAC
	// (POSRoleV2 + POSPermission tables). Frontends call pos-api GET /{tenant}/pos/auth/me
	// after SSO to get service-level roles and permissions. auth-api only issues the
	// global JWT roles (admin, manager, cashier, etc.) — pos-api maps those to local POS roles.

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
		"manager": {
			// Ordering
			"ordering.orders.add", "ordering.orders.view", "ordering.orders.change", "ordering.orders.manage",
			"ordering.catalog.add", "ordering.catalog.view", "ordering.catalog.change", "ordering.catalog.manage",
			"ordering.analytics.view",
			// Inventory
			"inventory.items.view", "inventory.items.change", "inventory.items.manage",
			"inventory.stock.view", "inventory.stock.change", "inventory.stock.manage",
			"inventory.recipes.view", "inventory.recipes.change",
			// Auth
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
			"auth.notifications.view",
			"auth.users.view", "auth.users.change",
		},
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
		// POS staff roles — only auth-service permissions here.
		// POS-specific permissions (pos.*.*) are managed by pos-api's local RBAC (POSRoleV2 table).
		// Frontends call GET /{tenant}/pos/auth/me to get service-level permissions.
		"cashier": {
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
		"waiter": {
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
		"kitchen": {
			"auth.profile.view", "auth.profile.change",
		},
		"bar": {
			"auth.profile.view", "auth.profile.change",
		},
		"receptionist": {
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
		// delivery_coordinator — assigned to ordering/logistics staff managing dispatch.
		// Recognized by ordering-backend and logistics-api for delivery route/zone access.
		"delivery_coordinator": {
			"logistics.tasks.view", "logistics.tasks.change", "logistics.tasks.manage",
			"logistics.zones.view",
			"logistics.fleet.view",
			"ordering.orders.view", "ordering.orders.change",
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
		// driver — logistics fleet/cargo driver (vehicle-based delivery, distinct from rider).
		// Used by logistics-api for fleet drivers managing cargo/truck deliveries.
		"driver": {
			"logistics.tasks.view_own", "logistics.tasks.change_own",
			"logistics.fleet.view",
			"logistics.vehicles.view",
			"logistics.earnings.view",
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
		// customer — end-user/consumer role for B2C access.
		// Used by ordering-backend for food/retail customers and ISP billing for subscribers.
		// Distinct from member (staff) — customers have no internal management access.
		"customer": {
			"ordering.orders.add", "ordering.orders.view_own", "ordering.orders.change_own",
			"ordering.catalog.view",
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
			"auth.notifications.view",
		},
		// technician — field technician role for ISP billing and IT services.
		// Can manage service tasks and view fleet/zone information.
		"technician": {
			"logistics.tasks.view", "logistics.tasks.change",
			"logistics.zones.view",
			"logistics.fleet.view",
			"auth.profile.view", "auth.profile.change",
			"auth.preferences.view", "auth.preferences.change",
		},
		// viewer — read-only cross-service role for auditors, observers, and reporting users.
		// Can view data across services but cannot create, modify, or delete anything.
		"viewer": {
			"ordering.orders.view", "ordering.catalog.view", "ordering.analytics.view",
			"inventory.items.view", "inventory.stock.view", "inventory.recipes.view",
			"inventory.warehouses.view",
			"logistics.tasks.view", "logistics.fleet.view", "logistics.zones.view",
			"auth.profile.view",
			"auth.notifications.view",
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
		{ID: "codevertex-website", Name: "Codevertex IT Solutions Website", ProductionHost: "codevertexitsolutions.com", Public: true},
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
	// codevertex-website is reachable on both apex and www
	cvWebsiteExtra := []string{"https://www.codevertexitsolutions.com/auth/callback"}

	oauthClients := make([]oauthClientSpec, 0, len(clients))
	for _, c := range clients {
		uris := buildRedirects(c.ProductionHost)
		if c.ID == "auth-ui" {
			uris = append(uris, authUIExtra...)
		}
		if c.ID == "codevertex-website" {
			uris = append(uris, cvWebsiteExtra...)
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

	// Seed legacy platform API key (kept for backward compatibility with services not yet migrated)
	log.Println("Seeding platform API key (legacy)...")
	if err := seedPlatformAPIKey(ctx, client, tenantEntities[0].ID); err != nil {
		log.Printf("⚠️  Failed to seed platform API key: %v", err)
	}

	// Seed platform App with GitHub-style token (new S2S mechanism)
	log.Println("Seeding platform App token...")
	if err := seedPlatformApp(ctx, client); err != nil {
		log.Printf("⚠️  Failed to seed platform App: %v", err)
	}

	log.Println("✅ Seeding completed successfully!")
	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
}

// outletSeedID returns a deterministic UUID for an outlet using the same formula
// as pos-api, inventory-api, and ordering-backend — ensuring cross-service UUID alignment.
func outletSeedID(tenantSlug, outletSlug string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("bengobox:cafe:outlet:%s:%s", tenantSlug, outletSlug)))
}

type outletDef struct {
	slug    string
	code    string
	name    string
	useCase string
	isHQ    bool
	address string
	pinMsg  string
}

// outletsByTenant defines the outlets to seed per tenant slug.
// Downstream services reference these UUIDs (computed via outletSeedID) for warehouse,
// device, order, and staff scoping — never create outlets independently in those services.
var outletsByTenant = map[string][]outletDef{
	"urban-loft": {
		{
			slug:    "busia",
			code:    "BUSIA",
			name:    "Urban Loft Cafe Busia",
			useCase: "hospitality",
			isHQ:    true,
			address: "Busia Town, Busia, Kenya",
			pinMsg:  "Welcome to Urban Loft Cafe — Shift starts 7:00 AM",
		},
	},
	"codevertex-demo": {
		// HQ outlet — hospitality (hotel, bar, restaurant)
		{
			slug: "demo-hospitality", code: "HOSP",
			name: "Demo Grand Hotel & Restaurant", useCase: "hospitality", isHQ: true,
			address: "Demo Plaza, Nairobi, Kenya",
			pinMsg:  "Welcome to Demo Grand Hotel — please check your shift schedule",
		},
		// Retail outlet — shop, supermarket, hardware
		{
			slug: "demo-retail", code: "RETAIL",
			name: "Demo Tech Store", useCase: "retail", isHQ: false,
			address: "Demo Mall, Westlands, Nairobi",
			pinMsg:  "Welcome to Demo Tech Store — barcode scanner is active",
		},
		// Quick service outlet — fast food, coffee kiosk
		{
			slug: "demo-quick", code: "QSR",
			name: "Demo Express Kiosk", useCase: "quick_service", isHQ: false,
			address: "Demo Food Court, CBD Nairobi",
			pinMsg:  "Welcome to Demo Express — fast service starts here!",
		},
		// Pharmacy outlet
		{
			slug: "demo-pharmacy", code: "PHARMA",
			name: "Demo Health Pharmacy", useCase: "pharmacy", isHQ: false,
			address: "Demo Health Centre, Upper Hill, Nairobi",
			pinMsg:  "Welcome to Demo Health Pharmacy — verify prescriptions at counter",
		},
		// Services outlet — salon, spa, appointments
		{
			slug: "demo-services", code: "SVC",
			name: "Demo Beauty & Wellness", useCase: "services", isHQ: false,
			address: "Demo Towers, Kilimani, Nairobi",
			pinMsg:  "Welcome to Demo Beauty & Wellness — check appointments board",
		},
		// Logistics / warehouse outlet
		{
			slug: "demo-logistics", code: "LOGIS",
			name: "Demo Logistics Hub", useCase: "logistics", isHQ: false,
			address: "Demo Industrial Area, Nairobi",
			pinMsg:  "Welcome to Demo Logistics Hub — report to dispatch supervisor",
		},
	},
	"mss": {
		{
			slug:    "main",
			code:    "MAIN",
			name:    "Masterspace Solutions HQ",
			useCase: "services",
			isHQ:    true,
			address: "Masterspace HQ, Nairobi, Kenya",
		},
	},
	"truload": {
		{
			slug:    "main",
			code:    "MAIN",
			name:    "TruLoad Weighbridge Main",
			useCase: "logistics",
			isHQ:    true,
			address: "TruLoad Weighbridge, Nairobi, Kenya",
		},
	},
}

func seedOutletsForTenant(ctx context.Context, client *ent.Client, tenantID uuid.UUID, tenantSlug string) error {
	defs, ok := outletsByTenant[tenantSlug]
	if !ok {
		return nil // tenant has no predefined outlets
	}

	for _, d := range defs {
		id := outletSeedID(tenantSlug, d.slug)

		existing, err := client.Outlet.Query().Where(entoutlet.ID(id)).Only(ctx)
		if err == nil {
			// Update mutable fields on re-run
			upd := existing.Update().
				SetCode(d.code).
				SetName(d.name).
				SetUseCase(d.useCase).
				SetIsHq(d.isHQ).
				SetStatus("active")
			if d.address != "" {
				upd = upd.SetNillableAddress(&d.address)
			}
			if d.pinMsg != "" {
				upd = upd.SetNillablePinLoginMessage(&d.pinMsg)
			}
			if _, err2 := upd.Save(ctx); err2 != nil {
				log.Printf("  ⚠️  update outlet %s/%s: %v", tenantSlug, d.slug, err2)
			} else {
				log.Printf("  ✓ Outlet updated: %s/%s (use_case=%s, is_hq=%v)", tenantSlug, d.code, d.useCase, d.isHQ)
			}
			continue
		}
		if !ent.IsNotFound(err) {
			return fmt.Errorf("query outlet %s/%s: %w", tenantSlug, d.slug, err)
		}

		create := client.Outlet.Create().
			SetID(id).
			SetTenantID(tenantID).
			SetCode(d.code).
			SetName(d.name).
			SetUseCase(d.useCase).
			SetIsHq(d.isHQ).
			SetStatus("active")
		if d.address != "" {
			create = create.SetNillableAddress(&d.address)
		}
		if d.pinMsg != "" {
			create = create.SetNillablePinLoginMessage(&d.pinMsg)
		}
		if _, err2 := create.Save(ctx); err2 != nil {
			return fmt.Errorf("create outlet %s/%s: %w", tenantSlug, d.slug, err2)
		}
		log.Printf("  ✓ Outlet created: %s/%s (use_case=%s, is_hq=%v, id=%s)", tenantSlug, d.code, d.useCase, d.isHQ, id)
	}
	return nil
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

	if envKey := os.Getenv("INTERNAL_SERVICE_KEY"); envKey != "" {
		// Use the provided key
		plainKey = envKey
		if len(plainKey) >= 8 {
			keyPrefix = plainKey[:8]
		} else {
			keyPrefix = plainKey
		}
		hashBytes := sha256.Sum256([]byte(plainKey))
		keyHash = hex.EncodeToString(hashBytes[:])
		log.Printf("  ℹ️  Using INTERNAL_SERVICE_KEY from environment")
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
	log.Printf("  INTERNAL_SERVICE_KEY=%s", plainKey)
	log.Printf("  Set this in auth-api-secrets (and all other service secrets) as INTERNAL_SERVICE_KEY.")
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

// seedPlatformApp creates the default platform App with a GitHub-style bng_app_* token.
// Services can migrate to this token progressively, replacing the legacy INTERNAL_SERVICE_KEY.
// The token is stored only as a SHA-256 hash; the plain token is printed once for operator storage.
func seedPlatformApp(ctx context.Context, client *ent.Client) error {
	const appName = "Codevertex Platform Services"

	// Idempotent: skip if already exists
	exists, err := client.App.Query().
		Where(
			entapp.NameEQ(appName),
			entapp.AppTypeEQ(entapp.AppTypePlatform),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("check existing platform app: %w", err)
	}
	if exists {
		log.Printf("  ✓ Platform App already exists")
		return nil
	}

	// Generate bng_app_* token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate token bytes: %w", err)
	}
	token := "bng_app_" + base64.URLEncoding.EncodeToString(b)
	prefix := token
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	hashBytes := sha256.Sum256([]byte(token))
	keyHash := hex.EncodeToString(hashBytes[:])

	// Generate public client_id
	cidBytes := make([]byte, 6)
	if _, err := rand.Read(cidBytes); err != nil {
		return fmt.Errorf("generate client_id: %w", err)
	}
	clientID := "app_" + hex.EncodeToString(cidBytes)

	_, err = client.App.Create().
		SetName(appName).
		SetDescription("Default platform app for S2S calls across all Codevertex services").
		SetAppType(entapp.AppTypePlatform).
		SetClientID(clientID).
		SetKeyHash(keyHash).
		SetKeyPrefix(prefix).
		SetScopes([]string{"s2s:*"}).
		SetStatus(entapp.StatusActive).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("create platform app: %w", err)
	}

	log.Printf("  ✅ Platform App created! client_id=%s", clientID)
	log.Printf("  ⚠️  IMPORTANT: Save this token — it will NOT be shown again:")
	log.Printf("  PLATFORM_APP_TOKEN=%s", token)
	log.Printf("  Configure this in each service's Settings → Integrations page as the S2S auth token.")
	return nil
}
