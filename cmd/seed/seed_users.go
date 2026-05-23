package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/google/uuid"
)

// seedDemoUser seeds the cross-platform demo user (demo@bengobox.dev).
// Primary tenant must be codevertex-demo, NOT codevertex (platform owner).
// Using codevertex as primary would mint is_platform_owner=true in the JWT,
// giving the demo user full platform-admin access — a confirmed prod bug.
func seedDemoUser(ctx context.Context, client *ent.Client, hasher *password.Hasher, tenantEntities []*tenantRef) error {
	demoPrimaryTenant := tenantEntities[len(tenantEntities)-1] // codevertex-demo

	demoEmail := "demo@bengobox.dev"
	demoPassword := os.Getenv("SEED_DEMO_PASSWORD")
	if demoPassword == "" {
		demoPassword = "DemoUser2024!" // default for local dev; override via env in production
	}

	demoHash, err := hasher.Hash(demoPassword)
	if err != nil {
		return fmt.Errorf("hash demo password: %w", err)
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
			return fmt.Errorf("seed demo user: %w", err)
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
	return nil
}

// seedAdminUser seeds the platform super admin user.
func seedAdminUser(ctx context.Context, client *ent.Client, hasher *password.Hasher, tenantEntities []*tenantRef) error {
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

	if adminEmail == "" || adminPassword == "" {
		return nil
	}

	adminHash, err := hasher.Hash(adminPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
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
			return fmt.Errorf("seed admin user: %w", err)
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
	return nil
}

// demoStaffSpec describes a demo staff user.
type demoStaffSpec struct {
	email string
	name  string
	role  string
}

// demoStaff lists all cross-platform demo staff under codevertex-demo.
// These accounts cover every POS role so PIN login works for demos on any outlet.
// Urban-loft staff emails have been migrated here; the urban-loft tenant now has
// only its real admin user (admin@theurbanloftcafe.com).
var demoStaff = []demoStaffSpec{
	// POS roles
	{"manager@demo.codevertexitsolutions.com", "Demo Manager", "manager"},
	{"cashier@demo.codevertexitsolutions.com", "Demo Cashier", "cashier"},
	{"waiter@demo.codevertexitsolutions.com", "Demo Waiter", "waiter"},
	{"kitchen@demo.codevertexitsolutions.com", "Demo Kitchen", "kitchen"},
	{"bar@demo.codevertexitsolutions.com", "Demo Bar Staff", "bar"},
	{"receptionist@demo.codevertexitsolutions.com", "Demo Receptionist", "receptionist"},
	// Logistics roles
	{"rider@demo.codevertexitsolutions.com", "Demo Rider", "rider"},
	{"driver@demo.codevertexitsolutions.com", "Demo Driver", "driver"},
	{"coordinator@demo.codevertexitsolutions.com", "Demo Coordinator", "delivery_coordinator"},
	// Cross-service roles
	{"technician@demo.codevertexitsolutions.com", "Demo Technician", "technician"},
	{"viewer@demo.codevertexitsolutions.com", "Demo Viewer", "viewer"},
	{"customer@demo.codevertexitsolutions.com", "Demo Customer", "customer"},
	// Pharmacy role
	{"pharmacist@demo.codevertexitsolutions.com", "Grace Pharmacist", "pharmacist"},
}

// seedDemoStaff seeds all demo staff users under the codevertex-demo tenant.
func seedDemoStaff(ctx context.Context, client *ent.Client, hasher *password.Hasher, demoTenant *tenantRef) error {
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
		isNew := false
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
			isNew = true
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

		// Publish outbox event so the running auth-api picks it up and syncs to
		// downstream services (pos-api staff profiles, inventory users, etc.).
		// New users get "created"; re-runs get "updated" to re-trigger provisioning.
		eventType := "updated"
		if isNew {
			eventType = "created"
		}
		publishSeedUserEvent(ctx, client, demoTenant.ID, staffUser.ID, map[string]any{
			"user_id":     staffUser.ID.String(),
			"email":       s.email,
			"full_name":   s.name,
			"tenant_id":   demoTenant.ID.String(),
			"tenant_slug": demoTenant.Slug,
			"roles":       []string{s.role},
			"method":      "seed",
		}, eventType)
	}
	return nil
}

// seedTenantStaffUsers seeds a generic staff user for every tenant.
func seedTenantStaffUsers(ctx context.Context, client *ent.Client, hasher *password.Hasher, tenantEntities []*tenantRef) error {
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
	return nil
}

// seedUrbanLoftAdmin seeds the tenant-specific admin for Urban Loft Cafe.
func seedUrbanLoftAdmin(ctx context.Context, client *ent.Client, hasher *password.Hasher, urbanLoftTenant *tenantRef) error {
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
			return nil
		}
		log.Printf("✓ Tenant admin exists: %s", tenantAdminEmail)
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
	return nil
}

// seedDemoTenantAdmin seeds the codevertex-demo tenant admin.
func seedDemoTenantAdmin(ctx context.Context, client *ent.Client, hasher *password.Hasher, demoTenant *tenantRef) error {
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
	return nil
}

// seedOAuthClients seeds OAuth client records for all known frontend applications.
func seedOAuthClients(ctx context.Context, client *ent.Client, tenantEntities []*tenantRef) error {
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
		{ID: "codevertex-website", Name: "Codevertex Africa Limited Website", ProductionHost: "codevertexitsolutions.com", Public: true},
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
			_, err := existing.Update().
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

		_, err := client.OAuthClient.Create().
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
	return nil
}

// seedMembership is a helper to add a user to a tenant with a given role if the membership doesn't exist.
func seedMembership(ctx context.Context, client *ent.Client, userID, tenantID uuid.UUID, tenantSlug, role string) {
	exists, _ := client.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userID),
			tenantmembership.TenantID(tenantID),
		).Exist(ctx)
	if !exists {
		_, err := client.TenantMembership.Create().
			SetUserID(userID).
			SetTenantID(tenantID).
			SetRoles([]string{role}).
			Save(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error creating %s membership for %s: %v", role, tenantSlug, err)
		} else {
			log.Printf("  ✓ Added %s role in %s", role, tenantSlug)
		}
	}
}
