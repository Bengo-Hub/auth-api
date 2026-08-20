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

// seedAdminUser seeds the platform super admin user.
func seedAdminUser(ctx context.Context, client *ent.Client, hasher *password.Hasher, tenantEntities []*tenantRef) error {
	adminEmail := os.Getenv("SEED_SUPER_ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = os.Getenv("SEED_ADMIN_EMAIL")
	}
	if adminEmail == "" {
		adminEmail = "admin@codevertexafrica.com"
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
// pin is the POS demo PIN (1-4 digits). Empty means no PIN is seeded for this account.
// outletSlugs lists the outlet slugs (within codevertex-demo) this staff can log in at.
// admin@demo.codevertexafrica.com (PIN 0000) is seeded separately in seedDemoTenantAdmin.
type demoStaffSpec struct {
	email       string
	name        string
	role        string
	pin         string
	outletSlugs []string
}

// allPOSOutlets lists all codevertex-demo outlet slugs that matter for POS login.
var allPOSOutlets = []string{"demo-hospitality", "demo-retail", "demo-quick", "demo-pharmacy", "demo-services"}

// demoStaff lists all cross-platform demo staff under codevertex-demo.
// PIN layout: manager=1111, cashier=2222, waiter=3333, kitchen=4444, bar=5555,
//
//	receptionist=6666, pharmacist=7777, stylist=8888, therapist=9999.
//
// Admin (0000) is in seedDemoTenantAdmin.
// Auth-api publishes auth.user.created + auth.user.pin_set events so pos-api
// creates StaffMember rows and sets PINs without service-level staff seeding.
var demoStaff = []demoStaffSpec{
	// POS roles — outlet scope defines where the PIN can log in
	{"manager@demo.codevertexafrica.com", "Demo Manager", "manager", "1111", allPOSOutlets},
	{"cashier@demo.codevertexafrica.com", "Demo Cashier", "cashier", "2222", allPOSOutlets},
	{"waiter@demo.codevertexafrica.com", "Demo Waiter", "waiter", "3333", []string{"demo-hospitality"}},
	{"kitchen@demo.codevertexafrica.com", "Demo Kitchen", "kitchen", "4444", []string{"demo-hospitality", "demo-quick"}},
	{"bar@demo.codevertexafrica.com", "Demo Bar Staff", "bar", "5555", []string{"demo-hospitality"}},
	{"receptionist@demo.codevertexafrica.com", "Demo Receptionist", "receptionist", "6666", []string{"demo-hospitality", "demo-services"}},
	// Pharmacy role
	{"pharmacist@demo.codevertexafrica.com", "Grace Pharmacist", "pharmacist", "7777", []string{"demo-pharmacy"}},
	// Services roles (beauty salon / spa / wellness)
	{"stylist@demo.codevertexafrica.com", "Demo Stylist", "stylist", "8888", []string{"demo-services"}},
	{"therapist@demo.codevertexafrica.com", "Demo Therapist", "therapist", "9999", []string{"demo-services"}},
	// Logistics roles (no POS PIN — these users don't log in at POS terminals)
	{"rider@demo.codevertexafrica.com", "Demo Rider", "rider", "", nil},
	{"driver@demo.codevertexafrica.com", "Demo Driver", "driver", "", nil},
	{"coordinator@demo.codevertexafrica.com", "Demo Coordinator", "delivery_coordinator", "", nil},
	// Cross-service roles
	{"technician@demo.codevertexafrica.com", "Demo Technician", "technician", "", nil},
	{"viewer@demo.codevertexafrica.com", "Demo Viewer", "viewer", "", nil},
	{"customer@demo.codevertexafrica.com", "Demo Customer", "customer", "", nil},

	// Inventory outlet managers — non-HQ (role=manager, NOT admin), one per use_case
	// so the inventory-ui per-use_case side-menu gating and page nomenclature can be
	// exercised by logging in as a single-outlet manager. No POS PIN: these users log
	// into inventory-ui via SSO, not at a POS terminal. The auth.user event carries
	// outlet_ids, which inventory-api's UserOutlet subscriber projects into assignments.
	// admin@demo (role=admin) stays HQ and sees the full "All Outlets" superset.
	{"mgr.hospitality@demo.codevertexafrica.com", "Demo Hospitality Manager", "manager", "", []string{"demo-hospitality"}},
	{"mgr.retail@demo.codevertexafrica.com", "Demo Retail Manager", "manager", "", []string{"demo-retail"}},
	{"mgr.quick@demo.codevertexafrica.com", "Demo Quick-Service Manager", "manager", "", []string{"demo-quick"}},
	{"mgr.pharmacy@demo.codevertexafrica.com", "Demo Pharmacy Manager", "manager", "", []string{"demo-pharmacy"}},
	{"mgr.services@demo.codevertexafrica.com", "Demo Services Manager", "manager", "", []string{"demo-services"}},
	{"mgr.warehouse@demo.codevertexafrica.com", "Demo Warehouse Manager", "manager", "", []string{"demo-warehouse"}},
	{"mgr.mfg@demo.codevertexafrica.com", "Demo Manufacturing Manager", "manager", "", []string{"demo-manufacturing"}},
	// Multi-location manager — assigned to 3 outlets across POS + non-POS use_cases to
	// prove the select-outlet multi-location flow (user must pick one before entering).
	{"mgr.multi@demo.codevertexafrica.com", "Demo Multi-Outlet Manager", "manager", "", []string{"demo-retail", "demo-pharmacy", "demo-manufacturing"}},

	// Codevertex Afya (hospital-service) clinical staff — SSO-only (no POS PIN), scoped
	// to demo-hospital. Distinct emails from pos-api's own pharmacist@demo above (this is
	// an additive, hospital-service-scoped identity set — pos-api's pharmacy demo data is
	// untouched). Roles doctor/nurse registered in seed_roles_catalogue.go/seed_permissions.go;
	// pharmacist/records_clerk already exist from pos-api's clinical seed.
	{"doctor@demo.codevertexafrica.com", "Dr. Amina Otieno", "doctor", "", []string{"demo-hospital"}},
	{"nurse@demo.codevertexafrica.com", "Nurse Faith Wanjiru", "nurse", "", []string{"demo-hospital"}},
	{"pharmacist.afya@demo.codevertexafrica.com", "Demo Afya Pharmacist", "pharmacist", "", []string{"demo-hospital"}},
	{"records@demo.codevertexafrica.com", "Demo Afya Records Clerk", "records_clerk", "", []string{"demo-hospital"}},
	{"mgr.hospital@demo.codevertexafrica.com", "Demo Afya Clinic Manager", "manager", "", []string{"demo-hospital"}},
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

		// Resolve outlet IDs from slugs using the same deterministic function as pos-api seed.
		outletIDStrs := make([]string, 0, len(s.outletSlugs))
		for _, slug := range s.outletSlugs {
			outletIDStrs = append(outletIDStrs, outletSeedID(demoTenant.Slug, slug).String())
		}

		// Publish outbox event so the running auth-api picks it up and syncs to
		// downstream services (pos-api staff profiles, inventory users, etc.).
		// New users get "created"; re-runs get "updated" to re-trigger provisioning.
		eventType := "updated"
		if isNew {
			eventType = "created"
		}
		payload := map[string]any{
			"user_id":     staffUser.ID.String(),
			"email":       s.email,
			"full_name":   s.name,
			"tenant_id":   demoTenant.ID.String(),
			"tenant_slug": demoTenant.Slug,
			"roles":       []string{s.role},
			"method":      "seed",
		}
		if len(outletIDStrs) > 0 {
			payload["outlet_ids"] = outletIDStrs
			payload["outlet_id"] = outletIDStrs[0] // backward-compat: primary outlet
		}
		publishSeedUserEvent(ctx, client, demoTenant.ID, staffUser.ID, payload, eventType)

		// Publish PIN set event so pos-api sets the demo PIN on this StaffMember.
		// Pos-api's auth.user.pin_set handler calls bcrypt.CompareHashAndPassword,
		// so the hash must be bcrypt — publishSeedPINEvent handles the hashing.
		if s.pin != "" {
			publishSeedPINEvent(ctx, client, demoTenant.ID, staffUser.ID, demoTenant.Slug, s.pin, []string{s.role})
		}
	}
	return nil
}

// erpDemoStaffSpec describes a demo ERP user (HR + internal-ops Django service).
// role is the global JWT role auth-api issues; it matches an ERP Django group name
// 1:1 so the ERP JIT (authmanagement/sso.py ERP_SERVICE_ROLES) assigns that group.
// ERP users do not log in at POS terminals, so there is no PIN/outlet scope here.
type erpDemoStaffSpec struct {
	email string
	name  string
	role  string
}

// erpDemoStaff lists one demo user per ERP service role under codevertex-demo.
// Roles mirror erp-api core/security.py + core/management/commands/seed_initial.py and
// the ERP_SERVICE_ROLES set in authmanagement/sso.py. Logging in as e.g.
// hr.manager@demo.codevertexafrica.com yields the "hr_manager" global role, which
// the ERP JIT maps to the hr_manager Django group → service permissions sync.
//
// "staff" and "receptionist" demo coverage: receptionist already has a POS demo user in
// demoStaff above (receptionist@demo... role=receptionist), and every tenant gets a
// staff@{slug} user via seedTenantStaffUsers (staff@codevertex-demo.com, role=staff).
// They are intentionally NOT duplicated here. The 11 entries below complete the set of
// 13 ERP roles so there is at least one demo user per role in codevertex-demo.
var erpDemoStaff = []erpDemoStaffSpec{
	{"superusers@demo.codevertexafrica.com", "Demo ERP Superuser", "superusers"},
	{"ceo@demo.codevertexafrica.com", "Demo CEO", "ceo"},
	{"hr.manager@demo.codevertexafrica.com", "Demo HR Manager", "hr_manager"},
	{"hr.assistant@demo.codevertexafrica.com", "Demo HR Assistant", "hr_assistant"},
	{"ict.manager@demo.codevertexafrica.com", "Demo ICT Manager", "ict_manager"},
	{"ict.officer@demo.codevertexafrica.com", "Demo ICT Officer", "ict_officer"},
	{"operations.manager@demo.codevertexafrica.com", "Demo Operations Manager", "operations_manager"},
	{"finance.manager@demo.codevertexafrica.com", "Demo Finance Manager", "finance_manager"},
	{"procurement.manager@demo.codevertexafrica.com", "Demo Procurement Manager", "procurement_manager"},
	{"sales.manager@demo.codevertexafrica.com", "Demo Sales Manager", "sales_manager"},
	{"secretary@demo.codevertexafrica.com", "Demo Secretary", "secretary"},
}

// seedERPDemoStaff seeds one demo user per ERP service role under codevertex-demo.
// Mirrors seedDemoStaff (user + tenant membership carrying the role as the global role +
// an auth.user outbox event) but without POS PIN/outlet scope, since ERP users are not
// POS terminal operators. Idempotent: re-runs find the existing user, re-use the
// seedMembership guard, and re-publish an "updated" event to re-trigger provisioning.
func seedERPDemoStaff(ctx context.Context, client *ent.Client, hasher *password.Hasher, demoTenant *tenantRef) error {
	log.Println("Seeding ERP demo staff under codevertex-demo...")
	demoStaffPassword := os.Getenv("SEED_DEMO_STAFF_PASSWORD")
	if demoStaffPassword == "" {
		demoStaffPassword = "DemoStaff2024!"
	}

	for _, s := range erpDemoStaff {
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
				log.Printf("  ⚠️  seed erp demo staff %s: %v", s.email, createErr)
				continue
			}
			log.Printf("  ✓ ERP demo staff exists: %s (%s)", s.email, s.role)
		} else {
			isNew = true
			log.Printf("  ✓ Created ERP demo staff: %s (%s)", s.email, s.role)
		}

		// Reuse the shared membership helper to attach the ERP role as the global role.
		seedMembership(ctx, client, staffUser.ID, demoTenant.ID, demoTenant.Slug, s.role)

		// Publish outbox event so the running auth-api syncs this user to downstream
		// services (erp-api JIT-provisions the CustomUser shadow + Django group on first
		// SSO login; the event lets eager provisioners pick it up too).
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
	// Production client tenants that manage their own real users — skip generic seed accounts.
	skipSlugs := map[string]bool{"urban-loft": true}
	for _, te := range tenantEntities {
		if skipSlugs[te.Slug] {
			continue
		}
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

// seedDemoTenantAdmin seeds the codevertex-demo tenant admin.
func seedDemoTenantAdmin(ctx context.Context, client *ent.Client, hasher *password.Hasher, demoTenant *tenantRef) error {
	demoTenantAdminEmail := "admin@demo.codevertexafrica.com"
	demoTenantAdminPassword := os.Getenv("SEED_DEMO_TENANT_ADMIN_PASSWORD")
	if demoTenantAdminPassword == "" {
		demoTenantAdminPassword = "DemoAdmin2024!"
	}
	demoTenantAdminHash, _ := hasher.Hash(demoTenantAdminPassword)

	isNew := false
	demoTenantAdmin, err := client.User.Create().
		SetEmail(demoTenantAdminEmail).
		SetPasswordHash(demoTenantAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(demoTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "Demo Admin",
			"created_by": "seed",
			"role":       "admin",
		}).
		Save(ctx)
	if err != nil {
		demoTenantAdmin, _ = client.User.Query().Where(user.EmailEQ(demoTenantAdminEmail)).Only(ctx)
		log.Printf("✓ Demo tenant admin exists: %s", demoTenantAdminEmail)
	} else {
		isNew = true
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

		// Publish user event so pos-api creates a StaffMember for the demo admin.
		// Then publish PIN 0000 so pos-api sets the PIN hash on that StaffMember.
		// This is the same admin@demo.codevertexafrica.com — no separate account created.
		eventType := "updated"
		if isNew {
			eventType = "created"
		}
		// Admin is assigned to all POS outlets.
		adminOutletIDs := make([]string, 0, len(allPOSOutlets))
		for _, slug := range allPOSOutlets {
			adminOutletIDs = append(adminOutletIDs, outletSeedID(demoTenant.Slug, slug).String())
		}
		publishSeedUserEvent(ctx, client, demoTenant.ID, demoTenantAdmin.ID, map[string]any{
			"user_id":     demoTenantAdmin.ID.String(),
			"email":       demoTenantAdminEmail,
			"full_name":   "Demo Admin",
			"tenant_id":   demoTenant.ID.String(),
			"tenant_slug": demoTenant.Slug,
			"roles":       []string{"admin"},
			"outlet_ids":  adminOutletIDs,
			"outlet_id":   adminOutletIDs[0],
			"method":      "seed",
		}, eventType)
		publishSeedPINEvent(ctx, client, demoTenant.ID, demoTenantAdmin.ID, demoTenant.Slug, "0000", []string{"admin"})
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
		ProductionHost string // e.g. "books.codevertexafrica.com"
		Public         bool
	}
	clients := []clientDef{
		{ID: "notifications-ui", Name: "Codevertex Notifications UI", ProductionHost: "notifications.codevertexafrica.com", Public: true},
		{ID: "ordering-ui", Name: "Codevertex Ordering UI", ProductionHost: "ordering.codevertexafrica.com", Public: true},
		{ID: "rider-app", Name: "Codevertex Rider App", ProductionHost: "riderapp.codevertexafrica.com", Public: true},
		{ID: "codevertex-website", Name: "Codevertex Africa Limited Website", ProductionHost: "codevertexafrica.com", Public: true},
		{ID: "subscriptions-ui", Name: "Codevertex Subscriptions UI", ProductionHost: "pricing.codevertexafrica.com", Public: true},
		{ID: "treasury-ui", Name: "Codevertex Treasury UI", ProductionHost: "books.codevertexafrica.com", Public: true},
		{ID: "pos-ui", Name: "Codevertex POS UI", ProductionHost: "pos.codevertexafrica.com", Public: true},
		{ID: "inventory-ui", Name: "Codevertex Inventory UI", ProductionHost: "inventory.codevertexafrica.com", Public: true},
		{ID: "erp-ui", Name: "Codevertex ERP UI", ProductionHost: "erp.codevertexafrica.com", Public: true},
		{ID: "logistics-ui", Name: "Codevertex Logistics UI", ProductionHost: "logistics.codevertexafrica.com", Public: true},
		{ID: "auth-ui", Name: "Codevertex Auth UI (Platform Admin)", ProductionHost: "accounts.codevertexafrica.com", Public: true},
		{ID: "marketflow-ui", Name: "MarketFlow UI", ProductionHost: "marketflow.codevertexafrica.com", Public: true},
		{ID: "truload-ui", Name: "TruLoad Frontend", ProductionHost: "truload.codevertexafrica.com", Public: true},
		{ID: "ticketing-ui", Name: "Codevertex Ticketing UI", ProductionHost: "ticketing.codevertexafrica.com", Public: true},
		{ID: "isp-billing-ui", Name: "Codevertex ISP Billing UI", ProductionHost: "ispbilling.codevertexafrica.com", Public: true},
		{ID: "hospital-ui", Name: "Codevertex Hospital UI (Afya)", ProductionHost: "afya.codevertexafrica.com", Public: true},
	}

	// Collect all tenant slugs for OAuth redirect URI generation.
	allSlugs := tenantSlugs

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
	authUIExtra := []string{"https://sso.codevertexafrica.com/auth/callback"}
	// codevertex-website is reachable on both apex and www
	cvWebsiteExtra := []string{"https://www.codevertexafrica.com/auth/callback"}
	// truload-ui serves three hostnames: the standard codevertexafrica.com subdomain
	// plus external KURA and MSS domains for axle-load enforcement tenants.
	truloadExtra := []string{
		"https://kuraweigh.kura.go.ke/auth/callback",
		"https://kuraweigh.kura.go.ke/kura/auth/callback",
		"https://kuraweightest.masterspace.co.ke/auth/callback",
		"https://kuraweightest.masterspace.co.ke/kura/auth/callback",
		"https://kuraweightest.masterspace.co.ke/mss/auth/callback",
	}

	oauthClients := make([]oauthClientSpec, 0, len(clients))
	for _, c := range clients {
		uris := buildRedirects(c.ProductionHost)
		if c.ID == "auth-ui" {
			uris = append(uris, authUIExtra...)
		}
		if c.ID == "codevertex-website" {
			uris = append(uris, cvWebsiteExtra...)
		}
		if c.ID == "truload-ui" {
			uris = append(uris, truloadExtra...)
		}
		// erp-ui is served on both the codevertex host (above) and the masterspace
		// tenant host — add the masterspace base + per-tenant callbacks too.
		if c.ID == "erp-ui" {
			uris = append(uris, buildRedirects("erp.masterspace.co.ke")...)
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
