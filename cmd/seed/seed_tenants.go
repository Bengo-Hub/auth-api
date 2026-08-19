package main

import (
	"context"
	"fmt"
	"log"

	"github.com/bengobox/auth-api/internal/ent"
	entoutlet "github.com/bengobox/auth-api/internal/ent/outlet"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/google/uuid"
)

// tenantSpec describes a tenant to seed.
type tenantSpec struct {
	name            string
	slug            string
	baseDomain      string
	isPlatformOwner bool
	isDemo          bool   // bypasses subscription gating across all services
	billingMode     string // "service_charge" for transaction-fee tenants
	useCases        []string
	logoURL         string
	website         string
	contactEmail    string
	contactPhone    string
	brandColors     map[string]any
}

// tenantRef is a lightweight reference returned after seeding tenants.
type tenantRef struct {
	ID   uuid.UUID
	Name string
	Slug string
}

// seedTenants upserts all platform tenants and returns their references in the same order.
func seedTenants(ctx context.Context, client *ent.Client) ([]*tenantRef, error) {
	// Media base URL for tenant logos — points to the SSO/accounts CDN host.
	const mediaBase = "https://accounts.codevertexafrica.com"

	tenants := []tenantSpec{
		{
			name: "Codevertex Africa Limited", slug: "codevertex", baseDomain: "codevertexafrica.com",
			isPlatformOwner: true, useCases: nil,
			logoURL: mediaBase + "/images/logo/codevertex.png", website: "https://codevertexafrica.com",
			contactEmail: "info@codevertexafrica.com", contactPhone: "+254 743 793 901",
			brandColors: map[string]any{"primary": "#9100B0", "secondary": "#6E6873", "accent": "#000000"},
		},
		{
			name: "Masterspace Solutions", slug: "mss", baseDomain: "masterspace.co.ke",
			useCases: []string{"services"},
			logoURL:  mediaBase + "/images/logo/mss.jpeg", website: "https://masterspace.co.ke",
			contactEmail: "info@masterspace.co.ke",
			brandColors:  map[string]any{"primary": "#1e3a5f", "secondary": "#4a90d9", "accent": "#f0ad4e"},
		},
		{
			name: "Kenya Urban Roads Authority (KURA)", slug: "kura", baseDomain: "kura.go.ke",
			useCases: []string{"logistics"},
			logoURL:  mediaBase + "/images/logo/kura.png", website: "https://kura.go.ke",
			contactEmail: "info@kura.go.ke",
			brandColors:  map[string]any{"primary": "#006633", "secondary": "#bb0000", "accent": "#000000"},
		},
		{
			name: "UltiChange", slug: "ultichange", baseDomain: "ultichange.org",
			useCases: []string{"services", "e_commerce"},
			logoURL:  mediaBase + "/images/logo/ultichange.svg", website: "https://ultichange.org",
			contactEmail: "info@ultichange.org",
			brandColors:  map[string]any{"primary": "#2d3436", "secondary": "#0984e3", "accent": "#00cec9"},
		},
		{
			name: "Urban Loft Cafe", slug: "urban-loft", baseDomain: "theurbanloftcafe.com",
			useCases: []string{"hospitality"},
			logoURL:  mediaBase + "/images/logo/urban-loft.png", website: "https://theurbanloftcafe.com",
			contactEmail: "info@theurbanloftcafe.com",
			brandColors:  map[string]any{"primary": "#3E2723", "secondary": "#795548", "accent": "#FFC107"},
		},
		{
			// Cross-platform demo tenant — covers all use-cases for platform demos.
			// is_demo=true is written to metadata so all downstream services bypass subscription gating.
			name: "Codevertex Demo", slug: "codevertex-demo", baseDomain: "demo.codevertexafrica.com",
			isDemo: true,
			// Must cover every use_case in outletsByTenant["codevertex-demo"] below —
			// "manufacturing" was missing even though the demo owns a manufacturing outlet
			// (MFG), an mgr.mfg@ demo user, and seeded production batches + BOM stock.
			useCases: []string{
				"hospitality", "retail", "quick_service", "pharmacy", "services",
				"logistics", "warehouse", "manufacturing", "commercial_weighing",
				"axle_load_enforcement", "hospital",
			},
			logoURL:      mediaBase + "/images/logo/codevertex.png",
			website:      "https://demo.codevertexafrica.com",
			contactEmail: "demo@codevertexafrica.com",
			brandColors:  map[string]any{"primary": "#9100B0", "secondary": "#6E6873", "accent": "#000000"},
		},
	}

	var refs []*tenantRef

	for _, t := range tenants {
		meta := map[string]any{
			"base_domain": t.baseDomain,
		}
		if t.isPlatformOwner {
			meta["is_platform_owner"] = true
			meta["scope"] = "platform"
		}
		if t.isDemo {
			meta["is_demo"] = true
		}
		if t.billingMode != "" {
			meta["billing_mode"] = t.billingMode
		}

		tenantEntity, err := client.Tenant.Query().Where(tenant.SlugEQ(t.slug)).Only(ctx)
		if err != nil {
			create := client.Tenant.Create().
				SetName(t.name).
				SetSlug(t.slug).
				SetStatus("active").
				SetIsDemo(t.isDemo).
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
				return nil, fmt.Errorf("create tenant %s: %w", t.slug, err)
			}
			log.Printf("✓ Created tenant: %s (%s) base_domain=%s", t.name, t.slug, t.baseDomain)
		} else {
			// Tenant already exists. Only enforce platform invariant metadata flags
			// (is_platform_owner, is_demo, base_domain, billing_mode).
			// All user-configurable fields (logo, brand colours, contact info, use cases)
			// are left untouched so admin customisations made via auth-ui are preserved.
			existingMeta := tenantEntity.Metadata
			if existingMeta == nil {
				existingMeta = map[string]any{}
			}
			for k, v := range meta {
				existingMeta[k] = v
			}
			upd := tenantEntity.Update().SetMetadata(existingMeta).SetIsDemo(t.isDemo)
			// Backfill optional fields only when they are still unset (never overwrite).
			if tenantEntity.LogoURL == nil && t.logoURL != "" {
				upd = upd.SetLogoURL(t.logoURL)
			}
			if tenantEntity.BrandColors == nil && len(t.brandColors) > 0 {
				upd = upd.SetBrandColors(t.brandColors)
			}
			if tenantEntity.Website == nil && t.website != "" {
				upd = upd.SetWebsite(t.website)
			}
			if tenantEntity.ContactEmail == nil && t.contactEmail != "" {
				upd = upd.SetContactEmail(t.contactEmail)
			}
			// One-off correction: "codevertex" was originally seeded with the founder's
			// personal Gmail address as its contact email, which then leaked into every
			// customer-facing notification footer (OTP emails, etc). Force-correct that one
			// known-stale value; every other tenant/field keeps the backfill-only behavior
			// above so admin-console edits are never clobbered.
			if t.slug == "codevertex" && tenantEntity.ContactEmail != nil && *tenantEntity.ContactEmail == "codevertexitsolutions@gmail.com" {
				upd = upd.SetContactEmail(t.contactEmail)
			}
			if tenantEntity.ContactPhone == nil && t.contactPhone != "" {
				upd = upd.SetContactPhone(t.contactPhone)
			}
			// Backfill use cases when unset. The demo tenant is the exception: its use_case
			// list must stay in lockstep with the outlets the seed owns (same reasoning as the
			// demo-only outlet display reset below), so it is re-synced on every run rather
			// than only when empty.
			if len(t.useCases) > 0 && (len(tenantEntity.UseCases) == 0 || t.isDemo) {
				upd = upd.SetUseCase(t.useCases[0]).SetUseCases(t.useCases)
			}
			if _, err2 := upd.Save(ctx); err2 != nil {
				log.Printf("⚠️  update tenant metadata %s: %v", t.slug, err2)
			} else {
				log.Printf("✓ Tenant exists (metadata synced): %s (%s)", t.name, t.slug)
			}
		}

		refs = append(refs, &tenantRef{
			ID:   tenantEntity.ID,
			Name: tenantEntity.Name,
			Slug: tenantEntity.Slug,
		})
	}

	return refs, nil
}

// outletDef describes an outlet to seed for a specific tenant.
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
			name: "Demo City Supermarket", useCase: "retail", isHQ: false,
			address: "Demo Mall, Westlands, Nairobi",
			pinMsg:  "Welcome to Demo City Supermarket — barcode scanner is active",
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
		// Hospital/clinic outlet — Codevertex Afya (consultation, lab, pharmacy, billing)
		{
			slug: "demo-hospital", code: "AFYA",
			name: "Demo Afya Clinic", useCase: "hospital", isHQ: false,
			address: "Demo Health Centre, Upper Hill, Nairobi",
			pinMsg:  "Welcome to Demo Afya Clinic — verify patient identity before opening a chart",
		},
		// Services outlet — salon, spa, appointments
		{
			slug: "demo-services", code: "SVC",
			name: "Demo Beauty & Wellness", useCase: "services", isHQ: false,
			address: "Demo Towers, Kilimani, Nairobi",
			pinMsg:  "Welcome to Demo Beauty & Wellness — check appointments board",
		},
		// Logistics hub — syncs to logistics-api only (dispatch, routing, rider management)
		{
			slug: "demo-logistics", code: "LOGIS",
			name: "Demo Logistics Hub", useCase: "logistics", isHQ: false,
			address: "Demo Industrial Area, Nairobi",
			pinMsg:  "Welcome to Demo Logistics Hub — report to dispatch supervisor",
		},
		// Inventory-only warehouse — stock storage with no POS/ordering
		{
			slug: "demo-warehouse", code: "WH",
			name: "Demo Central Warehouse", useCase: "warehouse", isHQ: false,
			address: "Demo Warehouse Park, Mombasa Road, Nairobi",
			pinMsg:  "Welcome to Demo Central Warehouse — check inbound manifest",
		},
		// Manufacturing facility — BOM-driven production, syncs to inventory-api only
		{
			slug: "demo-manufacturing", code: "MFG",
			name: "Demo Production Facility", useCase: "manufacturing", isHQ: false,
			address: "Demo Industrial Park, Athi River, Kenya",
			pinMsg:  "Welcome to Demo Manufacturing — check the production schedule",
		},
		// TruLoad: commercial weighbridge station
		{
			slug: "demo-commercial", code: "COMM",
			name: "Demo Commercial Weighbridge", useCase: "commercial_weighing", isHQ: false,
			address: "Demo Industrial Zone, Athi River, Kenya",
			pinMsg:  "Welcome to Demo Commercial Weighbridge — log in to begin weighing session",
		},
		// TruLoad: axle load enforcement checkpoint
		{
			slug: "demo-enforcement", code: "ENF",
			name: "Demo Axle Load Enforcement Hub", useCase: "axle_load_enforcement", isHQ: false,
			address: "Demo Weigh Station, Nakuru Highway, Kenya",
			pinMsg:  "Welcome to Demo Enforcement — report to station commander",
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
}

// outletSeedID returns a deterministic UUID for an outlet using the same formula
// as pos-api, inventory-api, and ordering-backend — ensuring cross-service UUID alignment.
func outletSeedID(tenantSlug, outletSlug string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("bengobox:cafe:outlet:%s:%s", tenantSlug, outletSlug)))
}

// seedOutletsForTenant upserts all predefined outlets for the given tenant.
func seedOutletsForTenant(ctx context.Context, client *ent.Client, tenantID uuid.UUID, tenantSlug string) error {
	defs, ok := outletsByTenant[tenantSlug]
	if !ok {
		return nil // tenant has no predefined outlets
	}

	for _, d := range defs {
		id := outletSeedID(tenantSlug, d.slug)

		existing, err := client.Outlet.Query().Where(entoutlet.ID(id)).Only(ctx)
		if err == nil {
			// Always sync seed-structural fields (code, use_case, is_hq, status).
			// For the demo tenant, also reset display/UX fields so demo state stays
			// predictable across deployments.
			// For real tenants, preserve name, address, and PIN message — these may
			// have been customised via the POS admin or auth-ui and must not be reset.
			upd := existing.Update().
				SetCode(d.code).
				SetUseCase(d.useCase).
				SetIsHq(d.isHQ).
				SetStatus("active")
			if tenantSlug == "codevertex-demo" {
				upd = upd.SetName(d.name)
				if d.address != "" {
					upd = upd.SetNillableAddress(&d.address)
				}
				if d.pinMsg != "" {
					upd = upd.SetNillablePinLoginMessage(&d.pinMsg)
				}
			} else {
				// Backfill only when unset.
				if existing.Name == "" {
					upd = upd.SetName(d.name)
				}
				if existing.Address == nil && d.address != "" {
					upd = upd.SetNillableAddress(&d.address)
				}
				if existing.PinLoginMessage == nil && d.pinMsg != "" {
					upd = upd.SetNillablePinLoginMessage(&d.pinMsg)
				}
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
