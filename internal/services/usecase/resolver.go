package usecase

import (
	"context"
	"sort"
	"strings"
)

// Config represents the use-case specific configuration.
type Config struct {
	UseCase            string         `json:"use_case"`
	Features           []string       `json:"features"`
	Settings           map[string]any `json:"settings"`
	DisplayName        string         `json:"display_name"`
	ApplicableServices []string       `json:"applicable_services"`
}

// Definition is one use case. Catalogue below is the only list of use cases in auth-api: the
// outlet whitelist, outlet event routing, the self-signup trial plan and which apps a tenant can
// sign in to are all read from it.
type Definition struct {
	Code        string
	DisplayName string
	// Aliases are other values tenants and outlets store for the same use case.
	Aliases []string
	// Outlet: accepted as an outlet use_case (KnownUseCases).
	Outlet bool
	// Services receive outlet sync events (ApplicableServices).
	Services []string
	// Apps are the OAuth clients whose /{slug}/auth/callback a tenant with this use case gets.
	// An app listed under no use case is a platform app every tenant uses (auth-ui, treasury-ui).
	Apps []string
	// TrialPlan is the subscriptions-api plan a self-signup trial starts on; empty means STARTER.
	TrialPlan string
	Features  []string
	// Nomenclature: catalog, item and category labels.
	Catalog, Item, Category string
}

// App groups shared by several use cases.
var (
	posApps        = []string{"pos-ui", "inventory-ui"}
	storefrontApps = []string{"pos-ui", "inventory-ui", "ordering-ui", "logistics-ui", "rider-app"}
	posServices    = []string{"pos-api", "ordering-backend", "inventory-api"}
)

// Catalogue lists every use case. Keep subscriptions-api plan use_case values and the auth-ui
// signup choices in line with these codes.
var Catalogue = []Definition{
	{Code: "hospitality", DisplayName: "Hospitality", Outlet: true,
		Aliases:  []string{"food_delivery", "hotel", "restaurant", "bar", "cafe"},
		Services: posServices, Apps: storefrontApps, TrialPlan: "POWERSUITE_HOSP_BASIC",
		Features: []string{"menu_management", "table_ordering", "kitchen_display", "reservations"},
		Catalog:  "Menu", Item: "Dish", Category: "Course"},
	{Code: "retail", DisplayName: "Retail", Outlet: true,
		Aliases:  []string{"grocery", "e_commerce", "ecommerce", "hardware", "agrovet"},
		Services: posServices, Apps: storefrontApps, TrialPlan: "POWERSUITE_DUKA_BASIC",
		Features: []string{"inventory_management", "barcoding", "pos_checkout", "ecommerce_sync"},
		Catalog:  "Catalog", Item: "Product", Category: "Department"},
	{Code: "quick_service", DisplayName: "Quick Service", Outlet: true,
		Services: posServices, Apps: storefrontApps, TrialPlan: "POWERSUITE_HOSP_BASIC",
		Features: []string{"kiosk_ordering", "fast_checkout", "inventory_tracking"},
		Catalog:  "Menu", Item: "Item", Category: "Category"},
	// The DAWA family was retired 2026-08-29; a pharmacy or chemist starts on hospital-service's
	// AFYA_CHEMIST tier (facility_type chemist comes from the plan's own metadata).
	{Code: "pharmacy", DisplayName: "Pharmacy", Outlet: true, Aliases: []string{"chemist"},
		Services: []string{"pos-api", "inventory-api"}, Apps: append([]string{"hospital-ui"}, posApps...),
		TrialPlan: "AFYA_CHEMIST",
		Features:  []string{"prescription_management", "controlled_substances", "inventory_management"},
		Catalog:   "Formulary", Item: "Medicine", Category: "Drug Class"},
	{Code: "services", DisplayName: "Services", Outlet: true,
		Services: []string{"pos-api", "inventory-api"}, Apps: posApps, TrialPlan: "POWERSUITE_HOSP_BASIC",
		Features: []string{"appointment_scheduling", "service_catalog", "staff_commissions"},
		Catalog:  "Services", Item: "Service", Category: "Service Type"},
	{Code: "hospital", DisplayName: "Hospital / Clinic", Outlet: true,
		Services: []string{"hospital-api"}, Apps: []string{"hospital-ui"},
		Features: []string{"patient_records", "consultation", "laboratory", "pharmacy_dispensing", "billing"},
		Catalog:  "Formulary", Item: "Drug", Category: "Department"},
	{Code: "warehouse", DisplayName: "Warehouse", Outlet: true, Aliases: []string{"warehousing"},
		Services: []string{"inventory-api"}, Apps: []string{"inventory-ui"}, TrialPlan: "POWERSUITE_DUKA_BASIC",
		Features: []string{"stock_management", "lot_tracking", "put_away", "pick_pack"},
		Catalog:  "Inventory", Item: "SKU", Category: "Category"},
	{Code: "logistics", DisplayName: "Logistics", Outlet: true, Aliases: []string{"delivery", "courier", "distribution"},
		Services: []string{"logistics-api"}, Apps: []string{"logistics-ui", "rider-app"},
		Features: []string{"dispatch_management", "rider_tracking", "route_optimization", "delivery_tasks"},
		Catalog:  "Services", Item: "Delivery Task", Category: "Zone"},
	{Code: "commercial_weighing", DisplayName: "Commercial Weighing", Outlet: true, Aliases: []string{"weighbridge", "weighing"},
		Services: []string{"truload"}, Apps: []string{"truload-ui"},
		Features: []string{"weighbridge_operations", "commercial_transactions", "weight_certificates", "fleet_throughput"},
		Catalog:  "Transactions", Item: "Weighing Session", Category: "Commodity"},
	{Code: "axle_load_enforcement", DisplayName: "Axle Load Enforcement", Outlet: true,
		Services: []string{"truload"}, Apps: []string{"truload-ui"},
		Features: []string{"overload_detection", "enforcement_cases", "prosecution", "vehicle_inspection"},
		Catalog:  "Cases", Item: "Weighing", Category: "Offence Type"},
	{Code: "manufacturing", DisplayName: "Manufacturing", Outlet: true,
		Services: []string{"inventory-api"}, Apps: []string{"inventory-ui"},
		Features: []string{"bill_of_materials", "production_batches", "raw_material_consumption", "quality_control"},
		Catalog:  "Bill of Materials", Item: "Product", Category: "Product Line"},
	// ISP and hotspot providers onboard onto isp-billing. The signup form folds both into
	// use_case "isp" (the hotspot distinction is kept in tenant metadata.isp_business_type).
	{Code: "isp", DisplayName: "ISP / Hotspot", Outlet: true, Aliases: []string{"pppoe", "wifi"},
		Services: []string{"isp-billing"}, Apps: []string{"isp-billing-ui"}, TrialPlan: "ISP_BILLING_STARTER",
		Features: ispFeatures, Catalog: "Packages", Item: "Plan", Category: "Service Type"},
	{Code: "hotspot", DisplayName: "ISP / Hotspot", Outlet: true,
		Services: []string{"isp-billing"}, Apps: []string{"isp-billing-ui"}, TrialPlan: "ISP_BILLING_STARTER",
		Features: ispFeatures, Catalog: "Packages", Item: "Plan", Category: "Service Type"},
	// Maskani property platform: each estate or building is an outlet of the property tenant.
	{Code: "property", DisplayName: "Property Management", Outlet: true, Aliases: []string{"estate", "real_estate"},
		Services: []string{"maskani-api"}, Apps: []string{"maskani-ui"},
		Features: []string{"unit_register", "service_charge_billing", "unit_sales", "visitor_management", "work_orders"},
		Catalog:  "Charges", Item: "Unit", Category: "Block"},
	// Hadia gift registry: registry owners and their guests on hadiafrica.com.
	{Code: "gift_registry", DisplayName: "Gift Registry", Outlet: true, Aliases: []string{"registry"},
		Services: []string{"hadia-api"}, Apps: []string{"hadia-ui"},
		Features: []string{"registries", "guest_contributions", "escrow_wallets", "gift_pages"},
		Catalog:  "Registries", Item: "Gift", Category: "Occasion"},
	// Tenant-level only (never an outlet): library-service, and MarketFlow's FBO niche, whose
	// app (marketflow-ui) is a platform app.
	{Code: "library", DisplayName: "Library", Apps: []string{"library-ui"}, TrialPlan: "LIBRARY_STARTER",
		Features: []string{"basic_operations"}, Catalog: "Catalog", Item: "Title", Category: "Collection"},
	// fbo trials on MarketFlow's free tier (2026-11-11): the old "STARTER" fallback names no plan,
	// so a new Forever Business Owner got no subscription and MarketFlow refused every request.
	{Code: "fbo", DisplayName: "Forever Business Owner", TrialPlan: "MARKETFLOW_STARTER",
		Features: []string{"basic_operations"}, Catalog: "Catalog", Item: "Item", Category: "Category"},
}

var ispFeatures = []string{"hotspot_management", "pppoe_management", "voucher_system", "customer_management", "router_management"}

// KnownUseCases is the authoritative list of valid outlet use_case values.
var KnownUseCases = func() []string {
	out := make([]string, 0, len(Catalogue))
	for _, d := range Catalogue {
		if d.Outlet {
			out = append(out, d.Code)
		}
	}
	return out
}()

// Lookup returns the definition for a code or alias (case-insensitive), or nil.
func Lookup(value string) *Definition {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return nil
	}
	for i := range Catalogue {
		d := &Catalogue[i]
		if d.Code == v {
			return d
		}
		for _, a := range d.Aliases {
			if a == v {
				return d
			}
		}
	}
	return nil
}

// Canonical returns the catalogue code for a code or alias, or the value unchanged.
func Canonical(value string) string {
	if d := Lookup(value); d != nil {
		return d.Code
	}
	return strings.ToLower(strings.TrimSpace(value))
}

// ApplicableServices returns which downstream services receive outlet sync events
// for a given use_case. Used in outlet responses and NATS event routing.
func ApplicableServices(useCase string) []string {
	if d := Lookup(useCase); d != nil && len(d.Services) > 0 {
		return append([]string(nil), d.Services...)
	}
	return []string{}
}

// TrialPlan returns the plan a self-signup trial for this use case starts on.
func TrialPlan(useCase string) string {
	if d := Lookup(useCase); d != nil && d.TrialPlan != "" {
		return d.TrialPlan
	}
	return "STARTER"
}

// IsValidUseCase reports whether useCase is a known, supported outlet use case.
func IsValidUseCase(useCase string) bool {
	for _, uc := range KnownUseCases {
		if uc == useCase {
			return true
		}
	}
	return false
}

// UseCasesForApp returns the use case codes whose tenants sign in to an app; empty for a
// platform app every tenant uses.
func UseCasesForApp(clientID string) []string {
	var out []string
	for _, d := range Catalogue {
		for _, a := range d.Apps {
			if a == clientID {
				out = append(out, d.Code)
				break
			}
		}
	}
	return out
}

// AppServes reports whether a tenant with these use cases signs in to the app. A platform app
// serves everyone, and so does every app for a tenant with no use cases (an older tenant), so
// nobody loses sign-in.
func AppServes(clientID string, tenantUseCases []string) bool {
	served := UseCasesForApp(clientID)
	if len(served) == 0 || len(tenantUseCases) == 0 {
		return true
	}
	for _, u := range tenantUseCases {
		code := Canonical(u)
		for _, s := range served {
			if s == code {
				return true
			}
		}
	}
	return false
}

// Service provides logic to resolve use-case specific behavior.
type Service struct{}

// NewService constructs a new UseCase service.
func NewService() *Service {
	return &Service{}
}

// ResolveConfig returns the configuration for a given use case.
func (s *Service) ResolveConfig(ctx context.Context, useCase string) *Config {
	applicable := ApplicableServices(useCase)
	if d := Lookup(useCase); d != nil && d.Outlet {
		code := d.Code
		if d.Code == "isp" || d.Code == "hotspot" {
			code = useCase // ISP and hotspot keep the value asked for
		}
		return &Config{
			UseCase:            code,
			DisplayName:        d.DisplayName,
			ApplicableServices: applicable,
			Features:           append([]string(nil), d.Features...),
			Settings: map[string]any{
				"catalog_nomenclature":  d.Catalog,
				"item_nomenclature":     d.Item,
				"category_nomenclature": d.Category,
			},
		}
	}
	return &Config{
		UseCase:            useCase,
		DisplayName:        "Default",
		ApplicableServices: applicable,
		Features:           []string{"basic_operations"},
		Settings: map[string]any{
			"catalog_nomenclature":  "Catalog",
			"item_nomenclature":     "Item",
			"category_nomenclature": "Category",
		},
	}
}

// MergeConfigs unions the features/applicable_services of several use cases into one
// Config — for a multi-use_case tenant (e.g. retail + logistics), "applicable" must
// mean "applicable to ANY of the tenant's selected use cases," not just the first one
// a caller happens to resolve. Settings/nomenclature come from the first (primary)
// use case, since those are presentation labels that can't meaningfully merge.
func (s *Service) MergeConfigs(ctx context.Context, useCases []string) *Config {
	if len(useCases) == 0 {
		return s.ResolveConfig(ctx, "other")
	}
	if len(useCases) == 1 {
		return s.ResolveConfig(ctx, useCases[0])
	}
	featureSet := map[string]struct{}{}
	serviceSet := map[string]struct{}{}
	displayNames := make([]string, 0, len(useCases))
	for _, uc := range useCases {
		cfg := s.ResolveConfig(ctx, uc)
		for _, f := range cfg.Features {
			featureSet[f] = struct{}{}
		}
		for _, svc := range cfg.ApplicableServices {
			serviceSet[svc] = struct{}{}
		}
		displayNames = append(displayNames, cfg.DisplayName)
	}
	return &Config{
		UseCase:            strings.Join(useCases, ","),
		DisplayName:        strings.Join(displayNames, " + "),
		Features:           setToSortedSlice(featureSet),
		ApplicableServices: setToSortedSlice(serviceSet),
		Settings:           s.ResolveConfig(ctx, useCases[0]).Settings,
	}
}

func setToSortedSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
