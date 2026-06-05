package usecase

import (
	"context"
)

// Config represents the use-case specific configuration.
type Config struct {
	UseCase            string         `json:"use_case"`
	Features           []string       `json:"features"`
	Settings           map[string]any `json:"settings"`
	DisplayName        string         `json:"display_name"`
	ApplicableServices []string       `json:"applicable_services"`
}

// KnownUseCases is the authoritative list of valid outlet use_case values.
// Each value maps to specific downstream services via ApplicableServices().
var KnownUseCases = []string{
	"hospitality",
	"retail",
	"quick_service",
	"pharmacy",
	"services",
	"warehouse",
	"logistics",
	"commercial_weighing",
	"axle_load_enforcement",
	"manufacturing",
}

// ApplicableServices returns which downstream services receive outlet sync events
// for a given use_case. Used in outlet responses and NATS event routing.
func ApplicableServices(useCase string) []string {
	switch useCase {
	case "hospitality", "retail", "quick_service":
		return []string{"pos-api", "ordering-backend", "inventory-api"}
	case "pharmacy", "services":
		return []string{"pos-api", "inventory-api"}
	case "warehouse", "manufacturing":
		return []string{"inventory-api"}
	case "logistics":
		return []string{"logistics-api"}
	case "commercial_weighing", "axle_load_enforcement":
		return []string{"truload"}
	default:
		return []string{}
	}
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

// Service provides logic to resolve use-case specific behavior.
type Service struct{}

// NewService constructs a new UseCase service.
func NewService() *Service {
	return &Service{}
}

// ResolveConfig returns the configuration for a given use case.
func (s *Service) ResolveConfig(ctx context.Context, useCase string) *Config {
	applicable := ApplicableServices(useCase)
	switch useCase {
	case "hospitality":
		return &Config{
			UseCase:            "hospitality",
			DisplayName:        "Hospitality",
			ApplicableServices: applicable,
			Features:           []string{"menu_management", "table_ordering", "kitchen_display", "reservations"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Menu",
				"item_nomenclature":     "Dish",
				"category_nomenclature": "Course",
			},
		}
	case "retail":
		return &Config{
			UseCase:            "retail",
			DisplayName:        "Retail",
			ApplicableServices: applicable,
			Features:           []string{"inventory_management", "barcoding", "pos_checkout", "ecommerce_sync"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Catalog",
				"item_nomenclature":     "Product",
				"category_nomenclature": "Department",
			},
		}
	case "quick_service":
		return &Config{
			UseCase:            "quick_service",
			DisplayName:        "Quick Service",
			ApplicableServices: applicable,
			Features:           []string{"kiosk_ordering", "fast_checkout", "inventory_tracking"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Menu",
				"item_nomenclature":     "Item",
				"category_nomenclature": "Category",
			},
		}
	case "pharmacy":
		return &Config{
			UseCase:            "pharmacy",
			DisplayName:        "Pharmacy",
			ApplicableServices: applicable,
			Features:           []string{"prescription_management", "controlled_substances", "inventory_management"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Formulary",
				"item_nomenclature":     "Medicine",
				"category_nomenclature": "Drug Class",
			},
		}
	case "services":
		return &Config{
			UseCase:            "services",
			DisplayName:        "Services",
			ApplicableServices: applicable,
			Features:           []string{"appointment_scheduling", "service_catalog", "staff_commissions"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Services",
				"item_nomenclature":     "Service",
				"category_nomenclature": "Service Type",
			},
		}
	case "warehouse":
		return &Config{
			UseCase:            "warehouse",
			DisplayName:        "Warehouse",
			ApplicableServices: applicable,
			Features:           []string{"stock_management", "lot_tracking", "put_away", "pick_pack"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Inventory",
				"item_nomenclature":     "SKU",
				"category_nomenclature": "Category",
			},
		}
	case "logistics":
		return &Config{
			UseCase:            "logistics",
			DisplayName:        "Logistics",
			ApplicableServices: applicable,
			Features:           []string{"dispatch_management", "rider_tracking", "route_optimization", "delivery_tasks"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Services",
				"item_nomenclature":     "Delivery Task",
				"category_nomenclature": "Zone",
			},
		}
	case "commercial_weighing":
		return &Config{
			UseCase:            "commercial_weighing",
			DisplayName:        "Commercial Weighing",
			ApplicableServices: applicable,
			Features:           []string{"weighbridge_operations", "commercial_transactions", "weight_certificates", "fleet_throughput"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Transactions",
				"item_nomenclature":     "Weighing Session",
				"category_nomenclature": "Commodity",
			},
		}
	case "axle_load_enforcement":
		return &Config{
			UseCase:            "axle_load_enforcement",
			DisplayName:        "Axle Load Enforcement",
			ApplicableServices: applicable,
			Features:           []string{"overload_detection", "enforcement_cases", "prosecution", "vehicle_inspection"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Cases",
				"item_nomenclature":     "Weighing",
				"category_nomenclature": "Offence Type",
			},
		}
	case "manufacturing":
		return &Config{
			UseCase:            "manufacturing",
			DisplayName:        "Manufacturing",
			ApplicableServices: applicable,
			Features:           []string{"bill_of_materials", "production_batches", "raw_material_consumption", "quality_control"},
			Settings: map[string]any{
				"catalog_nomenclature":  "Bill of Materials",
				"item_nomenclature":     "Product",
				"category_nomenclature": "Product Line",
			},
		}
	default:
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
}
