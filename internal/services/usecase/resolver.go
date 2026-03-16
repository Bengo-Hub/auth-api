package usecase

import (
	"context"
)

// Config represents the use-case specific configuration.
type Config struct {
	UseCase     string         `json:"use_case"`
	Features    []string       `json:"features"`
	Settings    map[string]any `json:"settings"`
	DisplayName string         `json:"display_name"`
}

// Service provides logic to resolve use-case specific behavior.
type Service struct{}

// NewService constructs a new UseCase service.
func NewService() *Service {
	return &Service{}
}

// ResolveConfig returns the configuration for a given use case.
func (s *Service) ResolveConfig(ctx context.Context, useCase string) *Config {
	switch useCase {
	case "hospitality":
		return &Config{
			UseCase:     "hospitality",
			DisplayName: "Hospitality",
			Features:    []string{"menu_management", "table_ordering", "kitchen_display", "reservations"},
			Settings: map[string]any{
				"catalog_nomenclature": "Menu",
				"item_nomenclature":    "Dish",
				"category_nomenclature": "Course",
			},
		}
	case "retail":
		return &Config{
			UseCase:     "retail",
			DisplayName: "Retail",
			Features:    []string{"inventory_management", "barcoding", "pos_checkout", "ecommerce_sync"},
			Settings: map[string]any{
				"catalog_nomenclature": "Catalog",
				"item_nomenclature":    "Product",
				"category_nomenclature": "Department",
			},
		}
	case "quick_service":
		return &Config{
			UseCase:     "quick_service",
			DisplayName: "Quick Service",
			Features:    []string{"kiosk_ordering", "fast_checkout", "inventory_tracking"},
			Settings: map[string]any{
				"catalog_nomenclature": "Menu",
				"item_nomenclature":    "Item",
				"category_nomenclature": "Category",
			},
		}
	default:
		return &Config{
			UseCase:     useCase,
			DisplayName: "Default",
			Features:    []string{"basic_operations"},
			Settings: map[string]any{
				"catalog_nomenclature": "Catalog",
				"item_nomenclature":    "Item",
				"category_nomenclature": "Category",
			},
		}
	}
}
