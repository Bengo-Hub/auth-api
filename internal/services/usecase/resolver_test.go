package usecase

import (
	"reflect"
	"testing"
)

// The trial plan each signup value got from auth.defaultTrialPlan before it moved here.
func TestTrialPlanMatchesTheFormerSwitch(t *testing.T) {
	want := map[string]string{
		"isp": "ISP_BILLING_STARTER", "hotspot": "ISP_BILLING_STARTER", "pppoe": "ISP_BILLING_STARTER",
		"library":     "LIBRARY_STARTER",
		"hospitality": "POWERSUITE_HOSP_BASIC", "quick_service": "POWERSUITE_HOSP_BASIC", "services": "POWERSUITE_HOSP_BASIC",
		"food_delivery": "POWERSUITE_HOSP_BASIC", "hotel": "POWERSUITE_HOSP_BASIC", "restaurant": "POWERSUITE_HOSP_BASIC",
		"bar": "POWERSUITE_HOSP_BASIC", "cafe": "POWERSUITE_HOSP_BASIC",
		"retail": "POWERSUITE_DUKA_BASIC", "grocery": "POWERSUITE_DUKA_BASIC", "warehouse": "POWERSUITE_DUKA_BASIC",
		"warehousing": "POWERSUITE_DUKA_BASIC", "e_commerce": "POWERSUITE_DUKA_BASIC", "ecommerce": "POWERSUITE_DUKA_BASIC",
		"hardware": "POWERSUITE_DUKA_BASIC", "agrovet": "POWERSUITE_DUKA_BASIC",
		"pharmacy": "AFYA_CHEMIST", "chemist": "AFYA_CHEMIST",
		"logistics": "STARTER", "property": "STARTER", "gift_registry": "STARTER", "unknown": "STARTER", "": "STARTER",
	}
	for in, plan := range want {
		if got := TrialPlan(in); got != plan {
			t.Errorf("TrialPlan(%q) = %q, want %q", in, got, plan)
		}
	}
}

// Outlet event routing for the values the former switch knew.
func TestApplicableServicesMatchesTheFormerSwitch(t *testing.T) {
	want := map[string][]string{
		"retail":        {"pos-api", "ordering-backend", "inventory-api"},
		"pharmacy":      {"pos-api", "inventory-api"},
		"hospital":      {"hospital-api"},
		"manufacturing": {"inventory-api"},
		"courier":       {"logistics-api"},
		"weighbridge":   {"truload"},
		"wifi":          {"isp-billing"},
		"real_estate":   {"maskani-api"},
		"gift_registry": {"hadia-api"},
		"nothing":       {},
	}
	for in, services := range want {
		if got := ApplicableServices(in); !reflect.DeepEqual(got, services) {
			t.Errorf("ApplicableServices(%q) = %v, want %v", in, got, services)
		}
	}
}

func TestKnownUseCasesAreOutletCodesOnly(t *testing.T) {
	for _, uc := range []string{"library", "fbo", "grocery"} {
		if IsValidUseCase(uc) {
			t.Errorf("%q must not be accepted as an outlet use case", uc)
		}
	}
	for _, uc := range []string{"retail", "property", "gift_registry", "hotspot"} {
		if !IsValidUseCase(uc) {
			t.Errorf("%q must be accepted as an outlet use case", uc)
		}
	}
}

func TestAppServes(t *testing.T) {
	if !AppServes("treasury-ui", []string{"property"}) {
		t.Error("a platform app serves every tenant")
	}
	if !AppServes("pos-ui", []string{"e_commerce"}) {
		t.Error("an alias reaches its use case's apps")
	}
	if AppServes("maskani-ui", []string{"retail"}) {
		t.Error("a retail tenant has no maskani-ui callbacks")
	}
	if !AppServes("maskani-ui", nil) {
		t.Error("a tenant without use cases keeps every app")
	}
}
