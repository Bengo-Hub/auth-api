package main

import (
	"context"
	"log"
	"strings"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/passwordpolicy"
	"github.com/bengobox/auth-api/internal/ent/role"
)

// wildcardRoles are the all-permissions roles whose permission set must never be
// edited via the admin API (they resolve to every permission at seed time).
var wildcardRoles = map[string]bool{
	"superuser":  true,
	"admin":      true,
	"superusers": true,
}

// platformSystemRoles are first-class platform roles (non-ERP, non-service).
var platformSystemRoles = map[string]bool{
	"superuser": true,
	"admin":     true,
	"developer": true,
	"manager":   true,
	"staff":     true,
	"member":    true,
	"viewer":    true,
	"customer":  true,
}

// erpRoles map 1:1 to erp-api Django groups (scope = erp).
var erpRoles = map[string]bool{
	"superusers":          true,
	"ceo":                 true,
	"hr_manager":          true,
	"hr_assistant":        true,
	"ict_manager":         true,
	"ict_officer":         true,
	"operations_manager":  true,
	"finance_manager":     true,
	"procurement_manager": true,
	"sales_manager":       true,
	"secretary":           true,
}

// posRoles are POS/hospitality staff roles (scope = pos).
var posRoles = map[string]bool{
	"cashier":      true,
	"waiter":       true,
	"kitchen":      true,
	"bar":          true,
	"barista":      true,
	"receptionist": true,
	"pharmacist":   true,
}

// logisticsRoles are delivery/field roles (scope = logistics).
var logisticsRoles = map[string]bool{
	"rider":                true,
	"driver":               true,
	"delivery_coordinator": true,
	"technician":           true,
}

// ispRoles are ISP-billing provider/subscriber roles (scope = isp). isp-billing
// maps these global role names to its own fine-grained isp.*.* RBAC locally.
var ispRoles = map[string]bool{
	"isp_admin":      true,
	"isp_technician": true,
	"isp_customer":   true,
	"isp_viewer":     true,
}

// roleScope infers a coarse scope grouping for a role code.
func roleScope(code string) string {
	switch {
	case erpRoles[code]:
		return "erp"
	case posRoles[code]:
		return "pos"
	case logisticsRoles[code]:
		return "logistics"
	case ispRoles[code]:
		return "isp"
	case platformSystemRoles[code]:
		return "platform"
	default:
		return "platform"
	}
}

// roleDisplayName turns a snake_case role code into a Title Case display name.
func roleDisplayName(code string) string {
	parts := strings.Split(code, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

// seedRolesCatalogue upserts a metadata-only Role row for every role defined in
// rolePerms. The Role entity is DECOUPLED from RolePermission — the join is by
// value (role_code == role_name). All seeded roles are marked is_system=true so
// they cannot be edited/deleted via the admin API (only custom, admin-created
// roles are mutable). Idempotent.
func seedRolesCatalogue(ctx context.Context, client *ent.Client) error {
	log.Println("Seeding role catalogue (metadata-only Role rows)...")
	for code := range rolePerms {
		scope := roleScope(code)
		name := roleDisplayName(code)
		existing, err := client.Role.Query().Where(role.RoleCodeEQ(code)).Only(ctx)
		if err == nil && existing != nil {
			// Keep metadata fresh but preserve is_system invariant.
			_, uErr := existing.Update().
				SetName(name).
				SetScope(scope).
				SetIsSystem(true).
				Save(ctx)
			if uErr != nil {
				log.Printf("  ⚠️  update role %s: %v", code, uErr)
			}
			continue
		}
		if !ent.IsNotFound(err) && err != nil {
			log.Printf("  ⚠️  query role %s: %v", code, err)
			continue
		}
		_, cErr := client.Role.Create().
			SetRoleCode(code).
			SetName(name).
			SetScope(scope).
			SetIsSystem(true).
			Save(ctx)
		if cErr != nil {
			log.Printf("  ⚠️  create role %s: %v", code, cErr)
			continue
		}
		log.Printf("  ✓ Role catalogue entry: %s (scope=%s)", code, scope)
	}
	return nil
}

// seedDefaultPasswordPolicy ensures a single platform-wide PasswordPolicy row
// (tenant_id = NULL) exists. Idempotent — never overwrites an admin-tuned policy.
func seedDefaultPasswordPolicy(ctx context.Context, client *ent.Client) error {
	exists, err := client.PasswordPolicy.Query().
		Where(passwordpolicy.TenantIDIsNil()).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		log.Println("Default password policy already present; skipping.")
		return nil
	}
	_, err = client.PasswordPolicy.Create().
		SetMinLength(8).
		SetRequireUpper(true).
		SetRequireLower(true).
		SetRequireDigit(true).
		SetRequireSymbol(false).
		SetExpiryDays(0).
		SetReuseBlockCount(0).
		Save(ctx)
	if err != nil {
		return err
	}
	log.Println("  ✓ Seeded default platform password policy")
	return nil
}
