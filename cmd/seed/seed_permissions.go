package main

import (
	"context"
	"log"
	"strings"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/permission"
	"github.com/bengobox/auth-api/internal/ent/rolepermission"
)

// servicePerms lists all permissions in {service}.{module}.{action} format.
// NOTE: pos.*.* permissions are NOT seeded here.
// Per Trinity Authorization Pattern: pos-service owns its own fine-grained RBAC
// (POSRoleV2 + POSPermission tables). Frontends call pos-api GET /{tenant}/pos/auth/me
// after SSO to get service-level roles and permissions. auth-api only issues the
// global JWT roles (admin, manager, cashier, etc.) — pos-api maps those to local POS roles.
var servicePerms = map[string][]string{
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
		// Layer-1 RBAC / security administration (auth-ui platform pages).
		"auth.roles.manage",
		"auth.audit.view",
		"auth.security.manage",
		// Platform-only modules that previously had no permission code at all
		// (enforcement is via is_platform_owner; these exist so the Permissions
		// catalogue page reflects every platform surface, and so a future
		// permission-based check has a code to check against).
		"auth.clients.manage",
		"auth.integrations.manage",
		"auth.entitlements.manage",
		"auth.backups.manage",
		"auth.apps.manage",
		"auth.apikeys.manage",
	},
}

// rolePerms maps each role name to its allowed permission codes.
// superuser and admin receive all permissions (empty slice = all).
var rolePerms = map[string][]string{
	"superuser": {}, // all permissions (populated at seed time)
	"admin":     {}, // all permissions (populated at seed time)
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
	// developer: Developer Portal access (apps/API keys/OAuth clients) without any
	// admin/billing/team-management access. Same baseline as "member" — App/APIKey
	// management itself is gated by tenant membership, not a permission code (see
	// AppHandler.CreateApp), so there's no auth.apps.* permission to grant yet; this
	// role exists so a tenant admin can hand out portal access as its own named tier
	// instead of granting "admin" wholesale.
	"developer": {
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
	// barista — hospitality coffee-bar staff (café). Takes orders, runs the till, and prepares
	// drinks. Like the other POS staff roles, pos.*.* permissions are owned by pos-api's POSRoleV2
	// table — auth-api only issues the global role name + auth.* self-service permissions here.
	"barista": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
	},
	// accountant — finance/back-office role. Manages inventory, purchases, and treasury subject to
	// the tenant's subscription-allowed features and limits. Treasury's fine-grained permissions are
	// resolved locally by treasury-api (its own "accountant" role via mapGlobalRoleToTreasuryRole);
	// inventory's are resolved by inventory-api ("accountant" role). auth-api seeds the inventory.*
	// permissions it owns here (so GET /me exposes them for nav guards), plus ordering read access
	// for reconciliation and auth.* self-service.
	"accountant": {
		// Inventory (auth-api owns inventory.* permission seeding for global roles)
		"inventory.items.view", "inventory.items.change",
		"inventory.categories.view",
		"inventory.warehouses.view",
		"inventory.stock.view", "inventory.stock.change", "inventory.stock.manage",
		"inventory.recipes.view",
		// Ordering visibility for sales reconciliation/reporting
		"ordering.orders.view", "ordering.analytics.view",
		// Auth self-service
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// pharmacist — licensed pharmacy dispenser.
	// POS-specific permissions (pos.pharmacy.*) are managed by pos-api's POSRoleV2 table.
	"pharmacist": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
	},
	// doctor — hospital-service prescriber/clinician.
	// Fine-grained hospital.consultation.*/hospital.pharmacy.* perms are managed by
	// hospital-api's own RBAC module (Trinity Layer 2/3), not this global catalog.
	"doctor": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// nurse — hospital-service triage/ward/vitals staff.
	// Fine-grained hospital.triage.*/hospital.inpatient.* perms are hospital-api-owned.
	"nurse": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// records_clerk — hospital-service reception/records/registration staff.
	// Fine-grained hospital.records.* perms are hospital-api-owned.
	"records_clerk": {
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
	// ─────────────────────────────────────────────────────────────────────────
	// ISP-billing service roles (isp-billing decentralized to SSO).
	// Platform-owner + ISP-provider admins log in via auth-api; the isp-billing
	// service (ispbilling.codevertexafrica.com UI, ispbillingapi. API) maps
	// these global role names to its own fine-grained isp.*.* RBAC locally. Per the
	// Trinity Authorization Pattern, auth-api ONLY seeds the global role names + the
	// auth.* self-service (and sensible cross-service read) permissions it owns here.
	//
	// isp_admin — ISP provider administrator. Manages the provider's users + full
	// self-service; isp.*.* (subscribers, plans, routers, billing) resolved by isp-billing.
	"isp_admin": {
		"auth.users.view", "auth.users.add", "auth.users.change",
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view", "auth.notifications.manage",
	},
	// isp_technician — ISP field technician. Installs/services subscriber links.
	// Mirrors the existing cross-service "technician" role's logistics task/zone access
	// for field dispatch, plus auth.* self-service.
	"isp_technician": {
		"logistics.tasks.view", "logistics.tasks.change",
		"logistics.zones.view",
		"logistics.fleet.view",
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
	},
	// isp_customer — ISP subscriber (end-user/consumer). Self-service only.
	"isp_customer": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// isp_viewer — read-only ISP observer/reporting role. Self-service + notifications view.
	"isp_viewer": {
		"auth.profile.view",
		"auth.notifications.view",
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

	// ─────────────────────────────────────────────────────────────────────────
	// ERP service roles (erp-api: decomposed HR + internal-ops Django service).
	// These map 1:1 by name to the ERP's Django groups (core/security.py +
	// core/management/commands/seed_initial.py). The ERP JIT (authmanagement/sso.py
	// ERP_SERVICE_ROLES) assigns the matching Django group when it sees a global JWT
	// role with the same name, then ensure_rbac_provisioned syncs that group's
	// fine-grained model permissions. Per the Trinity Authorization Pattern, erp-api
	// owns its own fine-grained RBAC — so auth-api only seeds auth.* self-service
	// permissions here (the same as the other service roles above: cashier, waiter,
	// pharmacist, etc.). auth-api's job is purely to ISSUE these role names as global
	// roles; the ERP resolves the actual hrm/finance/procurement permissions locally.
	//
	// NOTE: "staff" and "receptionist" are ERP roles too, but already defined above
	// (ESS / front-office) — their existing auth.* perms are reused as-is; do not
	// re-add them here (duplicate map keys are a compile error).

	// superusers — ERP all-access group (Permission.objects.all()). Plural form is the
	// ERP's own group name (distinct from the platform "superuser"). All permissions.
	"superusers": {}, // all permissions (populated at seed time)
	// ceo — read-only across the entire ERP (READ_ALL: every view_ permission).
	"ceo": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// hr_manager — full manage on HR modules + approvals (view/add/change/delete).
	"hr_manager": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// hr_assistant — HR modules without delete (view/add/change).
	"hr_assistant": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// ict_manager — change/manage on technical/system modules (view/add/change).
	"ict_manager": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
		"auth.users.view", "auth.users.change",
	},
	// ict_officer — read-only on technical/system modules (view).
	"ict_officer": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// operations_manager — internal-ops management role (erp seed_initial group).
	"operations_manager": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
		"auth.users.view",
	},
	// finance_manager — finance management role (erp seed_initial group).
	"finance_manager": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// procurement_manager — procurement management role (erp seed_initial group).
	"procurement_manager": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// sales_manager — sales/CRM management role (erp seed_initial group).
	"sales_manager": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
	// secretary — front-office read-only (employees/attendance/leave + CRM view).
	"secretary": {
		"auth.profile.view", "auth.profile.change",
		"auth.preferences.view", "auth.preferences.change",
		"auth.notifications.view",
	},
}

// seedPermissions upserts all service permissions and returns a map of code → ID.
func seedPermissions(ctx context.Context, client *ent.Client) (map[string]int, error) {
	log.Println("Seeding permissions (Django-style: service.module.action)...")

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
	return permissionIDs, nil
}

// seedRoles upserts role-permission assignments for all defined roles.
func seedRoles(ctx context.Context, client *ent.Client, permissionIDs map[string]int) error {
	for roleName, codes := range rolePerms {
		resolvedCodes := resolvePermissions(roleName, codes, permissionIDs)
		for _, code := range resolvedCodes {
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
			_, err := client.RolePermission.Create().
				SetRoleName(roleName).
				SetPermissionID(pid).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating role_permission %s/%s: %v", roleName, code, err)
			}
		}
		log.Printf("  ✓ Role %s: %d permissions", roleName, len(resolvedCodes))
	}
	return nil
}

// resolvePermissions expands empty code slices (superuser/admin) to all known permissions.
func resolvePermissions(roleName string, codes []string, permissionIDs map[string]int) []string {
	if len(codes) == 0 {
		all := make([]string, 0, len(permissionIDs))
		for code := range permissionIDs {
			all = append(all, code)
		}
		return all
	}
	return codes
}
