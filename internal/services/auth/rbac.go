package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/audit"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/auditlog"
	"github.com/bengobox/auth-api/internal/ent/passwordpolicy"
	"github.com/bengobox/auth-api/internal/ent/permission"
	"github.com/bengobox/auth-api/internal/ent/role"
	"github.com/bengobox/auth-api/internal/ent/rolepermission"
	"github.com/google/uuid"
)

// RBAC / security management errors.
var (
	// ErrRoleNotFound is returned when a role_code has no Role row.
	ErrRoleNotFound = errors.New("role not found")
	// ErrRoleExists is returned when creating a role whose code is taken.
	ErrRoleExists = errors.New("role already exists")
	// ErrSystemRoleImmutable is returned when editing/deleting a system role.
	ErrSystemRoleImmutable = errors.New("system role cannot be modified")
	// ErrWildcardRoleLocked is returned when editing permissions of a wildcard role.
	ErrWildcardRoleLocked = errors.New("permissions for this role are managed by the platform and cannot be edited")
)

// wildcardRoleCodes are all-permission roles whose permission set must never be
// edited via the admin API (mirrors cmd/seed wildcardRoles).
var wildcardRoleCodes = map[string]bool{
	"superuser":  true,
	"admin":      true,
	"superusers": true,
}

// IsWildcardRole reports whether the role resolves to all permissions and is
// therefore permission-locked in the admin UI.
func IsWildcardRole(code string) bool { return wildcardRoleCodes[code] }

// PermissionItem is a single permission in the catalogue.
type PermissionItem struct {
	ID       int    `json:"id"`
	Code     string `json:"code"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Service  string `json:"service"`
	Module   string `json:"module"`
}

// PermissionGroup groups permissions by service then module for the UI matrix.
type PermissionGroup struct {
	Service string           `json:"service"`
	Modules []PermissionList `json:"modules"`
}

// PermissionList groups permissions by module within a service.
type PermissionList struct {
	Module      string           `json:"module"`
	Permissions []PermissionItem `json:"permissions"`
}

// RoleSummary is a Role row plus computed counts for the list view.
type RoleSummary struct {
	RoleCode        string    `json:"role_code"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	IsSystem        bool      `json:"is_system"`
	IsWildcard      bool      `json:"is_wildcard"`
	Scope           string    `json:"scope"`
	PermissionCount int       `json:"permission_count"`
	MemberCount     int       `json:"member_count"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AuditLogItem is a serialisable audit-log row.
type AuditLogItem struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   string         `json:"resource_id,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	Context      map[string]any `json:"context,omitempty"`
	OccurredAt   time.Time      `json:"occurred_at"`
}

// PasswordPolicyData is the serialisable form of a password policy.
type PasswordPolicyData struct {
	MinLength       int  `json:"min_length"`
	RequireUpper    bool `json:"require_upper"`
	RequireLower    bool `json:"require_lower"`
	RequireDigit    bool `json:"require_digit"`
	RequireSymbol   bool `json:"require_symbol"`
	ExpiryDays      int  `json:"expiry_days"`
	ReuseBlockCount int  `json:"reuse_block_count"`
}

// ─── Permissions catalogue ───────────────────────────────────────────────────

// ListPermissionCatalogue returns all permissions grouped by service then module.
// Codes are split on "." as {service}.{module}.{action}.
func (s *Service) ListPermissionCatalogue(ctx context.Context) ([]PermissionGroup, error) {
	perms, err := s.entClient.Permission.Query().
		Order(ent.Asc(permission.FieldCode)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	// service -> module -> []PermissionItem (preserve insertion order)
	type modAcc struct {
		order []string
		byMod map[string][]PermissionItem
	}
	svcOrder := []string{}
	svcAcc := map[string]*modAcc{}
	for _, p := range perms {
		svc, module := splitPermissionCode(p.Code)
		acc, ok := svcAcc[svc]
		if !ok {
			acc = &modAcc{byMod: map[string][]PermissionItem{}}
			svcAcc[svc] = acc
			svcOrder = append(svcOrder, svc)
		}
		if _, ok := acc.byMod[module]; !ok {
			acc.order = append(acc.order, module)
		}
		acc.byMod[module] = append(acc.byMod[module], PermissionItem{
			ID:       p.ID,
			Code:     p.Code,
			Resource: p.Resource,
			Action:   p.Action,
			Service:  svc,
			Module:   module,
		})
	}
	sort.Strings(svcOrder)
	groups := make([]PermissionGroup, 0, len(svcOrder))
	for _, svc := range svcOrder {
		acc := svcAcc[svc]
		sort.Strings(acc.order)
		modules := make([]PermissionList, 0, len(acc.order))
		for _, m := range acc.order {
			modules = append(modules, PermissionList{Module: m, Permissions: acc.byMod[m]})
		}
		groups = append(groups, PermissionGroup{Service: svc, Modules: modules})
	}
	return groups, nil
}

// splitPermissionCode splits a "{service}.{module}.{action}" code into service
// and module. Codes with fewer parts fall back gracefully.
func splitPermissionCode(code string) (service, module string) {
	parts := strings.SplitN(code, ".", 3)
	switch len(parts) {
	case 3:
		return parts[0], parts[1]
	case 2:
		return parts[0], parts[1]
	default:
		return code, code
	}
}

// ─── Roles ───────────────────────────────────────────────────────────────────

// ListRolesWithCounts returns every Role row with its permission and member counts.
func (s *Service) ListRolesWithCounts(ctx context.Context) ([]RoleSummary, error) {
	roles, err := s.entClient.Role.Query().Order(ent.Asc(role.FieldRoleCode)).All(ctx)
	if err != nil {
		return nil, err
	}

	// permission_count per role_name from RolePermission.
	rps, err := s.entClient.RolePermission.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	permCount := map[string]int{}
	for _, rp := range rps {
		permCount[rp.RoleName]++
	}

	// member_count: memberships whose roles JSON array contains the code.
	memberships, err := s.entClient.TenantMembership.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	memberCount := map[string]int{}
	for _, m := range memberships {
		for _, r := range m.Roles {
			memberCount[r]++
		}
	}

	out := make([]RoleSummary, 0, len(roles))
	for _, r := range roles {
		desc := ""
		if r.Description != "" {
			desc = r.Description
		}
		pc := permCount[r.RoleCode]
		if wildcardRoleCodes[r.RoleCode] {
			// Wildcard roles resolve to all permissions at seed time.
			pc = len(permsAll(rps))
		}
		out = append(out, RoleSummary{
			RoleCode:        r.RoleCode,
			Name:            r.Name,
			Description:     desc,
			IsSystem:        r.IsSystem,
			IsWildcard:      wildcardRoleCodes[r.RoleCode],
			Scope:           r.Scope,
			PermissionCount: pc,
			MemberCount:     memberCount[r.RoleCode],
			CreatedAt:       r.CreatedAt,
			UpdatedAt:       r.UpdatedAt,
		})
	}
	return out, nil
}

// permsAll returns the distinct permission_ids assigned to ANY role; used as the
// effective permission count for wildcard roles (which are seeded to all perms).
func permsAll(rps []*ent.RolePermission) []int {
	seen := map[int]struct{}{}
	for _, rp := range rps {
		seen[rp.PermissionID] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// GetRole returns a single role summary by code.
func (s *Service) GetRole(ctx context.Context, code string) (*RoleSummary, error) {
	r, err := s.entClient.Role.Query().Where(role.RoleCodeEQ(code)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	pc, err := s.entClient.RolePermission.Query().Where(rolepermission.RoleNameEQ(code)).Count(ctx)
	if err != nil {
		return nil, err
	}
	mc := 0
	memberships, err := s.entClient.TenantMembership.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	for _, m := range memberships {
		for _, rn := range m.Roles {
			if rn == code {
				mc++
			}
		}
	}
	return &RoleSummary{
		RoleCode:        r.RoleCode,
		Name:            r.Name,
		Description:     r.Description,
		IsSystem:        r.IsSystem,
		IsWildcard:      wildcardRoleCodes[r.RoleCode],
		Scope:           r.Scope,
		PermissionCount: pc,
		MemberCount:     mc,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}, nil
}

// GetRolePermissions returns the permission codes assigned to a role.
func (s *Service) GetRolePermissions(ctx context.Context, code string) ([]string, error) {
	rps, err := s.entClient.RolePermission.Query().
		Where(rolepermission.RoleNameEQ(code)).
		WithPermission().
		All(ctx)
	if err != nil {
		return nil, err
	}
	codes := make([]string, 0, len(rps))
	for _, rp := range rps {
		if rp.Edges.Permission != nil {
			codes = append(codes, rp.Edges.Permission.Code)
		}
	}
	sort.Strings(codes)
	return codes, nil
}

// CreateRoleInput captures fields for a new custom role.
type CreateRoleInput struct {
	RoleCode    string
	Name        string
	Description string
	Scope       string
}

// CreateRole creates a custom, non-system role.
func (s *Service) CreateRole(ctx context.Context, in CreateRoleInput) (*ent.Role, error) {
	code := strings.TrimSpace(in.RoleCode)
	if code == "" {
		return nil, fmt.Errorf("role_code is required")
	}
	exists, err := s.entClient.Role.Query().Where(role.RoleCodeEQ(code)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrRoleExists
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = code
	}
	create := s.entClient.Role.Create().
		SetRoleCode(code).
		SetName(name).
		SetIsSystem(false)
	if in.Description != "" {
		create.SetDescription(in.Description)
	}
	if in.Scope != "" {
		create.SetScope(in.Scope)
	}
	r, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrRoleExists
		}
		return nil, err
	}
	return r, nil
}

// UpdateRoleInput captures editable role metadata.
type UpdateRoleInput struct {
	Name        *string
	Description *string
	Scope       *string
}

// UpdateRole edits a non-system role's metadata.
func (s *Service) UpdateRole(ctx context.Context, code string, in UpdateRoleInput) (*ent.Role, error) {
	r, err := s.entClient.Role.Query().Where(role.RoleCodeEQ(code)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	if r.IsSystem {
		return nil, ErrSystemRoleImmutable
	}
	upd := r.Update()
	if in.Name != nil {
		upd.SetName(*in.Name)
	}
	if in.Description != nil {
		upd.SetDescription(*in.Description)
	}
	if in.Scope != nil {
		upd.SetScope(*in.Scope)
	}
	return upd.Save(ctx)
}

// DeleteRole deletes a non-system role and its RolePermission rows.
func (s *Service) DeleteRole(ctx context.Context, code string) error {
	r, err := s.entClient.Role.Query().Where(role.RoleCodeEQ(code)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrRoleNotFound
		}
		return err
	}
	if r.IsSystem {
		return ErrSystemRoleImmutable
	}
	if _, err := s.entClient.RolePermission.Delete().
		Where(rolepermission.RoleNameEQ(code)).Exec(ctx); err != nil {
		return fmt.Errorf("delete role permissions: %w", err)
	}
	return s.entClient.Role.DeleteOne(r).Exec(ctx)
}

// SetRolePermissions reconciles the RolePermission rows for a role to exactly
// match the supplied permission codes. Wildcard roles are locked. Unknown codes
// are ignored. Returns the resulting permission codes.
func (s *Service) SetRolePermissions(ctx context.Context, code string, permissionCodes []string) ([]string, error) {
	if wildcardRoleCodes[code] {
		return nil, ErrWildcardRoleLocked
	}
	// Ensure the role exists (custom or system non-wildcard).
	if _, err := s.entClient.Role.Query().Where(role.RoleCodeEQ(code)).Only(ctx); err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}

	// Resolve desired codes -> permission IDs (drop unknown codes).
	desiredIDs := map[int]string{}
	if len(permissionCodes) > 0 {
		perms, err := s.entClient.Permission.Query().
			Where(permission.CodeIn(permissionCodes...)).
			All(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range perms {
			desiredIDs[p.ID] = p.Code
		}
	}

	// Current assignments.
	current, err := s.entClient.RolePermission.Query().
		Where(rolepermission.RoleNameEQ(code)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	currentIDs := map[int]int{} // permission_id -> rolepermission row id
	for _, rp := range current {
		currentIDs[rp.PermissionID] = rp.ID
	}

	// Add missing.
	for pid := range desiredIDs {
		if _, ok := currentIDs[pid]; ok {
			continue
		}
		if _, err := s.entClient.RolePermission.Create().
			SetRoleName(code).
			SetPermissionID(pid).
			Save(ctx); err != nil && !ent.IsConstraintError(err) {
			return nil, fmt.Errorf("add permission %d: %w", pid, err)
		}
	}
	// Remove extras.
	var toDelete []int
	for pid, rowID := range currentIDs {
		if _, ok := desiredIDs[pid]; !ok {
			toDelete = append(toDelete, rowID)
		}
	}
	if len(toDelete) > 0 {
		if _, err := s.entClient.RolePermission.Delete().
			Where(rolepermission.IDIn(toDelete...)).Exec(ctx); err != nil {
			return nil, fmt.Errorf("remove permissions: %w", err)
		}
	}

	out := make([]string, 0, len(desiredIDs))
	for _, c := range desiredIDs {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

// ─── Audit logs ───────────────────────────────────────────────────────────────

// WriteAuditLog persists an audit entry (thin wrapper over the audit logger).
func (s *Service) WriteAuditLog(ctx context.Context, e audit.Entry) {
	if s.auditor == nil {
		return
	}
	s.auditor.Record(ctx, e)
}

// AuditQuery filters an audit-log listing.
type AuditQuery struct {
	ResourceType string
	Action       string
	ActorUserID  *uuid.UUID
	TenantID     *uuid.UUID
	From         *time.Time
	To           *time.Time
	Limit        int
	Offset       int
}

// QueryAuditLogs returns a filtered, paginated slice of audit logs (most recent
// first) plus the total count for pagination.
func (s *Service) QueryAuditLogs(ctx context.Context, q AuditQuery) ([]AuditLogItem, int, error) {
	query := s.entClient.AuditLog.Query()
	if q.ResourceType != "" {
		query = query.Where(auditlog.ResourceTypeEQ(q.ResourceType))
	}
	if q.Action != "" {
		query = query.Where(auditlog.ActionContainsFold(q.Action))
	}
	if q.ActorUserID != nil {
		query = query.Where(auditlog.UserIDEQ(*q.ActorUserID))
	}
	if q.TenantID != nil {
		query = query.Where(auditlog.TenantIDEQ(*q.TenantID))
	}
	if q.From != nil {
		query = query.Where(auditlog.OccurredAtGTE(*q.From))
	}
	if q.To != nil {
		query = query.Where(auditlog.OccurredAtLTE(*q.To))
	}

	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := query.
		Order(ent.Desc(auditlog.FieldOccurredAt)).
		Limit(limit).
		Offset(q.Offset).
		All(ctx)
	if err != nil {
		return nil, 0, err
	}
	out := make([]AuditLogItem, 0, len(rows))
	for _, a := range rows {
		item := AuditLogItem{
			ID:           a.ID.String(),
			Action:       a.Action,
			ResourceType: a.ResourceType,
			ResourceID:   a.ResourceID,
			IPAddress:    a.IPAddress,
			UserAgent:    a.UserAgent,
			Context:      a.Context,
			OccurredAt:   a.OccurredAt,
		}
		if a.TenantID != uuid.Nil {
			item.TenantID = a.TenantID.String()
		}
		if a.UserID != uuid.Nil {
			item.UserID = a.UserID.String()
		}
		out = append(out, item)
	}
	return out, total, nil
}

// ─── Password policy ──────────────────────────────────────────────────────────

// GetPasswordPolicy returns the platform-wide password policy, falling back to
// hard defaults if no row exists yet.
func (s *Service) GetPasswordPolicy(ctx context.Context) (PasswordPolicyData, error) {
	p, err := s.entClient.PasswordPolicy.Query().
		Where(passwordpolicy.TenantIDIsNil()).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return defaultPasswordPolicy(), nil
		}
		return PasswordPolicyData{}, err
	}
	return PasswordPolicyData{
		MinLength:       p.MinLength,
		RequireUpper:    p.RequireUpper,
		RequireLower:    p.RequireLower,
		RequireDigit:    p.RequireDigit,
		RequireSymbol:   p.RequireSymbol,
		ExpiryDays:      p.ExpiryDays,
		ReuseBlockCount: p.ReuseBlockCount,
	}, nil
}

// SetPasswordPolicy upserts the platform-wide password policy.
func (s *Service) SetPasswordPolicy(ctx context.Context, in PasswordPolicyData) (PasswordPolicyData, error) {
	if in.MinLength < 4 {
		in.MinLength = 4
	}
	existing, err := s.entClient.PasswordPolicy.Query().
		Where(passwordpolicy.TenantIDIsNil()).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return PasswordPolicyData{}, err
	}
	if existing != nil {
		_, err = existing.Update().
			SetMinLength(in.MinLength).
			SetRequireUpper(in.RequireUpper).
			SetRequireLower(in.RequireLower).
			SetRequireDigit(in.RequireDigit).
			SetRequireSymbol(in.RequireSymbol).
			SetExpiryDays(in.ExpiryDays).
			SetReuseBlockCount(in.ReuseBlockCount).
			Save(ctx)
		if err != nil {
			return PasswordPolicyData{}, err
		}
		return in, nil
	}
	_, err = s.entClient.PasswordPolicy.Create().
		SetMinLength(in.MinLength).
		SetRequireUpper(in.RequireUpper).
		SetRequireLower(in.RequireLower).
		SetRequireDigit(in.RequireDigit).
		SetRequireSymbol(in.RequireSymbol).
		SetExpiryDays(in.ExpiryDays).
		SetReuseBlockCount(in.ReuseBlockCount).
		Save(ctx)
	if err != nil {
		return PasswordPolicyData{}, err
	}
	return in, nil
}

func defaultPasswordPolicy() PasswordPolicyData {
	return PasswordPolicyData{
		MinLength:    8,
		RequireUpper: true,
		RequireLower: true,
		RequireDigit: true,
	}
}

// ValidatePassword checks a candidate password against the configured platform
// password policy. It is applied on the NEXT password set/change/reset only —
// never retroactively. Returns ErrPasswordTooWeak on failure.
func (s *Service) ValidatePassword(ctx context.Context, candidate string) error {
	policy, err := s.GetPasswordPolicy(ctx)
	if err != nil {
		// Fail open to the legacy heuristic rather than blocking all changes
		// if the policy row cannot be read.
		return s.validatePassword(candidate)
	}
	if len(candidate) < policy.MinLength {
		return ErrPasswordTooWeak
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, ch := range candidate {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		case !isAlphanumeric(ch):
			hasSymbol = true
		}
	}
	if policy.RequireUpper && !hasUpper {
		return ErrPasswordTooWeak
	}
	if policy.RequireLower && !hasLower {
		return ErrPasswordTooWeak
	}
	if policy.RequireDigit && !hasDigit {
		return ErrPasswordTooWeak
	}
	if policy.RequireSymbol && !hasSymbol {
		return ErrPasswordTooWeak
	}
	return nil
}
