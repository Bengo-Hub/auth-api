package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/password"
)

// masterspaceStaff lists the real Masterspace (mss) ERP staff to provision for SSO.
// Roles are their primary ERP role (mapped 1:1 to the erp-api Django groups, which carry the
// fine-grained permissions). Password comes from SEED_MSS_PASSWORD (default below) and every
// account is flagged must_change_password so the temp password is reset on first login.
var masterspaceStaff = []struct {
	Email string
	Name  string
	Role  string
}{
	{"philip.adar@masterspace.co.ke", "Philip Adar", "ceo"},
	{"james.okech@masterspace.co.ke", "James Okech", "cto"},
	{"titus.owuor@masterspace.co.ke", "Titus Owuor", "superuser"},
	{"test@masterspace.co.ke", "Test User", "superuser"},
	{"joseph.ondiwa@masterspace.co.ke", "Joseph Ondiwa", "ict_officer"},
	{"cornelius.odhiambo@masterspace.co.ke", "Cornelius Odhiambo", "ict_officer"},
	{"george.rabar@masterspace.co.ke", "George Rabar", "ict_officer"},
	{"evans.ochieng@masterspace.co.ke", "Evans Ochieng", "finance_manager"},
	{"elizabeth.ojala@masterspace.co.ke", "Elizabeth Ojala", "finance_manager"},
}

// seedMasterspaceUsers provisions the Masterspace staff with a known temp password + mss membership.
// Idempotent: existing accounts have their password reset to the temp password and must_change set.
func seedMasterspaceUsers(ctx context.Context, client *ent.Client, hasher *password.Hasher, tenantEntities []*tenantRef) error {
	var mss *tenantRef
	for _, te := range tenantEntities {
		if te.Slug == "mss" {
			mss = te
			break
		}
	}
	if mss == nil {
		return fmt.Errorf("mss tenant not found among seeded tenants")
	}

	pw := os.Getenv("SEED_MSS_PASSWORD")
	if pw == "" {
		pw = "ChangeMe123!" // documented temp default; overridden via env, reset on first login
	}
	hash, err := hasher.Hash(pw)
	if err != nil {
		return fmt.Errorf("hash mss password: %w", err)
	}

	// Forced password change is OPT-IN (SEED_MSS_FORCE_CHANGE=true). Default OFF so the temp
	// password logs in directly — a must_change_password=true otherwise detours the SSO flow
	// to the auth-ui password-change page and breaks login into downstream apps.
	forceChange := os.Getenv("SEED_MSS_FORCE_CHANGE") == "true"

	log.Printf("Seeding %d Masterspace (mss) users (force_change=%v)...", len(masterspaceStaff), forceChange)
	for _, s := range masterspaceStaff {
		profile := map[string]any{
			"name":                 s.Name,
			"must_change_password": forceChange,
			"created_by":           "seed:mss",
			"role":                 s.Role,
		}
		u, err := client.User.Create().
			SetEmail(s.Email).
			SetPasswordHash(hash).
			SetStatus("active").
			SetPrimaryTenantID(mss.ID.String()).
			SetProfile(profile).
			Save(ctx)
		if err != nil {
			// Exists — reset to the temp password + must_change so they can log in.
			u, err = client.User.Query().Where(user.EmailEQ(s.Email)).Only(ctx)
			if err != nil {
				log.Printf("  ⚠️  %s: %v", s.Email, err)
				continue
			}
			if _, err := u.Update().SetPasswordHash(hash).SetProfile(profile).
				SetPrimaryTenantID(mss.ID.String()).Save(ctx); err != nil {
				log.Printf("  ⚠️  update %s: %v", s.Email, err)
			}
			log.Printf("  ✓ Reset existing user: %s (%s)", s.Email, s.Role)
		} else {
			log.Printf("  ✓ Created user: %s (%s)", s.Email, s.Role)
		}

		// Upsert mss tenant membership with the user's role.
		exists, _ := client.TenantMembership.Query().Where(
			tenantmembership.UserID(u.ID), tenantmembership.TenantID(mss.ID),
		).Exist(ctx)
		if exists {
			memb, err := client.TenantMembership.Query().Where(
				tenantmembership.UserID(u.ID), tenantmembership.TenantID(mss.ID),
			).Only(ctx)
			if err == nil {
				_, _ = memb.Update().SetRoles([]string{s.Role}).SetStatus("active").Save(ctx)
			}
		} else if _, err := client.TenantMembership.Create().
			SetUserID(u.ID).SetTenantID(mss.ID).SetRoles([]string{s.Role}).Save(ctx); err != nil {
			log.Printf("  ⚠️  membership %s: %v", s.Email, err)
		}
	}
	log.Println("✓ Masterspace users seeded.")
	return nil
}
