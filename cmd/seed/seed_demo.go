package main

import (
	"context"
	"log"
	"os"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/password"
)

// seedTruLoadAdmin seeds the admin user for the TruLoad commercial weighing tenant.
func seedTruLoadAdmin(ctx context.Context, client *ent.Client, hasher *password.Hasher, truloadTenant *tenantRef) error {
	truloadAdminEmail := "admin@truload.codevertexitsolutions.com"
	truloadAdminPassword := os.Getenv("SEED_TRULOAD_ADMIN_PASSWORD")
	if truloadAdminPassword == "" {
		truloadAdminPassword = "ChangeMe123!" // default for local dev; override via env in production
	}
	truloadAdminHash, _ := hasher.Hash(truloadAdminPassword)

	truloadAdmin, err := client.User.Create().
		SetEmail(truloadAdminEmail).
		SetPasswordHash(truloadAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(truloadTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "TruLoad Demo Admin",
			"phone":      "+254700000010",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		truloadAdmin, err = client.User.Query().Where(user.EmailEQ(truloadAdminEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed truload admin: %v", err)
			return nil
		}
		log.Printf("✓ TruLoad admin exists: %s", truloadAdminEmail)
	} else {
		log.Printf("✓ Created TruLoad admin: %s", truloadAdminEmail)
	}

	if truloadAdmin != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(truloadAdmin.ID),
				tenantmembership.TenantID(truloadTenant.ID),
			).Exist(ctx)
		if !exists {
			_, err = client.TenantMembership.Create().
				SetUserID(truloadAdmin.ID).
				SetTenantID(truloadTenant.ID).
				SetRoles([]string{"admin"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating truload admin membership: %v", err)
			} else {
				log.Printf("  ✓ Added admin role in %s", truloadTenant.Slug)
			}
		}
	}
	return nil
}

// seedKURAAdmin seeds the canonical admin for Kenya Urban Roads Authority.
// All previous kura users were removed via kubectl SQL (database-maintenance.md).
// This seeds the canonical kura admin: axleload@kura.go.ke
func seedKURAAdmin(ctx context.Context, client *ent.Client, hasher *password.Hasher, kuraTenant *tenantRef) error {
	kuraAdminEmail := "axleload@kura.go.ke"
	kuraAdminPassword := os.Getenv("SEED_KURA_ADMIN_PASSWORD")
	if kuraAdminPassword == "" {
		kuraAdminPassword = "Admin312$"
	}
	kuraAdminHash, _ := hasher.Hash(kuraAdminPassword)

	kuraAdmin, err := client.User.Create().
		SetEmail(kuraAdminEmail).
		SetPasswordHash(kuraAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(kuraTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "AxleLoad KURA Admin",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		kuraAdmin, err = client.User.Query().Where(user.EmailEQ(kuraAdminEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed kura admin: %v", err)
			return nil
		}
		log.Printf("✓ KURA admin exists: %s", kuraAdminEmail)
	} else {
		log.Printf("✓ Created KURA admin: %s", kuraAdminEmail)
	}

	if kuraAdmin != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(kuraAdmin.ID),
				tenantmembership.TenantID(kuraTenant.ID),
			).Exist(ctx)
		if !exists {
			_, err = client.TenantMembership.Create().
				SetUserID(kuraAdmin.ID).
				SetTenantID(kuraTenant.ID).
				SetRoles([]string{"admin"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating kura admin membership: %v", err)
			} else {
				log.Printf("  ✓ Added admin role in %s", kuraTenant.Slug)
			}
		}
	}
	return nil
}
