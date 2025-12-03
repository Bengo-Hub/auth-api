package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bengobox/auth-service/internal/config"
	"github.com/bengobox/auth-service/internal/ent"
	"github.com/bengobox/auth-service/internal/ent/tenant"
	"github.com/bengobox/auth-service/internal/ent/tenantmembership"
	"github.com/bengobox/auth-service/internal/ent/user"
	"github.com/bengobox/auth-service/internal/password"
)

// SeedData creates default tenant and admin user if they don't exist.
// This function is idempotent and safe to run multiple times.
func SeedData(ctx context.Context, client *ent.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	log.Println("🌱 Starting database seeding...")

	// Get admin password from environment or use default
	adminPassword := os.Getenv("SEED_ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "ChangeMe123!"
		log.Println("⚠️  Using default admin password. Set SEED_ADMIN_PASSWORD environment variable in production.")
	}

	// Initialize password hasher with default secure parameters
	hasher := password.NewHasher(config.SecurityConfig{
		Argon2Time:      3,
		Argon2Memory:    65536,
		Argon2Threads:   2,
		Argon2KeyLength: 32,
	})

	// Create or get default tenant (codevertex)
	defaultTenant, err := client.Tenant.Query().
		Where(tenant.SlugEQ("codevertex")).
		Only(ctx)

	if ent.IsNotFound(err) {
		log.Println("📦 Creating default tenant: codevertex")
		defaultTenant, err = client.Tenant.Create().
			SetSlug("codevertex").
			SetName("CodeVertex IT Solutions").
			SetStatus("active").
			Save(ctx)
		if err != nil {
			return fmt.Errorf("create default tenant: %w", err)
		}
		log.Println("✅ Default tenant created")
	} else if err != nil {
		return fmt.Errorf("query default tenant: %w", err)
	} else {
		log.Println("✓ Default tenant already exists")
	}

	// Create or get admin user
	adminEmail := "admin@codevertexitsolutions.com"
	existingAdmin, err := client.User.Query().
		Where(user.EmailEQ(adminEmail)).
		Only(ctx)

	var adminUser *ent.User
	if ent.IsNotFound(err) {
		log.Println("👤 Creating admin user:", adminEmail)

		// Hash password using Argon2id
		hashedPassword, err := hasher.Hash(adminPassword)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}

		adminUser, err = client.User.Create().
			SetEmail(adminEmail).
			SetPasswordHash(hashedPassword).
			SetStatus("active").
			SetPrimaryTenantID(defaultTenant.ID.String()).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("create admin user: %w", err)
		}
		log.Println("✅ Admin user created")
		log.Printf("   Email: %s\n", adminEmail)
		log.Printf("   Password: %s\n", adminPassword)
		log.Printf("   Tenant: codevertex\n")
	} else if err != nil {
		return fmt.Errorf("query admin user: %w", err)
	} else {
		log.Println("✓ Admin user already exists")
		adminUser = existingAdmin

		// Optionally update password if SEED_ADMIN_PASSWORD is set
		if os.Getenv("SEED_ADMIN_PASSWORD") != "" {
			log.Println("🔄 Updating admin password...")
			hashedPassword, err := hasher.Hash(adminPassword)
			if err != nil {
				return fmt.Errorf("hash password: %w", err)
			}

			_, err = adminUser.Update().
				SetPasswordHash(hashedPassword).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("update admin password: %w", err)
			}
			log.Println("✅ Admin password updated")
		}
	}

	// Create or update tenant membership with superuser role
	membership, err := client.TenantMembership.Query().
		Where(
			tenantmembership.UserIDEQ(adminUser.ID),
			tenantmembership.TenantIDEQ(defaultTenant.ID),
		).
		Only(ctx)

	if ent.IsNotFound(err) {
		log.Println("🔗 Creating tenant membership for admin")
		_, err = client.TenantMembership.Create().
			SetUserID(adminUser.ID).
			SetTenantID(defaultTenant.ID).
			SetRoles([]string{"superuser", "admin"}).
			SetStatus("active").
			Save(ctx)
		if err != nil {
			return fmt.Errorf("create tenant membership: %w", err)
		}
		log.Println("✅ Tenant membership created")
	} else if err != nil {
		return fmt.Errorf("query tenant membership: %w", err)
	} else {
		log.Println("✓ Tenant membership already exists")
		// Update roles if needed
		currentRoles := membership.Roles
		needsUpdate := true
		for _, role := range currentRoles {
			if role == "superuser" {
				needsUpdate = false
				break
			}
		}
		if needsUpdate {
			log.Println("🔄 Updating membership roles...")
			_, err = membership.Update().
				SetRoles([]string{"superuser", "admin"}).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("update membership roles: %w", err)
			}
			log.Println("✅ Membership roles updated")
		}
	}

	log.Println("🎉 Database seeding completed successfully!")
	return nil
}
