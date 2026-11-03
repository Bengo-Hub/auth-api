// Package main: cmd/member-services lists the services each active tenant member gets (the access
// package's rules) and, with -apply, republishes auth.user.updated for them so every service's
// auth.user consumer keeps or removes its local copy accordingly.
//
// Dry run (default, changes nothing):
//
//	auth-member-services                 # every tenant
//	auth-member-services -tenant shop    # one tenant (slug)
//
// Output is tab-separated: tenant slug, user id, email, roles, services ("unknown" when they could
// not be decided; such members are never republished).
//
// Apply, after reviewing the dry run:
//
//	auth-member-services -apply [-tenant shop] [-only shop:<user_id>,...]
//	auth-member-services -revoke shop:<user_id>,...   # people no longer members of shop
//
// -only limits -apply to the listed members, so services that do not read `services` yet are not
// sent updates for everyone.
//
// Each republished event goes through the outbox like any member edit, carrying the member's
// services (outbox.SetUserServices), so the services apply the same rules as for live events.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"go.uber.org/zap"

	sharedcache "github.com/Bengo-Hub/cache"

	"github.com/bengobox/auth-api/internal/app"
	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/platform/outbox"
	"github.com/bengobox/auth-api/internal/services/access"
	"github.com/bengobox/auth-api/internal/services/integrations"
)

func main() {
	apply := flag.Bool("apply", false, "republish auth.user.updated for every member whose services are known")
	tenantSlug := flag.String("tenant", "", "only this tenant (slug)")
	only := flag.String("only", "", "with -apply: only these members, as slug:user_id pairs separated by commas")
	revoke := flag.String("revoke", "", "slug:user_id pairs (commas) of people who are no longer members: "+
		"publish auth.user.updated with an empty services list so every service removes its copy in that tenant")
	flag.Parse()
	onlySet := parsePairs(*only)
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx := context.Background()
	client, _, err := database.NewClient(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer client.Close()
	redisClient, err := sharedcache.NewRedis(ctx, sharedcache.RedisConfig{
		Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB, TLS: cfg.Redis.EnableTLS,
	})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	integrationSvc := integrations.New(client, redisClient, cfg.Security.EncryptionKey, cfg.Token.Issuer)
	resolver := access.New(client, app.MemberPlanLookup(app.NewSubscriptionClient(cfg, integrationSvc, zap.NewNop())))
	outbox.SetUserServices(resolver.MemberServices)

	q := client.TenantMembership.Query().Where(tenantmembership.StatusEQ("active")).WithTenant().WithUser()
	if *tenantSlug != "" {
		q = q.Where(tenantmembership.HasTenantWith(tenant.SlugEQ(*tenantSlug)))
	}
	members, err := q.All(ctx)
	if err != nil {
		log.Fatalf("memberships: %v", err)
	}

	out := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(out, "TENANT\tUSER\tEMAIL\tROLES\tSERVICES")
	published, unknown := 0, 0
	for _, m := range members {
		services, ok := resolver.ForMembership(ctx, m)
		shown := "unknown"
		if ok {
			shown = strings.Join(services, ",")
			if shown == "" {
				shown = "(none)"
			}
		} else {
			unknown++
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n", slugOf(m), m.UserID, emailOf(m), strings.Join(m.Roles, ","), shown)
		if !*apply || !ok {
			continue
		}
		if onlySet != nil && !onlySet[slugOf(m)+":"+m.UserID.String()] {
			continue
		}
		payload := map[string]any{
			"user_id": m.UserID.String(), "tenant_id": m.TenantID.String(), "tenant_slug": slugOf(m),
			"email": emailOf(m), "roles": m.Roles, "services": services,
		}
		if m.Edges.User != nil {
			if name, _ := m.Edges.User.Profile["name"].(string); name != "" {
				payload["full_name"] = name
			}
		}
		if err := outbox.Write(ctx, client, m.TenantID, "auth.user", m.UserID, "updated", slugOf(m), payload); err != nil {
			log.Fatalf("publish %s/%s: %v", slugOf(m), m.UserID, err)
		}
		published++
	}
	_ = out.Flush()

	// People no longer members of a tenant still have copies there: an explicit empty list makes
	// each service remove its copy in that tenant (a caller-set list is kept by outbox.Write).
	// Every pair is checked before anything is written, so a bad entry never leaves a run half
	// done. A tenant auth no longer has is reported and skipped (its leftovers are a tenant
	// purge, not a member revoke); an active member stops the run.
	type revokeTarget struct {
		slug     string
		tenantID uuid.UUID
		userID   uuid.UUID
	}
	var targets []revokeTarget
	var skipped []string
	for pair := range parsePairs(*revoke) {
		slug, rawID, _ := strings.Cut(pair, ":")
		userID, err := uuid.Parse(rawID)
		if err != nil {
			log.Fatalf("revoke %q: bad user id", pair)
		}
		t, err := client.Tenant.Query().Where(tenant.SlugEQ(slug)).Only(ctx)
		if ent.IsNotFound(err) {
			skipped = append(skipped, pair)
			continue
		}
		if err != nil {
			log.Fatalf("revoke %q: tenant: %v", pair, err)
		}
		if exists, _ := client.TenantMembership.Query().Where(tenantmembership.TenantID(t.ID),
			tenantmembership.UserID(userID), tenantmembership.StatusEQ("active")).Exist(ctx); exists {
			log.Fatalf("revoke %q: still an active member; use -apply instead (nothing was revoked)", pair)
		}
		targets = append(targets, revokeTarget{slug: slug, tenantID: t.ID, userID: userID})
	}
	for _, rt := range targets {
		payload := map[string]any{"user_id": rt.userID.String(), "tenant_id": rt.tenantID.String(),
			"tenant_slug": rt.slug, "services": []string{}}
		if err := outbox.Write(ctx, client, rt.tenantID, "auth.user", rt.userID, "updated", rt.slug, payload); err != nil {
			log.Fatalf("revoke %s:%s: %v", rt.slug, rt.userID, err)
		}
	}
	for _, pair := range skipped {
		fmt.Printf("skipped %s: no such tenant in auth\n", pair)
	}

	fmt.Printf("\n%d members, %d with unknown services", len(members), unknown)
	if len(targets) > 0 {
		fmt.Printf(", %d former members revoked", len(targets))
	}
	switch {
	case *apply:
		fmt.Printf(", %d auth.user.updated events queued", published)
	case len(targets) == 0:
		fmt.Print(" (dry run: nothing published; rerun with -apply)")
	}
	fmt.Println()
}

// parsePairs reads "slug:user_id,slug:user_id"; nil when empty.
func parsePairs(s string) map[string]bool {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

func slugOf(m *ent.TenantMembership) string {
	if m.Edges.Tenant != nil {
		return m.Edges.Tenant.Slug
	}
	return m.TenantID.String()
}

func emailOf(m *ent.TenantMembership) string {
	if m.Edges.User != nil {
		return m.Edges.User.Email
	}
	return ""
}
