package domains

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/enttest"
)

// openDomainsDB opens an isolated Postgres schema; skips when Postgres is unreachable.
func openDomainsDB(t *testing.T) *ent.Client {
	t.Helper()
	base := os.Getenv("TEST_POSTGRES_URL")
	if base == "" {
		base = "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable"
	}
	db, err := sql.Open("postgres", base)
	if err != nil {
		t.Skipf("postgres: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("postgres unreachable: %v", err)
	}
	const schema = "ent_test_domain_downgrade"
	if _, err := db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE; CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	_ = db.Close()
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	client := enttest.Open(t, "postgres", base+sep+"search_path="+schema)
	t.Cleanup(func() {
		_ = client.Close()
		if d, err := sql.Open("postgres", base); err == nil {
			_, _ = d.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
			_ = d.Close()
		}
	})
	return client
}

type notice struct {
	host, kind string
	until      time.Time
}

// After a downgrade a MarketFlow domain keeps working for the grace with a notice, is paused
// after it with a notice, and comes back with a notice once the plan includes it again. A plan
// that cannot be read changes nothing (owner, 2026-11-12).
func TestEnforcePlansGraceThenPause(t *testing.T) {
	client := openDomainsDB(t)
	ctx := context.Background()
	tenantID := uuid.New()
	row, err := client.TenantDomain.Create().SetTenantID(tenantID).SetService("marketflow").SetHostname("shop.example.co.ke").
		SetStatus(StatusActive).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := client.TenantDomain.Create().SetTenantID(tenantID).SetService("ordering").SetHostname("store.example.co.ke").
		SetStatus(StatusActive).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var plan PlanInfo
	var lookupErr error
	var got []notice
	s := &Service{ent: client, log: zap.NewNop(), cache: map[string]cachedResolution{}}
	s.SetPlanGate(map[string]string{"marketflow": "marketflow_custom_domain"}, func(context.Context, uuid.UUID) (PlanInfo, error) {
		return plan, lookupErr
	})
	s.SetDowngrade(14*24*time.Hour, func(_ context.Context, _ uuid.UUID, host, _, kind string, until time.Time) {
		got = append(got, notice{host, kind, until})
	})
	reload := func(id uuid.UUID) *ent.TenantDomain {
		r, err := client.TenantDomain.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	day0 := time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)

	// Plan still includes it: nothing happens.
	plan = PlanInfo{Features: []string{"marketflow_custom_domain"}}
	if err := s.EnforcePlans(ctx, day0); err != nil || len(got) != 0 {
		t.Fatalf("kept plan: %v %v", err, got)
	}

	// Downgrade: grace starts, one notice; the ungated ordering domain is untouched.
	plan = PlanInfo{Features: []string{"marketflow_public_page"}}
	if err := s.EnforcePlans(ctx, day0); err != nil {
		t.Fatal(err)
	}
	r := reload(row.ID)
	if r.Status != StatusActive || r.GraceUntil == nil || !r.GraceUntil.Equal(day0.Add(14*24*time.Hour)) {
		t.Fatalf("grace not started: %+v", r)
	}
	if len(got) != 1 || got[0].kind != NoticeGrace || got[0].host != "shop.example.co.ke" {
		t.Fatalf("notices %+v", got)
	}
	if reload(other.ID).GraceUntil != nil {
		t.Fatal("an app with no plan feature is never gated")
	}

	// Within the grace: nothing more. A failed plan read changes nothing either.
	if err := s.EnforcePlans(ctx, day0.Add(5*24*time.Hour)); err != nil || len(got) != 1 {
		t.Fatalf("within grace: %v %v", err, got)
	}
	lookupErr = errors.New("subscriptions down")
	if err := s.EnforcePlans(ctx, day0.Add(20*24*time.Hour)); err != nil || reload(row.ID).Status != StatusActive {
		t.Fatal("an unreadable plan must not pause a domain")
	}
	lookupErr = nil

	// Past the grace: paused, notice, and Resolve no longer answers.
	if err := s.EnforcePlans(ctx, day0.Add(15*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := reload(row.ID); r.Status != StatusPaused || len(got) != 2 || got[1].kind != NoticePaused {
		t.Fatalf("not paused: %+v %+v", r, got)
	}
	if res, err := s.Resolve(ctx, "shop.example.co.ke"); err != nil || res != nil {
		t.Fatalf("a paused domain must not resolve: %+v %v", res, err)
	}

	// Upgrade: active again, grace cleared, notice.
	plan = PlanInfo{Features: []string{"marketflow_custom_domain"}}
	if err := s.EnforcePlans(ctx, day0.Add(16*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := reload(row.ID); r.Status != StatusActive || r.GraceUntil != nil || len(got) != 3 || got[2].kind != NoticeRestored {
		t.Fatalf("not restored: %+v %+v", r, got)
	}
}
