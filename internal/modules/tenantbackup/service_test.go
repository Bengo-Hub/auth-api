package tenantbackup

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bengo-Hub/httpware/objectstore"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/clients/subscription"
)

func TestParseServices(t *testing.T) {
	got := ParseServices(" pos=http://pos:4000/ , bad, treasury=http://t:4000|fin,=x,notifications=http://n:4000,")
	if len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if got["pos"] != (Target{URL: "http://pos:4000", Tag: "pos"}) {
		t.Errorf("pos: %+v", got["pos"])
	}
	if got["treasury"] != (Target{URL: "http://t:4000", Tag: "fin"}) {
		t.Errorf("explicit tag wins: %+v", got["treasury"])
	}
	if got["notifications"].Tag != "" {
		t.Errorf("platform services have no plan tag: %+v", got["notifications"])
	}
}

type fakeEntitler struct {
	tags []string
	err  error
}

func (f fakeEntitler) GetEntitledServices(_ context.Context, id uuid.UUID) (*subscription.EntitledServices, error) {
	if f.err != nil {
		return nil, f.err
	}
	all := []string{"pos", "library", "erp", "hospital", "projects", "maskani", "truncated"}
	in := map[string]bool{}
	for _, t := range f.tags {
		in[t] = true
	}
	out := &subscription.EntitledServices{TenantID: id.String()}
	for _, a := range all {
		out.Services = append(out.Services, subscription.EntitledService{ServiceTag: a, Name: a, Entitled: in[a]})
	}
	return out, nil
}

func exportStream(rows int, withSummary bool) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(`{"type":"export","service":"x"}` + "\n"))
	for i := 0; i < rows; i++ {
		_, _ = gz.Write([]byte(fmt.Sprintf(`{"type":"row","table":"t","row":{"id":%d}}`+"\n", i)))
	}
	if withSummary {
		_, _ = gz.Write([]byte(fmt.Sprintf(`{"type":"summary","tables":{"t":%d},"rows":%d}`+"\n", rows, rows)))
	}
	_ = gz.Close()
	return buf.Bytes()
}

// TestBackupOnPostgres needs TENANTBACKUP_TEST_POSTGRES_URL (a scratch database).
func TestBackupOnPostgres(t *testing.T) {
	dsn := os.Getenv("TENANTBACKUP_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("TENANTBACKUP_TEST_POSTGRES_URL not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	tenantID := uuid.New()
	for _, q := range []string{
		`DROP TABLE IF EXISTS tenants`,
		`CREATE TABLE tenants (id uuid PRIMARY KEY, slug text, metadata jsonb)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants VALUES ($1, 'acme', '{"theme":"blue"}')`, tenantID); err != nil {
		t.Fatal(err)
	}

	var gotKey, gotTenant atomic.Value
	exportCalls := map[string]*int32{}
	// service builds a test server: probe answers per probe (nil = old service that streams the
	// export for any request), export answers with the export body.
	service := func(name string, probe func(w http.ResponseWriter), export func(w http.ResponseWriter)) *httptest.Server {
		exportCalls[name] = new(int32)
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotKey.Store(r.Header.Get("X-API-Key"))
			gotTenant.Store(r.Header.Get("X-Tenant-ID"))
			if r.URL.Path != exportPath {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.URL.Query().Get("probe") == "1" && probe != nil {
				probe(w)
				return
			}
			atomic.AddInt32(exportCalls[name], 1)
			export(w)
		}))
	}
	jsonBody := func(body string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
	}
	stream := func(rows int, summary bool) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/x-ndjson+gzip")
			_, _ = w.Write(exportStream(rows, summary))
		}
	}
	pos := service("pos", jsonBody(`{"has_data":true,"tables_with_data":["t"]}`), stream(3, true))
	erp := service("erp", jsonBody(`{"has_data":false,"tables_with_data":[]}`), stream(0, true))
	maskani := service("maskani", jsonBody(`{"has_data":true}`), stream(5, true))
	hospital := service("hospital", nil, stream(0, true)) // old service: probe ignored, empty export
	truncated := service("truncated", jsonBody(`{"has_data":true}`), stream(4, false))
	broken := service("projects", jsonBody(`{"has_data":true}`), func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) })
	missing := httptest.NewServer(http.NotFoundHandler())
	for _, s := range []*httptest.Server{pos, erp, maskani, hospital, truncated, broken, missing} {
		defer s.Close()
	}

	store, err := objectstore.New("auth", objectstore.Config{LocalRoot: t.TempDir(), LocalURLBase: "http://localhost:4000"})
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]Target{
		"pos": {URL: pos.URL, Tag: "pos"}, "erp": {URL: erp.URL, Tag: "erp"}, "maskani": {URL: maskani.URL, Tag: "maskani"},
		"hospital": {URL: hospital.URL, Tag: "hospital"}, "truncated": {URL: truncated.URL, Tag: "truncated"},
		"projects": {URL: broken.URL, Tag: "projects"}, "library": {URL: missing.URL, Tag: "library"},
	}
	// The plan covers everything except maskani.
	plan := fakeEntitler{tags: []string{"pos", "library", "erp", "hospital", "projects", "truncated"}}
	svc := New(db, store, targets, plan, "KEY", zap.NewNop())
	if !svc.Enabled() {
		t.Fatal("configured service must be enabled")
	}

	first := runToEnd(t, svc, tenantID, nil)
	if k, _ := gotKey.Load().(string); first.Status != StatusCompleted || first.Key == "" || k != "KEY" {
		t.Fatalf("first backup: %+v key=%q", first, k)
	}
	if tn, _ := gotTenant.Load().(string); tn != tenantID.String() {
		t.Fatalf("tenant header %q", tn)
	}
	want := map[string]string{
		"pos": ResultOK, "erp": ResultEmpty, "hospital": ResultEmpty, "library": ResultUnavailable,
		"projects": ResultFailed, "truncated": ResultFailed, "maskani": ResultNotInPlan,
	}
	got := map[string]string{}
	for _, s := range first.Services {
		got[s.Service] = s.Status
	}
	for name, status := range want {
		if got[name] != status {
			t.Errorf("%s: got %q want %q (all %v)", name, got[name], status, got)
		}
	}
	if !first.Partial {
		t.Error("a run with failed services is partial")
	}
	if n := atomic.LoadInt32(exportCalls["maskani"]); n != 0 {
		t.Errorf("a service outside the plan must never be called for its export: %d calls", n)
	}
	if n := atomic.LoadInt32(exportCalls["erp"]); n != 0 {
		t.Errorf("an empty service is skipped by the probe: %d export calls", n)
	}
	body, _, err := store.Get(ctx, first.Key)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if len(names) != 2 || !names["pos.jsonl.gz"] || !names["manifest.json"] {
		t.Fatalf("only the service with data is archived, got %v", names)
	}
	var theme string
	if err := db.QueryRowContext(ctx, `SELECT metadata->>'theme' FROM tenants WHERE id = $1`, tenantID).Scan(&theme); err != nil || theme != "blue" {
		t.Fatalf("other metadata must survive: %q %v", theme, err)
	}
	if u, err := svc.DownloadURL(first, "acme"); err != nil || u == "" {
		t.Fatalf("download link: %q %v", u, err)
	}

	// Picking one service collects only that one.
	one := runToEnd(t, svc, tenantID, []string{"pos"})
	if len(one.Services) != 1 || one.Services[0].Service != "pos" || one.Services[0].Status != ResultOK || one.Partial {
		t.Fatalf("single-service backup: %+v", one.Services)
	}
	if one.Key == first.Key {
		t.Fatal("a new backup gets a new key")
	}
	if ok, _ := store.Exists(ctx, first.Key); ok {
		t.Fatal("the previous backup must be deleted")
	}

	// A selection outside the plan or unknown is refused before anything runs.
	if _, err := svc.Start(ctx, tenantID, "u", []string{"maskani"}); !errors.Is(err, ErrNotInPlan) {
		t.Fatalf("service outside the plan: %v", err)
	}
	if _, err := svc.Start(ctx, tenantID, "u", []string{"nope"}); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("unknown service: %v", err)
	}
	cat, err := svc.Catalog(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	entitled := map[string]bool{}
	for _, c := range cat {
		entitled[c.Service] = c.Entitled
	}
	if entitled["maskani"] || !entitled["pos"] || len(cat) != len(targets) {
		t.Fatalf("catalog: %+v", cat)
	}

	// A plan that cannot be read never starts a backup.
	blind := New(db, store, targets, fakeEntitler{err: errors.New("down")}, "KEY", zap.NewNop())
	if _, err := blind.Start(ctx, tenantID, "u", nil); !errors.Is(err, ErrPlanUnverified) {
		t.Fatalf("unverified plan: %v", err)
	}

	// A fresh running state blocks a second start; a stale one does not.
	running := &State{Status: StatusRunning, StartedAt: time.Now().UTC(), HeartbeatAt: time.Now().UTC(), Key: one.Key}
	if err := svc.save(ctx, tenantID, running); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, tenantID, "u", []string{"pos"}); !errors.Is(err, ErrRunning) {
		t.Fatalf("want ErrRunning, got %v", err)
	}
	running.HeartbeatAt = time.Now().UTC().Add(-time.Hour)
	_ = svc.save(ctx, tenantID, running)
	third := runToEnd(t, svc, tenantID, []string{"pos"})
	if third.Status != StatusCompleted {
		t.Fatalf("a stale run must not block: %+v", third)
	}

	// No data anywhere in the selection: the backup fails and the previous archive stays.
	empty := New(db, store, map[string]Target{"erp": targets["erp"]}, plan, "KEY", zap.NewNop())
	failed := runToEnd(t, empty, tenantID, nil)
	if failed.Status != StatusFailed || failed.Key != third.Key {
		t.Fatalf("failed run must keep the previous archive: %+v", failed)
	}
	if ok, _ := store.Exists(ctx, third.Key); !ok {
		t.Fatal("previous archive deleted after a failed run")
	}
}

func runToEnd(t *testing.T, svc *Service, tenantID uuid.UUID, selected []string) *State {
	t.Helper()
	if _, err := svc.Start(context.Background(), tenantID, "user-1", selected); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		st, err := svc.Get(context.Background(), tenantID)
		if err != nil {
			t.Fatal(err)
		}
		if st != nil && st.Status != StatusRunning {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("backup did not finish")
	return nil
}
