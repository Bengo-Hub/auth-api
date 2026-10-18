package tenantbackup

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Bengo-Hub/httpware/objectstore"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"
)

func TestParseServices(t *testing.T) {
	got := ParseServices(" pos=http://pos:4000/ , bad, treasury=http://t:4000,=x,")
	if len(got) != 2 || got["pos"] != "http://pos:4000" || got["treasury"] != "http://t:4000" {
		t.Fatalf("%v", got)
	}
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

	var gotKey, gotTenant string
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotTenant = r.Header.Get("X-API-Key"), r.Header.Get("X-Tenant-ID")
		if r.URL.Path != exportPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("gzipped-export"))
	}))
	defer ok.Close()
	missing := httptest.NewServer(http.NotFoundHandler())
	defer missing.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	store, err := objectstore.New("auth", objectstore.Config{LocalRoot: t.TempDir(), LocalURLBase: "http://localhost:4000"})
	if err != nil {
		t.Fatal(err)
	}
	svc := New(db, store, map[string]string{"pos": ok.URL, "library": missing.URL, "erp": broken.URL}, "KEY", zap.NewNop())
	if !svc.Enabled() {
		t.Fatal("configured service must be enabled")
	}

	first := runToEnd(t, svc, tenantID)
	if first.Status != StatusCompleted || first.Key == "" || gotKey != "KEY" || gotTenant != tenantID.String() {
		t.Fatalf("first backup: %+v key=%q tenant=%q", first, gotKey, gotTenant)
	}
	statuses := map[string]string{}
	for _, s := range first.Services {
		statuses[s.Service] = s.Status
	}
	if statuses["pos"] != "ok" || statuses["library"] != "unavailable" || statuses["erp"] != "failed" {
		t.Fatalf("service results %v", statuses)
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
	if !names["pos.jsonl.gz"] || !names["manifest.json"] || names["erp.jsonl.gz"] || names["library.jsonl.gz"] {
		t.Fatalf("archive entries %v", names)
	}
	var theme string
	if err := db.QueryRowContext(ctx, `SELECT metadata->>'theme' FROM tenants WHERE id = $1`, tenantID).Scan(&theme); err != nil || theme != "blue" {
		t.Fatalf("other metadata must survive: %q %v", theme, err)
	}
	if u, err := svc.DownloadURL(first, "acme"); err != nil || u == "" {
		t.Fatalf("download link: %q %v", u, err)
	}

	// A second backup replaces the first; only the newest is kept.
	second := runToEnd(t, svc, tenantID)
	if second.Key == first.Key {
		t.Fatal("a new backup gets a new key")
	}
	if ok, _ := store.Exists(ctx, first.Key); ok {
		t.Fatal("the previous backup must be deleted")
	}

	// A fresh running state blocks a second start; a stale one does not.
	running := &State{Status: StatusRunning, StartedAt: time.Now(), HeartbeatAt: time.Now(), Key: second.Key}
	if err := svc.save(ctx, tenantID, running); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(tenantID, "u"); err != ErrRunning {
		t.Fatalf("want ErrRunning, got %v", err)
	}
	running.HeartbeatAt = time.Now().Add(-time.Hour)
	_ = svc.save(ctx, tenantID, running)
	third := runToEnd(t, svc, tenantID)
	if third.Status != StatusCompleted {
		t.Fatalf("a stale run must not block: %+v", third)
	}

	// All services failing: the backup fails and the previous archive stays.
	failing := New(db, store, map[string]string{"erp": broken.URL}, "KEY", zap.NewNop())
	failed := runToEnd(t, failing, tenantID)
	if failed.Status != StatusFailed || failed.Key != third.Key {
		t.Fatalf("failed run must keep the previous archive: %+v", failed)
	}
	if ok, _ := store.Exists(ctx, third.Key); !ok {
		t.Fatal("previous archive deleted after a failed run")
	}
}

func runToEnd(t *testing.T, svc *Service, tenantID uuid.UUID) *State {
	t.Helper()
	if _, err := svc.Start(tenantID, "user-1"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
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
