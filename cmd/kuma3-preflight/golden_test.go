package main

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// update regenerates the *.golden.json reference files instead of asserting:
//
//	go test ./... -run TestGoldenReports -update
var update = flag.Bool("update", false, "update golden report files")

// TestGoldenReports audits a mock control plane per scenario directory under
// testdata/golden and compares the rendered JSON report against a checked-in
// golden file. The JSON shape is the stable contract (see model.go), so a diff
// here means an intentional contract change — review it, then refresh with
// -update. The mock CP serves fixture responses from <scenario>/responses; any
// collection without a fixture answers an empty list, so a scenario declares
// only the endpoints it cares about.
func TestGoldenReports(t *testing.T) {
	root := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading scenarios: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, name)
			srv := mockCP(t, dir)

			c, err := newClient(srv.URL, "", 30*time.Second)
			if err != nil {
				t.Fatalf("newClient: %v", err)
			}
			rep, err := audit(context.Background(), c, "")
			if err != nil {
				t.Fatalf("audit: %v", err)
			}
			// Empty generatedAt keeps the output deterministic (omitempty drops it).
			got, err := renderJSON(rep.toModel(""))
			if err != nil {
				t.Fatalf("renderJSON: %v", err)
			}

			goldenPath := filepath.Join(dir, "report.golden.json")
			if *update {
				if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
					t.Fatalf("writing golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("reading golden (run with -update to create it): %v", err)
			}
			if got != string(want) {
				t.Errorf("golden mismatch for %q (run -update to accept)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
			}
		})
	}
}

// mockCP starts an httptest server that replays CP fixture responses for one
// scenario. Lookup order for each request: a fixture matching the full path+query
// (for paginated pages), then one matching the path alone, then — for paths
// listed in 404.txt — a 404, else an empty collection. GET / has no default and
// must be provided as responses/root.json.
func mockCP(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	notFound := loadNotFound(t, dir)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := readFixture(dir, r.URL.RequestURI()); ok {
			writeJSON(w, body)
			return
		}
		if body, ok := readFixture(dir, r.URL.Path); ok {
			writeJSON(w, body)
			return
		}
		if notFound[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/" {
			t.Errorf("scenario %s missing responses/root.json (GET /)", dir)
			http.Error(w, "missing index fixture", http.StatusInternalServerError)
			return
		}
		writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// readFixture loads responses/<key>.json for the given request target, where the
// key is the target with '/', '?', '&', '=' folded to '_' (root -> "root").
func readFixture(dir, target string) ([]byte, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "responses", fixtureKey(target)+".json"))
	if err != nil {
		return nil, false
	}
	return b, true
}

func fixtureKey(target string) string {
	s := strings.TrimPrefix(target, "/")
	if s == "" {
		return "root"
	}
	return strings.NewReplacer("/", "_", "?", "_", "&", "_", "=", "_").Replace(s)
}

// loadNotFound reads the optional 404.txt manifest: one request path per line
// (blank lines and '#' comments ignored) that the mock must answer with 404, so
// a scenario can exercise coverage-gap handling.
func loadNotFound(t *testing.T, dir string) map[string]bool {
	t.Helper()
	m := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(dir, "404.txt"))
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			m[line] = true
		}
	}
	return m
}
