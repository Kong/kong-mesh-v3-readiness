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
			// A scenario opts into the version-currency check by dropping a
			// latest-version.txt (one patch string). Scenarios without it skip the
			// check, so unrelated goldens stay untouched and offline/deterministic.
			latest, hasLatest := readScenarioLatest(t, dir)
			rep, err := audit(context.Background(), c, auditOptions{
				checkVersionCurrency: hasLatest, latestPatch: latest,
			})
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

// TestBlockerFindingsCarryDocLinks checks the end-to-end propagation path: the
// blockers the kitchen-sink scenario surfaces carry a Kong Mesh doc link all the
// way through audit -> model -> JSON. It cannot cover every blocker category (one
// fixture does not trigger them all) — TestBlockerCallSitesUseAddDoc is the
// comprehensive guard over the call sites themselves.
func TestBlockerFindingsCarryDocLinks(t *testing.T) {
	dir := filepath.Join("testdata", "golden", "kitchen-sink")
	srv := mockCP(t, dir)
	c, err := newClient(srv.URL, "", 30*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	latest, hasLatest := readScenarioLatest(t, dir)
	rep, err := audit(context.Background(), c, auditOptions{
		checkVersionCurrency: hasLatest, latestPatch: latest,
	})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	blockers := 0
	for _, f := range rep.toModel("").Findings {
		if f.Severity != blocker.String() || f.Category == "Unparseable resources" {
			continue
		}
		blockers++
		switch {
		case f.Doc == "":
			t.Errorf("blocker %q (%s) has no doc link", f.Title, f.Category)
		case !strings.HasPrefix(f.Doc, docBase+"/mesh/"):
			t.Errorf("blocker %q doc link %q is not a Kong Mesh docs URL", f.Title, f.Doc)
		}
	}
	if blockers == 0 {
		t.Fatal("kitchen-sink produced no blockers — fixture regressed")
	}
}

// TestBlockerCallSitesUseAddDoc enforces statically — over every call site, not
// just the ones a fixture happens to exercise — that a blocker is recorded via
// addDoc (which carries a Kong Mesh docs link), never the doc-less add. The one
// allowed exception is the Unparseable-resources blocker: a parse failure has no
// 3.0 replacement API to link. A new `add(blocker, ...)` fails this test.
func TestBlockerCallSitesUseAddDoc(t *testing.T) {
	src, err := os.ReadFile("audit.go")
	if err != nil {
		t.Fatalf("reading audit.go: %v", err)
	}
	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		// addDoc(blocker, ...) does not contain the substring ".add(blocker", so
		// only the doc-less add is matched here.
		if !strings.Contains(trimmed, ".add(blocker,") {
			continue
		}
		if strings.Contains(trimmed, `"Unparseable resources"`) {
			continue // the sole blocker with no replacement API to link
		}
		t.Errorf("audit.go:%d records a blocker via the doc-less add(); use addDoc with a docX link:\n\t%s", i+1, trimmed)
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

// readScenarioLatest returns the optional latest-version.txt baseline for a
// scenario and whether it was present (the file enables the version check). Only a
// genuine "not found" disables the check; any other read error fails the test so a
// transient/permission fault can't silently skip the version check.
func readScenarioLatest(t *testing.T, dir string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "latest-version.txt"))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatalf("reading latest-version.txt: %v", err)
	}
	return strings.TrimSpace(string(b)), true
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
