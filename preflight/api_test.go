package preflight_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kong/kong-mesh-v3-readiness/preflight"
)

// cleanConfigJSON is a GET /config payload with every setting already in its
// 3.0-ready state, so checkControlPlaneConfig produces no findings.
const cleanConfigJSON = `{
  "mode": "zone",
  "environment": "kubernetes",
  "defaults": {"restrictOutbound": true},
  "monitoringAssignmentServer": {"enabled": false},
  "experimental": {
    "autoReachableServices": false,
    "deltaXds": true,
    "sidecarContainers": true,
    "inboundTagsDisabled": true,
    "kdsEventBasedWatchdog": {"enabled": true}
  },
  "runtime": {"kubernetes": {
    "injector": {
      "unifiedResourceNamingEnabled": true,
      "ebpf": {"enabled": false}
    }
  }}
}`

// mockCleanCP starts a minimal stub CP: GET / returns a valid Kuma index, GET
// /config returns a 3.0-ready config, and GET /meshes returns a clean,
// fully-migrated Mesh; every other collection answers an empty list, so the
// audit completes with status "clean".
func mockCleanCP(t *testing.T) *httptest.Server {
	t.Helper()
	return mockCleanCPVersion(t, "2.14.0")
}

// mockCleanCPVersion is mockCleanCP with the reported control-plane version
// parameterized, for tests that need a stale audited CP.
func mockCleanCPVersion(t *testing.T, version string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"`+version+`","mode":"zone"}`)
		case "/config":
			_, _ = io.WriteString(w, cleanConfigJSON)
		case "/meshes":
			_, _ = io.WriteString(w, `{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}}],"next":null}`)
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestExternalConsumerFlow exercises the package's public surface the way an
// importing Go program would: call Audit, then render the result.
func TestExternalConsumerFlow(t *testing.T) {
	srv := mockCleanCP(t)

	rep, err := preflight.Audit(context.Background(), preflight.Options{Address: srv.URL, LatestPatch: "2.14.0"})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if rep.Status != preflight.StatusClean {
		t.Errorf("status = %q, want %q", rep.Status, preflight.StatusClean)
	}

	out, err := rep.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(out, `"tool_schema"`) || !strings.Contains(out, preflight.SchemaVersion) {
		t.Errorf("rendered JSON missing expected schema field: %s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("rendered JSON does not look like a JSON object: %s", out)
	}
}

func TestExternalConsumerFlowResourceReadLimit(t *testing.T) {
	srv := mockCleanCP(t)

	rep, err := preflight.Audit(context.Background(), preflight.Options{
		Address:           srv.URL,
		LatestPatch:       "2.14.0",
		ResourceReadLimit: 1,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if rep.Status != preflight.StatusInconclusive {
		t.Fatalf("status = %q, want %q", rep.Status, preflight.StatusInconclusive)
	}
	if len(rep.Coverage) != 1 || rep.Coverage[0].Path != "/meshes" {
		t.Fatalf("coverage = %+v, want one /meshes gap", rep.Coverage)
	}
	if !strings.Contains(rep.Coverage[0].Reason, "ceiling (1 resources)") {
		t.Fatalf("coverage reason = %q, want the limit value", rep.Coverage[0].Reason)
	}
}

func TestAuditMeshFilterBeyondResourceReadLimitIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.14.0","mode":"zone"}`)
		case "/config":
			_, _ = io.WriteString(w, cleanConfigJSON)
		case "/meshes":
			_, _ = io.WriteString(w, `{"total":2,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}},{"type":"Mesh","name":"target","meshServices":{"mode":"Exclusive"}}],"next":null}`)
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)

	rep, err := preflight.Audit(context.Background(), preflight.Options{
		Address:           srv.URL,
		LatestPatch:       "2.14.0",
		Mesh:              "target",
		ResourceReadLimit: 1,
	})
	if err != nil {
		t.Fatalf("Audit should preserve partial report when target mesh may be beyond read limit: %v", err)
	}
	if rep.Status != preflight.StatusInconclusive {
		t.Fatalf("status = %q, want %q", rep.Status, preflight.StatusInconclusive)
	}
	if len(rep.Coverage) != 1 || rep.Coverage[0].Path != "/meshes" {
		t.Fatalf("coverage = %+v, want one /meshes gap", rep.Coverage)
	}
	if len(rep.Meshes) != 0 {
		t.Fatalf("meshes = %v, want no admitted target mesh", rep.Meshes)
	}
}

// TestAuditSkipAuditedControlPlaneVersion proves the public Options field
// suppresses the blocker for the audited control plane's own stale version
// while still reporting the run as clean (no other findings on this CP).
func TestAuditSkipAuditedControlPlaneVersion(t *testing.T) {
	srv := mockCleanCPVersion(t, "2.9.0")

	rep, err := preflight.Audit(context.Background(), preflight.Options{
		Address: srv.URL, LatestPatch: "2.14.0", SkipAuditedControlPlaneVersionCheck: true,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if rep.Status != preflight.StatusClean {
		t.Errorf("status = %q, want %q", rep.Status, preflight.StatusClean)
	}
	if rep.Summary.Info < 1 {
		t.Errorf("Summary.Info = %d, want at least 1 (out-of-scope note)", rep.Summary.Info)
	}
	for _, f := range rep.Findings {
		if f.Severity == preflight.SeverityBlocker && f.Category == "Control plane version" {
			t.Errorf("found blocker in %q despite SkipAuditedControlPlaneVersionCheck: %+v", f.Category, f)
		}
	}
}

// blockedTransport is an http.RoundTripper that errors on any dial whose host
// isn't the one allowed CP host, so a test can prove Audit never reaches out
// anywhere except the audited control plane.
type blockedTransport struct {
	allowedHost string
	base        http.RoundTripper
}

func (b *blockedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != b.allowedHost {
		return nil, fmt.Errorf("blocked dial to unexpected host %q (only %q is allowed)", req.URL.Host, b.allowedHost)
	}
	return b.base.RoundTrip(req)
}

// TestAuditContactsOnlyControlPlane proves Audit issues HTTP requests only to
// the control plane named in Options.Address — never to any other host (e.g. a
// telemetry endpoint or the GitHub releases API the CLI itself queries).
func TestAuditContactsOnlyControlPlane(t *testing.T) {
	srv := mockCleanCP(t)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}

	hc := &http.Client{Transport: &blockedTransport{allowedHost: u.Host, base: http.DefaultTransport}}
	rep, err := preflight.Audit(context.Background(), preflight.Options{Address: srv.URL, LatestPatch: "2.14.0", HTTPClient: hc})
	if err != nil {
		t.Fatalf("Audit unexpectedly dialed a non-CP host (or otherwise failed): %v", err)
	}
	if rep.Status != preflight.StatusClean {
		t.Errorf("status = %q, want %q", rep.Status, preflight.StatusClean)
	}
}

// TestAuditRequestHeadersSentToControlPlane proves Audit forwards static request
// headers to control-plane requests while still honoring the caller's transport.
func TestAuditRequestHeadersSentToControlPlane(t *testing.T) {
	type seenRequest struct {
		path   string
		accept []string
		trace  []string
	}

	var seen []seenRequest
	hc := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			gotAccept := append([]string(nil), req.Header.Values("Accept")...)
			gotTrace := append([]string(nil), req.Header.Values("X-Trace-Id")...)
			if !slices.Equal(gotAccept, []string{"application/custom+json"}) {
				return nil, fmt.Errorf("%s Accept = %v, want only the custom value", req.URL.Path, gotAccept)
			}
			if !slices.Equal(gotTrace, []string{"trace-123"}) {
				return nil, fmt.Errorf("%s X-Trace-Id = %v, want custom header on every request", req.URL.Path, gotTrace)
			}
			seen = append(seen, seenRequest{
				path:   req.URL.Path,
				accept: gotAccept,
				trace:  gotTrace,
			})
			return http.DefaultTransport.RoundTrip(req)
		}),
	}
	srv := mockCleanCP(t)
	headers := http.Header{
		"Accept":     {"application/custom+json"},
		"X-Trace-Id": {"trace-123"},
	}

	rep, err := preflight.Audit(context.Background(), preflight.Options{
		Address:        srv.URL,
		LatestPatch:    "2.14.0",
		HTTPClient:     hc,
		RequestHeaders: headers,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if rep.Status != preflight.StatusClean {
		t.Errorf("status = %q, want %q", rep.Status, preflight.StatusClean)
	}
	if len(seen) < 2 {
		t.Fatalf("saw %d requests, want multiple control-plane requests validated", len(seen))
	}
	for _, req := range seen {
		if !slices.Equal(req.accept, []string{"application/custom+json"}) {
			t.Errorf("%s Accept = %v, want only the custom value", req.path, req.accept)
		}
		if !slices.Equal(req.trace, []string{"trace-123"}) {
			t.Errorf("%s X-Trace-Id = %v, want custom header on every request", req.path, req.trace)
		}
	}
}

func TestAuditRequestHeadersClonedBeforeUse(t *testing.T) {
	headers := http.Header{
		"X-Trace-Id": {"trace-123"},
	}
	seen := map[string]struct {
		trace    []string
		injected string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = struct {
			trace    []string
			injected string
		}{
			trace:    append([]string(nil), r.Header.Values("X-Trace-Id")...),
			injected: r.Header.Get("X-Injected"),
		}
		if r.URL.Path == "/" {
			headers["X-Trace-Id"][0] = "mutated-slice"
			headers.Set("X-Injected", "mutated-map")
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.14.0","mode":"zone"}`)
		case "/config":
			_, _ = io.WriteString(w, cleanConfigJSON)
		case "/meshes":
			_, _ = io.WriteString(w, `{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}}],"next":null}`)
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)

	rep, err := preflight.Audit(context.Background(), preflight.Options{
		Address:        srv.URL,
		LatestPatch:    "2.14.0",
		RequestHeaders: headers,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if rep.Status != preflight.StatusClean {
		t.Errorf("status = %q, want %q", rep.Status, preflight.StatusClean)
	}
	for path, got := range seen {
		if !slices.Equal(got.trace, []string{"trace-123"}) {
			t.Errorf("%s X-Trace-Id = %v, want cloned original value", path, got.trace)
		}
		if got.injected != "" {
			t.Errorf("%s X-Injected = %q, want caller's later map mutation ignored", path, got.injected)
		}
	}
	if _, ok := seen["/config"]; !ok {
		t.Fatal("Audit did not request /config after mutating caller headers")
	}
}

func TestAuditTokenOverridesCustomAuthorization(t *testing.T) {
	var gotAuthorization string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.14.0","mode":"zone"}`)
		case "/config":
			_, _ = io.WriteString(w, cleanConfigJSON)
		case "/meshes":
			_, _ = io.WriteString(w, `{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}}],"next":null}`)
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)

	_, err := preflight.Audit(context.Background(), preflight.Options{
		Address: srv.URL,
		Token:   "from-token",
		RequestHeaders: http.Header{
			"Authorization": {"Bearer from-header"},
		},
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if gotAuthorization != "Bearer from-token" {
		t.Errorf("Authorization = %q, want token to override the custom header", gotAuthorization)
	}
}

// TestAuditWritesNothingToStdio guards that the library never prints: Audit must
// be silent so an importing program's own stdout/stderr are never polluted.
func TestAuditWritesNothingToStdio(t *testing.T) {
	srv := mockCleanCP(t)

	stdout := captureFD(t, &os.Stdout)
	stderr := captureFD(t, &os.Stderr)

	_, err := preflight.Audit(context.Background(), preflight.Options{Address: srv.URL, HTTPClient: &http.Client{Timeout: 10 * time.Second}})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	if out := stdout(); out != "" {
		t.Errorf("Audit wrote to stdout: %q", out)
	}
	if got := stderr(); got != "" {
		t.Errorf("Audit wrote to stderr: %q", got)
	}
}

// captureFD redirects *target (os.Stdout or os.Stderr) to a pipe for the rest of
// the test and returns a function that restores the original and returns
// everything written.
func captureFD(t *testing.T, target **os.File) func() string {
	t.Helper()
	orig := *target
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	*target = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	return func() string {
		_ = w.Close()
		*target = orig
		got := <-done
		_ = r.Close()
		return got
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestAuditKnownGlobalSkipsAuditedConfig proves the public options let a caller
// that already knows the audited control plane is a global run a full audit
// without one GET /config request, while every zone's config is still audited.
func TestAuditKnownGlobalSkipsAuditedConfig(t *testing.T) {
	var mu sync.Mutex
	configRequests := 0
	zoneConfig := `{\"mode\":\"zone\",\"environment\":\"kubernetes\",\"experimental\":{\"deltaXds\":false,\"sidecarContainers\":false,\"inboundTagsDisabled\":false,\"kdsEventBasedWatchdog\":{\"enabled\":false}},\"runtime\":{\"kubernetes\":{\"injector\":{\"unifiedResourceNamingEnabled\":false,\"ebpf\":{\"enabled\":false}}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.14.0","mode":"global"}`)
		case "/config":
			mu.Lock()
			configRequests++
			mu.Unlock()
			http.Error(w, "the audit must not read the audited control plane's own config", http.StatusInternalServerError)
		case "/meshes":
			_, _ = io.WriteString(w, `{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}}],"next":null}`)
		case "/zones+insights":
			_, _ = io.WriteString(w, `{"total":1,"items":[{"type":"ZoneOverview","name":"east","zoneInsight":{"subscriptions":[{"config":"`+zoneConfig+`","version":{"kumaCp":{"version":"2.14.0"}}}]}}],"next":null}`)
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)

	rep, err := preflight.Audit(context.Background(), preflight.Options{
		Address:                       srv.URL,
		LatestPatch:                   "2.14.0",
		KnownGlobalControlPlane:       true,
		SkipAuditedControlPlaneConfig: true,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	mu.Lock()
	got := configRequests
	mu.Unlock()
	if got != 0 {
		t.Errorf("GET /config requests = %d, want 0", got)
	}
	if rep.Status != preflight.StatusBlockers {
		t.Errorf("status = %q, want %q (the zone's Delta xDS blocker)", rep.Status, preflight.StatusBlockers)
	}
	if len(rep.Coverage) != 0 {
		t.Errorf("coverage = %+v, want none", rep.Coverage)
	}
	if rep.ControlPlane.Mode != "global" {
		t.Errorf("mode = %q, want %q", rep.ControlPlane.Mode, "global")
	}
	var skipped, zoneBlocker bool
	for _, f := range rep.Findings {
		if f.Title == "Audited control plane settings not audited" && f.Severity == preflight.SeverityInfo {
			skipped = true
		}
		if f.Title == "Unified resource naming not enabled" && f.Severity == preflight.SeverityBlocker {
			zoneBlocker = true
		}
	}
	if !skipped {
		t.Errorf("missing the info finding naming the skipped scope; findings: %+v", rep.Findings)
	}
	if !zoneBlocker {
		t.Errorf("the zone's own config was not audited; findings: %+v", rep.Findings)
	}
}

// TestAuditSkipAuditedConfigRequiresKnownGlobal proves the guard: skipping the
// audited control plane's own settings is rejected without the mode assertion,
// and no request is made.
func TestAuditSkipAuditedConfigRequiresKnownGlobal(t *testing.T) {
	srv := mockCleanCP(t)

	_, err := preflight.Audit(context.Background(), preflight.Options{
		Address:                       srv.URL,
		SkipAuditedControlPlaneConfig: true,
	})
	if err == nil {
		t.Fatalf("Audit must reject SkipAuditedControlPlaneConfig without KnownGlobalControlPlane")
	}
	if !strings.Contains(err.Error(), "KnownGlobalControlPlane") {
		t.Errorf("error = %v, want it to name Options.KnownGlobalControlPlane", err)
	}
}

// TestAuditKnownGlobalWithoutSkipReadsConfig proves the mode assertion alone
// still reads and audits the control plane's own settings.
func TestAuditKnownGlobalWithoutSkipReadsConfig(t *testing.T) {
	rep, err := preflight.Audit(context.Background(), preflight.Options{
		Address:                 mockCleanCP(t).URL,
		LatestPatch:             "2.14.0",
		KnownGlobalControlPlane: true,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if rep.ControlPlane.Mode != "global" {
		t.Errorf("mode = %q, want the asserted %q", rep.ControlPlane.Mode, "global")
	}
	var noted bool
	for _, f := range rep.Findings {
		if f.Title == "Control plane mode differs from the caller's assertion" {
			noted = true
		}
	}
	if !noted {
		t.Errorf("a /config mode that disagrees with the assertion must be reported; findings: %+v", rep.Findings)
	}
}
