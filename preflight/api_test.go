package preflight_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kong/kong-mesh-v3-readiness/preflight"
)

// cleanConfigJSON is a GET /config payload with every setting already in its
// 3.0-ready state, so checkControlPlaneConfig produces no findings.
const cleanConfigJSON = `{
  "mode": "zone",
  "environment": "kubernetes",
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if !strings.Contains(out, `"schema"`) || !strings.Contains(out, preflight.SchemaVersion) {
		t.Errorf("rendered JSON missing expected schema field: %s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("rendered JSON does not look like a JSON object: %s", out)
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
