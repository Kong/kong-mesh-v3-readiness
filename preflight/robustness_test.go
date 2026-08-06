package preflight

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// cpServer starts a stub CP: GET / returns a valid Kuma index, and each path in
// handlers gets its handler; every other path answers an empty collection.
func cpServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := handlers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		if r.URL.Path == "/" {
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0"}`))
			return
		}
		writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func gapForPath(r *collector, path string) (coverageGap, bool) {
	for _, g := range r.coverage {
		if g.path == path {
			return g, true
		}
	}
	return coverageGap{}, false
}

// TestNonKumaEndpointReportsFriendlyError: pointing --address at a 200 endpoint
// whose body is not a JSON CP index (e.g. an HTML login/ingress page, or a wrong
// subpath like /gui) must fail as "not a Kuma control plane" — never leak a raw
// JSON decode error ("invalid character '<'") that obscures the real problem.
func TestNonKumaEndpointReportsFriendlyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>login</body></html>"))
	}))
	t.Cleanup(srv.Close)
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	_, err = audit(context.Background(), c, auditOptions{})
	if err == nil {
		t.Fatal("audit of a non-Kuma HTML endpoint returned no error (would be a false green)")
	}
	if !strings.Contains(err.Error(), "does not look like a Kuma control plane") {
		t.Errorf("error = %q, want it to mention 'does not look like a Kuma control plane'", err)
	}
	if strings.Contains(err.Error(), "invalid character") || strings.Contains(err.Error(), "decoding") {
		t.Errorf("error leaked a raw JSON decode message instead of the friendly one: %q", err)
	}
}

// TestIndexBodyTimeoutPropagates: a --timeout (or context cancel) firing AFTER the
// 200 headers arrive, while the index body is being read, is a real transport
// failure and must surface as such — not be misreported as "not a Kuma control
// plane". Guards the narrowed index() reinterpretation (JSON-shape/empty only).
func TestIndexBodyTimeoutPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // 200 headers out, then hold the body open until the client times out
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 250 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	_, err = audit(context.Background(), c, auditOptions{})
	if err == nil {
		t.Fatal("audit returned no error on a body-read timeout")
	}
	if strings.Contains(err.Error(), "does not look like a Kuma control plane") {
		t.Errorf("body-read timeout misreported as non-Kuma: %v", err.Error())
	}
}

// TestConfigForbiddenDegradesToGap: a 403 on /config (Kong Mesh RBAC) must not
// abort the audit — it becomes a coverage gap and the run is inconclusive.
func TestConfigForbiddenDegradesToGap(t *testing.T) {
	srv := cpServer(t, map[string]http.HandlerFunc{
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":403}`))
		},
	})
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit aborted on /config 403, want graceful degradation: %v", err)
	}
	g, ok := gapForPath(rep, "/config")
	if !ok {
		t.Fatalf("no /config coverage gap recorded; gaps=%v", rep.coverage)
	}
	if !strings.Contains(g.reason, "--token") {
		t.Errorf("/config gap reason should mention --token, got %q", g.reason)
	}
	if rep.status() != StatusInconclusive {
		t.Errorf("status = %q, want %q", rep.status(), StatusInconclusive)
	}
}

// TestGlobalZonesInsightsForbiddenDegradesToGap: on a global CP, a 403 on
// /zones+insights must not abort the fan-out — it becomes a coverage gap.
func TestGlobalZonesInsightsForbiddenDegradesToGap(t *testing.T) {
	srv := cpServer(t, map[string]http.HandlerFunc{
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			// Universal global → no global-on-k8s blocker, so the only finding is the gap.
			writeJSON(w, []byte(`{"mode":"global","environment":"universal"}`))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":403}`))
		},
	})
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit aborted on /zones+insights 403, want graceful degradation: %v", err)
	}
	if rep.cp.Mode != "global" {
		t.Errorf("mode = %q, want global (stamped from /config)", rep.cp.Mode)
	}
	if _, ok := gapForPath(rep, "/zones+insights"); !ok {
		t.Fatalf("no /zones+insights coverage gap recorded; gaps=%v", rep.coverage)
	}
	if rep.status() != StatusInconclusive {
		t.Errorf("status = %q, want %q", rep.status(), StatusInconclusive)
	}
}

// TestGlobalTimeoutDuringCollectionAborts: caller-level timeouts are operational
// failures. They should not be fanned out into one coverage gap per remaining
// collection after audit scope has already been established.
func TestGlobalTimeoutDuringCollectionAborts(t *testing.T) {
	srv := cpServer(t, map[string]http.HandlerFunc{
		"/meshes": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Disabled"}}],"next":null}`))
		},
		"/traffic-permissions": func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(200 * time.Millisecond)
			writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
		},
	})
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	_, err = audit(ctx, c, auditOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("audit error = %v, want context deadline exceeded", err)
	}
}

// TestCollectionReadFailureReturnsPartialReport: once audit scope is established,
// a failed ordinary collection read must not abort the audit. The report keeps
// findings from other collections, records a coverage gap naming the failed
// collection, and becomes inconclusive.
func TestCollectionReadFailureReturnsPartialReport(t *testing.T) {
	srv := cpServer(t, map[string]http.HandlerFunc{
		"/meshes": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Disabled"}}],"next":null}`))
		},
		"/traffic-permissions": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":403}`))
		},
		"/dataplanes": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"total":1,"items":[{"type":"Dataplane","name":"dp-1","mesh":"default","networking":{"transparentProxying":{"reachableServices":["backend_kuma-demo_svc_80"]}}}],"next":null}`))
		},
	})
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit aborted on collection read failure, want partial report: %v", err)
	}
	g, ok := gapForPath(rep, "/traffic-permissions")
	if !ok {
		t.Fatalf("no coverage gap recorded for failed collection; gaps=%v", rep.coverage)
	}
	if !strings.Contains(g.reason, "NOT audited") {
		t.Errorf("gap reason = %q, want NOT audited marker", g.reason)
	}
	model := rep.toModel("")
	if model.Status != StatusInconclusive {
		t.Fatalf("status = %q, want %q", model.Status, StatusInconclusive)
	}
	titles := []string{}
	for _, f := range model.Findings {
		titles = append(titles, f.Title)
	}
	for _, want := range []string{
		"meshServices.mode is not Exclusive",
		"Dataplane uses reachableServices",
	} {
		if !slices.Contains(titles, want) {
			t.Errorf("retained findings missing %q; got titles=%v", want, titles)
		}
	}
}

// TestOptionalCollectionReadFailureDegradesToGap: optional collections still do
// not treat 404 as a gap, but other read failures after scope is established
// must degrade to an inconclusive partial report instead of aborting.
func TestOptionalCollectionReadFailureDegradesToGap(t *testing.T) {
	t.Run("forbidden becomes gap", func(t *testing.T) {
		srv := cpServer(t, map[string]http.HandlerFunc{
			"/meshes": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Disabled"}}],"next":null}`))
			},
			"/meshglobalratelimits": func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"status":403}`))
			},
		})
		c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
		if err != nil {
			t.Fatalf("newClient: %v", err)
		}
		rep, err := audit(context.Background(), c, auditOptions{})
		if err != nil {
			t.Fatalf("audit aborted on optional collection 403, want graceful degradation: %v", err)
		}
		if _, ok := gapForPath(rep, "/meshglobalratelimits"); !ok {
			t.Fatalf("no /meshglobalratelimits coverage gap recorded; gaps=%v", rep.coverage)
		}
		if rep.status() != StatusInconclusive {
			t.Errorf("status = %q, want %q", rep.status(), StatusInconclusive)
		}
	})

	t.Run("not served stays non-gap", func(t *testing.T) {
		srv := cpServer(t, map[string]http.HandlerFunc{
			"/config": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"mode":"zone","environment":"kubernetes","experimental":{"autoReachableServices":false,"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true,"ebpf":{"enabled":false}},"workloadLabels":["app.kubernetes.io/name"]}}}`))
			},
			"/meshes": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}}],"next":null}`))
			},
		})
		c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
		if err != nil {
			t.Fatalf("newClient: %v", err)
		}
		rep, err := audit(context.Background(), c, auditOptions{})
		if err != nil {
			t.Fatalf("audit aborted on optional collection 404, want normal success: %v", err)
		}
		if _, ok := gapForPath(rep, "/meshglobalratelimits"); ok {
			t.Fatalf("unexpected /meshglobalratelimits coverage gap on 404; gaps=%v", rep.coverage)
		}
		if rep.status() != StatusClean {
			t.Errorf("status = %q, want %q", rep.status(), StatusClean)
		}
	})
}
