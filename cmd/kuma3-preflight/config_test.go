package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestControlPlaneConfigDeprecatedSettingReported checks that each removed or
// soon-to-be-default CP setting in GET /config surfaces as the expected finding.
func TestControlPlaneConfigDeprecatedSettingReported(t *testing.T) {
	cases := []struct {
		name     string
		config   string
		severity string
		title    string
	}{
		{
			name:     "global on kubernetes",
			config:   `{"environment":"kubernetes","mode":"global","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Global control plane on Kubernetes",
		},
		{
			name:     "autoReachableServices",
			config:   `{"environment":"kubernetes","mode":"zone","experimental":{"autoReachableServices":true,"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "autoReachableServices enabled",
		},
		{
			name:     "ebpf transparent proxy",
			config:   `{"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true,"ebpf":{"enabled":true}}}}}`,
			severity: "blocker", title: "eBPF transparent proxy enabled",
		},
		{
			name:     "unified naming off",
			config:   `{"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":false}}}}`,
			severity: "blocker", title: "Unified resource naming not enabled",
		},
		{
			name:     "delta xds off",
			config:   `{"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":false,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Delta xDS not enabled",
		},
		{
			name:     "inbound tags enabled",
			config:   `{"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":false,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Inbound tags still enabled",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/config": tc.config})
			if _, ok := findFinding(m, tc.severity, cpConfigCategory, tc.title); !ok {
				t.Errorf("expected %s finding %q, got %+v", tc.severity, tc.title, m.Findings)
			}
		})
	}
}

// TestControlPlaneConfigInjectorChecksSkippedOffKubernetes verifies the
// injector-only checks (unified naming, eBPF) do not fire on a Universal CP,
// which has no injector, while the environment-agnostic experimental blockers do.
func TestControlPlaneConfigInjectorChecksSkippedOffKubernetes(t *testing.T) {
	m := auditResponses(t, map[string]string{
		"/config": `{"environment":"universal","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}}}`,
	})
	for _, title := range []string{"Unified resource naming not enabled", "eBPF transparent proxy enabled", "Global control plane on Kubernetes"} {
		if _, ok := findFinding(m, "blocker", cpConfigCategory, title); ok {
			t.Errorf("injector/k8s check %q must not fire on Universal", title)
		}
	}
	if len(m.Findings) != 0 {
		t.Errorf("a 3.0-ready Universal config should yield no config findings, got %+v", m.Findings)
	}
}

// TestControlPlaneConfigMissingIsCoverageGap verifies that a CP not serving
// /config (404, older builds) is recorded as a coverage gap, not a clean pass.
func TestControlPlaneConfigMissingIsCoverageGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `{"product":"Kuma","version":"2.9.0","mode":"zone"}`)
		case "/config":
			http.NotFound(w, r)
		default:
			_, _ = io.WriteString(w, `{"total":0,"items":[],"next":null}`)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := newClient(srv.URL, "", 30*time.Second)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	m := rep.toModel("")
	if m.Status != statusInconclusive {
		t.Errorf("status = %q, want %q", m.Status, statusInconclusive)
	}
	var found bool
	for _, g := range m.Coverage {
		if g.Path == "/config" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a /config coverage gap, got %+v", m.Coverage)
	}
}
