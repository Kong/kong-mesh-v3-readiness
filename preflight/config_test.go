package preflight

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

// TestControlPlaneConfigDeprecatedSettingReported checks that each removed or
// soon-to-be-default CP setting in GET /config surfaces as the expected finding,
// with the detail rendered in the single fixed shape every config check shares.
func TestControlPlaneConfigDeprecatedSettingReported(t *testing.T) {
	cases := []struct {
		name     string
		config   string
		severity string
		title    string
		detail   string
	}{
		{
			name:     "global on kubernetes",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"global","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Global control plane on Kubernetes",
			detail: cpConfigDetail("mode", "global", "universal"),
		},
		{
			name:     "autoReachableServices",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"autoReachableServices":true,"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "autoReachableServices enabled",
			detail: cpConfigDetail("experimental.autoReachableServices", "true", "false"),
		},
		{
			name:     "ebpf transparent proxy",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true,"ebpf":{"enabled":true}}}}}`,
			severity: "blocker", title: "eBPF transparent proxy enabled",
			detail: cpConfigDetail("runtime.kubernetes.injector.ebpf.enabled", "true", "false"),
		},
		{
			name:     "unified naming off",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":false}}}}`,
			severity: "blocker", title: "Unified resource naming not enabled",
			detail: cpConfigDetail("runtime.kubernetes.injector.unifiedResourceNamingEnabled", "false", "true"),
		},
		{
			name:     "delta xds off",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":false,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Delta xDS not enabled",
			detail: cpConfigDetail("experimental.deltaXds", "false", "true"),
		},
		{
			name:     "inbound tags enabled",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":false,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Inbound tags still enabled",
			detail: cpConfigDetail("experimental.inboundTagsDisabled", "false", "true"),
		},
		{
			name:     "kds event-based watchdog off",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":false}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "KDS event-based watchdog not enabled",
			detail: cpConfigDetail("experimental.kdsEventBasedWatchdog.enabled", "false", "true"),
		},
		{
			name:     "default outbound unrestricted",
			config:   `{"environment":"kubernetes","mode":"zone","defaults":{"allowAllOutbound":true},"experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Default outbound not restricted",
			detail: cpConfigDetail("defaults.allowAllOutbound", "true", "false"),
		},
		{
			// A control plane older than the 2.14 patch that added the switch serves
			// no `defaults.allowAllOutbound` at all; absent reads as the permissive true.
			name:     "default outbound switch absent",
			config:   `{"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Default outbound not restricted",
			detail: cpConfigDetail("defaults.allowAllOutbound", "true", "false"),
		},
		{
			name:     "sidecar containers off",
			config:   `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":false,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
			severity: "blocker", title: "Native sidecar containers not enabled",
			detail: cpConfigDetail("experimental.sidecarContainers", "false", "true"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/config": tc.config})
			f, ok := findFinding(m, tc.severity, cpConfigCategory, tc.title)
			if !ok {
				t.Fatalf("expected %s finding %q, got %+v", tc.severity, tc.title, m.Findings)
			}
			if f.Detail != tc.detail {
				t.Errorf("detail = %q, want %q", f.Detail, tc.detail)
			}
		})
	}
}

// TestControlPlaneConfigInjectorChecksSkippedOffKubernetes verifies the
// injector-only checks (unified naming, eBPF) do not fire on a Universal CP,
// which has no injector, while the environment-agnostic experimental blockers do.
func TestControlPlaneConfigInjectorChecksSkippedOffKubernetes(t *testing.T) {
	m := auditResponses(t, map[string]string{
		"/config": `{"defaults":{"allowAllOutbound":false},"environment":"universal","mode":"zone","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}}}`,
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

	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 30 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	m := rep.toModel("")
	if m.Status != StatusInconclusive {
		t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
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

// TestControlPlaneConfigDetailsShareOneShape guards the contract downstream
// consumers rely on: every actionable Control plane configuration finding states
// its remediation as the same sentence, so none of them can drift back into
// free-form phrasing. The informational no-zones finding a global emits is
// exempt — it reports an observation, not a field to change, and the template
// reads as nonsense there.
func TestControlPlaneConfigDetailsShareOneShape(t *testing.T) {
	shape := regexp.MustCompile(`^the field \S+ value has to be changed from .+ to .+$`)

	for _, tc := range []struct {
		name      string
		responses map[string]string
		want      int
	}{
		{
			name: "zone control plane tripping every config check",
			responses: map[string]string{
				"/config": `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"zone","experimental":{"autoReachableServices":true,"deltaXds":false,"sidecarContainers":false,"inboundTagsDisabled":false,"kdsEventBasedWatchdog":{"enabled":false}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":false,"ebpf":{"enabled":true}}}}}`,
			},
			want: 7,
		},
		{
			name: "global control plane with no zones connected",
			responses: map[string]string{
				"/config":         `{"defaults":{"allowAllOutbound":false},"environment":"kubernetes","mode":"global","experimental":{"deltaXds":true,"sidecarContainers":true,"inboundTagsDisabled":true,"kdsEventBasedWatchdog":{"enabled":true}},"runtime":{"kubernetes":{"injector":{"unifiedResourceNamingEnabled":true}}}}`,
				"/zones+insights": `{"total":0,"items":[],"next":null}`,
			},
			want: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, tc.responses)

			var got int
			for _, f := range m.Findings {
				if f.Category != cpConfigCategory {
					continue
				}
				got++
				if f.Severity != SeverityBlocker {
					continue
				}
				if !shape.MatchString(f.Detail) {
					t.Errorf("finding %q detail %q does not match the unified shape", f.Title, f.Detail)
				}
			}
			if got != tc.want {
				t.Errorf("config findings = %d, want %d (%+v)", got, tc.want, m.Findings)
			}
		})
	}
}
