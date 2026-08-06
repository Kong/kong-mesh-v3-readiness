package preflight

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestLatestZoneVersion(t *testing.T) {
	mk := func(vs ...string) zoneOverview {
		var zo zoneOverview
		for _, v := range vs {
			var s zoneSubscription
			s.Version.KumaCp.Version = v
			zo.ZoneInsight.Subscriptions = append(zo.ZoneInsight.Subscriptions, s)
		}
		return zo
	}
	if v, ok := latestZoneVersion(mk("2.13.0", "2.14.0")); !ok || v != "2.14.0" {
		t.Errorf("got (%q,%v), want freshest 2.14.0", v, ok)
	}
	if v, ok := latestZoneVersion(mk("2.14.0", "")); !ok || v != "2.14.0" {
		t.Errorf("got (%q,%v), want earlier non-empty 2.14.0", v, ok)
	}
	if _, ok := latestZoneVersion(mk()); ok {
		t.Errorf("no subscriptions should return ok=false")
	}
	if _, ok := latestZoneVersion(mk("", "")); ok {
		t.Errorf("all-empty versions should return ok=false")
	}
}

// auditVersion audits a stub CP with the version-currency check enabled.
func auditVersion(t *testing.T, latest string, handlers map[string]http.HandlerFunc) *collector {
	t.Helper()
	return auditVersionOpts(t, auditOptions{checkVersionCurrency: true, latestPatch: latest}, handlers)
}

// auditVersionOpts audits a stub CP with the given auditOptions, overriding
// checkVersionCurrency and latestPatch is left to the caller via opts.
func auditVersionOpts(t *testing.T, opts auditOptions, handlers map[string]http.HandlerFunc) *collector {
	t.Helper()
	srv := cpServer(t, handlers)
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	return rep
}

func versionFinding(r *collector) (rawFinding, bool) {
	for _, f := range r.findings {
		if f.category == cpVersionCategory {
			return f, true
		}
	}
	return rawFinding{}, false
}

func hasExample(f rawFinding, want string) bool {
	return slices.Contains(f.examples, want)
}

func TestCheckControlPlaneVersionsConnected(t *testing.T) {
	t.Run("behind latest patch is a blocker", func(t *testing.T) {
		rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"2.9.0","mode":"zone"}`))
			},
		})
		f, ok := versionFinding(rep)
		if !ok {
			t.Fatalf("no %q finding; findings=%v", cpVersionCategory, rep.findings)
		}
		if f.severity != blocker {
			t.Errorf("severity = %v, want blocker", f.severity)
		}
		if !hasExample(f, "control plane (2.9.0)") {
			t.Errorf("examples = %v, want to include the connected CP", f.examples)
		}
	})

	t.Run("current patch is silent", func(t *testing.T) {
		rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0","mode":"zone"}`))
			},
		})
		if _, ok := versionFinding(rep); ok {
			t.Errorf("current CP produced a version finding")
		}
	})
}

func TestCheckControlPlaneVersionsGlobalFanout(t *testing.T) {
	zones := `{"total":2,"items":[
		{"type":"ZoneInsight","name":"zone-a","zoneInsight":{"subscriptions":[{"version":{"kumaCp":{"version":"2.14.0"}}}]}},
		{"type":"ZoneInsight","name":"zone-b","zoneInsight":{"subscriptions":[{"version":{"kumaCp":{"version":"2.13.5"}}}]}}
	],"next":null}`
	rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0","mode":"global"}`))
		},
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"mode":"global","environment":"universal"}`))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(zones))
		},
	})
	f, ok := versionFinding(rep)
	if !ok {
		t.Fatalf("no %q finding; findings=%v", cpVersionCategory, rep.findings)
	}
	if !hasExample(f, "zone zone-b (2.13.5)") {
		t.Errorf("examples = %v, want the behind zone-b", f.examples)
	}
	if hasExample(f, "zone zone-a (2.14.0)") {
		t.Errorf("examples = %v, must not flag the current zone-a", f.examples)
	}
	if hasExample(f, "control plane (2.14.0)") {
		t.Errorf("examples = %v, must not flag the current global CP", f.examples)
	}
}

// A global CP whose /config is unreadable (e.g. RBAC without --token) reports no
// mode (GET / carries none), yet its connected zones must still be version-checked
// — skipping them would be a fake-clean. The fan-out must run on unknown mode.
func TestGlobalVersionFanoutWhenModeUnknown(t *testing.T) {
	zones := `{"total":1,"items":[
		{"type":"ZoneInsight","name":"zone-old","zoneInsight":{"subscriptions":[{"version":{"kumaCp":{"version":"2.11.2"}}}]}}
	],"next":null}`
	rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
		// Default cpServer "/" returns version 2.14.0 with NO mode field.
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden) // mode stays unknown
			_, _ = w.Write([]byte(`{"status":403}`))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(zones))
		},
	})
	if rep.cp.Mode != "" {
		t.Fatalf("precondition: mode should be unknown, got %q", rep.cp.Mode)
	}
	f, ok := versionFinding(rep)
	if !ok {
		t.Fatalf("stale zone silently skipped on a mode-unknown global; findings=%v", rep.findings)
	}
	if !hasExample(f, "zone zone-old (2.11.2)") {
		t.Errorf("examples = %v, want the stale zone-old", f.examples)
	}
}

// When mode is unknown and the CP is actually a zone/standalone, /zones+insights
// returns 404 — "not a global", not a coverage gap. The fan-out is attempted (mode
// unknown) but the 404 must be skipped silently, not recorded as a version gap.
func TestZoneCPNoVersionFanoutGap(t *testing.T) {
	rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
		// Default cpServer "/" carries no mode, so the fan-out is attempted.
		"/zones+insights": func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		},
	})
	if _, ok := gapForPath(rep, "/zones+insights (versions)"); ok {
		t.Errorf("a 404 on /zones+insights must not record a zone-version coverage gap")
	}
}

func TestLatestVersionWrongMinorIsGap(t *testing.T) {
	rep := auditVersion(t, "2.13.5", map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0","mode":"zone"}`))
		},
	})
	if _, ok := gapForPath(rep, "--latest-version"); !ok {
		t.Fatalf("a non-2.14 --latest-version should record a gap; gaps=%v", rep.coverage)
	}
	if _, ok := versionFinding(rep); ok {
		t.Errorf("must not produce a contradictory finding for a wrong-minor baseline")
	}
}

func TestVersionCurrencyUnknownIsGap(t *testing.T) {
	rep := auditVersion(t, "", nil)
	if _, ok := gapForPath(rep, "github.com/kumahq/kuma/releases"); !ok {
		t.Fatalf("empty latest patch should record a coverage gap; gaps=%v", rep.coverage)
	}
	if _, ok := versionFinding(rep); ok {
		t.Errorf("unknown latest must not produce a version finding")
	}
}

func TestVersionCheckOffByDefault(t *testing.T) {
	srv := cpServer(t, nil)
	c, err := newClientWithHTTP(srv.URL, "", &http.Client{Timeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rep, err := audit(context.Background(), c, auditOptions{}) // checkVersionCurrency: false
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, ok := versionFinding(rep); ok {
		t.Errorf("version check ran without being enabled")
	}
	if _, ok := gapForPath(rep, "github.com/kumahq/kuma/releases"); ok {
		t.Errorf("disabled version check recorded a gap")
	}
}

func hasFinding(r *collector, sev severity, category, title string) bool {
	for _, f := range r.findings {
		if f.severity == sev && f.category == category && f.title == title {
			return true
		}
	}
	return false
}

func TestSkipAuditedControlPlaneVersion(t *testing.T) {
	t.Run("stale audited CP is excluded", func(t *testing.T) {
		rep := auditVersionOpts(t, auditOptions{
			checkVersionCurrency: true, latestPatch: "2.14.0", skipAuditedCPVersion: true,
		}, map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"2.9.0","mode":"zone"}`))
			},
		})
		for _, f := range rep.findings {
			if f.category == cpVersionCategory && f.severity == blocker {
				t.Errorf("skipped audited CP must not produce a blocker; got %+v", f)
			}
		}
		if !hasFinding(rep, info, cpVersionCategory, "Audited control plane version check out of scope") {
			t.Errorf("missing out-of-scope info finding; findings=%v", rep.findings)
		}
	})

	t.Run("zone blocker survives, audited global excluded", func(t *testing.T) {
		zones := `{"total":1,"items":[
			{"type":"ZoneInsight","name":"zone-b","zoneInsight":{"subscriptions":[{"version":{"kumaCp":{"version":"2.13.5"}}}]}}
		],"next":null}`
		rep := auditVersionOpts(t, auditOptions{
			checkVersionCurrency: true, latestPatch: "2.14.0", skipAuditedCPVersion: true,
		}, map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"2.9.0","mode":"global"}`))
			},
			"/config": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"mode":"global","environment":"universal"}`))
			},
			"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(zones))
			},
		})
		var blockerFinding rawFinding
		var found bool
		for _, f := range rep.findings {
			if f.category == cpVersionCategory && f.severity == blocker {
				blockerFinding, found = f, true
			}
		}
		if !found {
			t.Fatalf("zone blocker missing; findings=%v", rep.findings)
		}
		if !hasExample(blockerFinding, "zone zone-b (2.13.5)") {
			t.Errorf("examples = %v, want zone-b", blockerFinding.examples)
		}
		if hasExample(blockerFinding, "control plane (2.9.0)") {
			t.Errorf("examples = %v, must not include the excluded audited CP", blockerFinding.examples)
		}
	})

	t.Run("unparseable audited version produces no coverage gap", func(t *testing.T) {
		rep := auditVersionOpts(t, auditOptions{
			checkVersionCurrency: true, latestPatch: "2.14.0", skipAuditedCPVersion: true,
		}, map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"dev","mode":"zone"}`))
			},
		})
		if _, ok := gapForPath(rep, "version (control plane)"); ok {
			t.Errorf("excluded audited CP must not record a version coverage gap; gaps=%v", rep.coverage)
		}
	})

	t.Run("default (flag unset) still flags the audited CP", func(t *testing.T) {
		rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, []byte(`{"product":"Kuma","version":"2.9.0","mode":"zone"}`))
			},
		})
		f, ok := versionFinding(rep)
		if !ok || f.severity != blocker {
			t.Fatalf("default behavior must still flag the audited CP; findings=%v", rep.findings)
		}
		if !hasExample(f, "control plane (2.9.0)") {
			t.Errorf("examples = %v, want the audited CP", f.examples)
		}
	})
}

func TestFlagIfBehindUnparseableIsGap(t *testing.T) {
	a := &auditor{rep: &collector{}}
	a.flagIfBehind("unknown", "control plane", 14, 0, "detail")
	if len(a.rep.findings) != 0 {
		t.Errorf("unparseable version produced a finding, want a gap only")
	}
	if _, ok := gapForPath(a.rep, "version (control plane)"); !ok {
		t.Errorf("unparseable version should record a coverage gap; gaps=%v", a.rep.coverage)
	}
}
