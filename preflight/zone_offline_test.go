package preflight

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const offlineZoneTitle = "Zone control plane offline"

const globalConfigJSON = `{"mode": "global", "environment": "universal"}`

// zoneOverviewItem builds a GET /zones+insights item. nil subscriptions omits
// zoneInsight entirely, the shape a zone that never connected has.
func zoneOverviewItem(name string, subscriptions []any) map[string]any {
	item := map[string]any{"type": "ZoneOverview", "name": name}
	if subscriptions != nil {
		item["zoneInsight"] = map[string]any{"subscriptions": subscriptions}
	}
	return item
}

func openSubscription(extra map[string]any) map[string]any {
	sub := map[string]any{"connectTime": "2026-06-22T10:00:00Z"}
	maps.Copy(sub, extra)
	return sub
}

func closedSubscription(extra map[string]any) map[string]any {
	sub := openSubscription(extra)
	sub["disconnectTime"] = "2026-06-23T09:00:00Z"
	return sub
}

// TestOfflineZoneIsBlocker covers MESH-107: a zone the global cannot reach over
// KDS carried no config or version, which used to be two coverage gaps. Gaps made
// the whole run inconclusive, so a consumer that refuses inconclusive scans (the
// Mesh-in-Konnect readiness translation) failed report creation and the operator
// lost every other finding. An offline zone is a fact to act on, so it is one
// blocker per zone and the rest of the report stays usable.
func TestOfflineZoneIsBlocker(t *testing.T) {
	cases := map[string]map[string]any{
		"never connected": zoneOverviewItem("hellozone", nil),
		"no subscription open": zoneOverviewItem("hellozone", []any{
			closedSubscription(nil),
		}),
		"only stale data left behind": zoneOverviewItem("hellozone", []any{
			closedSubscription(map[string]any{"config": `{"mode": "zone", "environment": "kubernetes"}`, "version": map[string]any{"kumaCp": map[string]any{"version": "2.9.0"}}}),
		}),
	}

	for name, zone := range cases {
		t.Run(name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{
				"/config":         globalConfigJSON,
				"/zones+insights": listBody(t, zone),
			})

			f, ok := findFinding(m, "blocker", cpConfigCategory, offlineZoneTitle)
			if !ok {
				t.Fatalf("offline zone not reported as a blocker\nfindings: %+v", m.Findings)
			}
			if f.Group != "control_plane" {
				t.Errorf("group = %q, want control_plane", f.Group)
			}
			if f.Count != 1 {
				t.Errorf("count = %d, want 1", f.Count)
			}
			if !slices.Equal(f.Examples, []string{"zone hellozone"}) {
				t.Errorf("examples = %v, want [zone hellozone]", f.Examples)
			}
			for _, g := range m.Coverage {
				if strings.Contains(g.Path, "hellozone") {
					t.Errorf("offline zone also recorded a coverage gap %q — that would make the run inconclusive: %+v", g.Path, m.Coverage)
				}
			}
			if m.Status != StatusBlockers {
				t.Errorf("status = %q, want %q", m.Status, StatusBlockers)
			}
		})
	}
}

// TestOfflineZoneStaleConfigIsNotAudited: a dropped zone's last reported config is
// a snapshot of a control plane that is not running, so it must not be audited as
// if it were current. The offline blocker is the only thing said about the zone.
func TestOfflineZoneStaleConfigIsNotAudited(t *testing.T) {
	stale := `{"mode": "zone", "environment": "kubernetes", "experimental": {"inboundTagsDisabled": false}}`
	m := auditResponses(t, map[string]string{
		"/config": globalConfigJSON,
		"/zones+insights": listBody(t,
			zoneOverviewItem("hellozone", []any{closedSubscription(map[string]any{"config": stale})}),
		),
	})

	if _, ok := findFinding(m, "blocker", cpConfigCategory, offlineZoneTitle); !ok {
		t.Fatalf("offline zone not reported\nfindings: %+v", m.Findings)
	}
	if f, ok := findFinding(m, "blocker", cpConfigCategory, "Inbound tags still enabled"); ok {
		t.Errorf("audited a dropped zone's stale config as current: %+v", f)
	}
}

// TestOfflineZoneFlaggedOnceAcrossFanouts keeps the config and version fan-outs
// from counting one offline zone twice: both read the same zone insight and both
// find nothing to audit.
func TestOfflineZoneFlaggedOnceAcrossFanouts(t *testing.T) {
	rep := auditVersion(t, "2.14.0", map[string]http.HandlerFunc{
		"/config": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(globalConfigJSON))
		},
		"/zones+insights": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, []byte(listBody(t,
				zoneOverviewItem("hellozone", []any{closedSubscription(map[string]any{"config": ""})}),
				zoneOverviewItem("east", []any{openSubscription(map[string]any{
					"config":  readyConfigJSON,
					"version": map[string]any{"kumaCp": map[string]any{"version": "2.14.0"}},
				})}),
			)))
		},
	})

	var found []rawFinding
	for _, f := range rep.findings {
		if f.title == offlineZoneTitle {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d %q findings, want exactly 1: %+v", len(found), offlineZoneTitle, found)
	}
	if found[0].count != 1 {
		t.Errorf("count = %d, want 1 (two fan-outs reported the same zone)", found[0].count)
	}
	if !slices.Equal(found[0].examples, []string{"zone hellozone"}) {
		t.Errorf("examples = %v, want [zone hellozone]", found[0].examples)
	}
	if _, ok := gapForPath(rep, "/zones+insights (hellozone)"); ok {
		t.Errorf("config fan-out recorded a coverage gap for the offline zone: %+v", rep.coverage)
	}
	if _, ok := gapForPath(rep, "/zones+insights (hellozone, version)"); ok {
		t.Errorf("version fan-out recorded a coverage gap for the offline zone: %+v", rep.coverage)
	}
	if rep.status() != StatusBlockers {
		t.Errorf("status = %q, want %q", rep.status(), StatusBlockers)
	}
}

// TestOnlineZoneWithoutConfigStaysCoverageGap keeps the gap for the case it was
// meant for: a zone that is connected but reported nothing to audit. The audit
// cannot tell whether that zone is clean, so the run stays inconclusive.
func TestOnlineZoneWithoutConfigStaysCoverageGap(t *testing.T) {
	m := auditResponses(t, map[string]string{
		"/config": globalConfigJSON,
		"/zones+insights": listBody(t,
			zoneOverviewItem("east", []any{openSubscription(map[string]any{"config": ""})}),
		),
	})

	if _, ok := findFinding(m, "blocker", cpConfigCategory, offlineZoneTitle); ok {
		t.Errorf("a connected zone was reported as offline: %+v", m.Findings)
	}
	var gapped bool
	for _, g := range m.Coverage {
		if g.Path == "/zones+insights (east)" {
			gapped = true
		}
	}
	if !gapped {
		t.Errorf("no coverage gap for a connected zone that reported no config: %+v", m.Coverage)
	}
	if m.Status != StatusInconclusive {
		t.Errorf("status = %q, want %q", m.Status, StatusInconclusive)
	}
}

// TestOfflineZonesAccumulateInOneFinding keeps one finding with one example per
// offline zone rather than a finding per zone.
func TestOfflineZonesAccumulateInOneFinding(t *testing.T) {
	m := auditResponses(t, map[string]string{
		"/config": globalConfigJSON,
		"/zones+insights": listBody(t,
			zoneOverviewItem("hellozone", nil),
			zoneOverviewItem("west", nil),
		),
	})

	f, ok := findFinding(m, "blocker", cpConfigCategory, offlineZoneTitle)
	if !ok {
		t.Fatalf("offline zones not reported\nfindings: %+v", m.Findings)
	}
	if f.Count != 2 {
		t.Errorf("count = %d, want 2", f.Count)
	}
	if want := []string{"zone hellozone", "zone west"}; !slices.Equal(f.Examples, want) {
		t.Errorf("examples = %v, want %v", f.Examples, want)
	}
}
