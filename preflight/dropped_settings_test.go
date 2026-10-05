package preflight

import (
	"encoding/json"
	"testing"
)

// TestDroppedCPSettings covers the CP settings 3.0 silently ignores: each patch
// is decoded onto a clean config through the real /config JSON keys.
func TestDroppedCPSettings(t *testing.T) {
	const (
		kdsTitle    = "KDS watchdog timing moved to multizone.{global,zone}.kds.eventBasedWatchdog"
		issuerTitle = "Zone token issuer switch moved to multizone.global.kds.auth.zoneToken.enableIssuer"
		vipTitle    = "Legacy DNS VIP settings have no effect in 3.0"
	)
	for _, tc := range []struct {
		name, patch, env string
		sev              severity
		title            string
		want             bool
	}{
		{"cache disabled", `{"store":{"cache":{"enabled":false}}}`, "kubernetes", blocker, "Store cache can no longer be disabled", true},
		{"cache enabled", `{"store":{"cache":{"enabled":true}}}`, "kubernetes", blocker, "Store cache can no longer be disabled", false},
		{"custom flush interval", `{"experimental":{"kdsEventBasedWatchdog":{"enabled":true,"flushInterval":"1s","fullResyncInterval":"1m0s"}}}`, "kubernetes", blocker, kdsTitle, true},
		{"custom full resync", `{"experimental":{"kdsEventBasedWatchdog":{"enabled":true,"flushInterval":"5s","fullResyncInterval":"30s"}}}`, "kubernetes", blocker, kdsTitle, true},
		{"default watchdog timing", `{"experimental":{"kdsEventBasedWatchdog":{"enabled":true,"flushInterval":"5s","fullResyncInterval":"1m0s"}}}`, "kubernetes", blocker, kdsTitle, false},
		{"custom timing on disabled watchdog", `{"experimental":{"kdsEventBasedWatchdog":{"enabled":false,"flushInterval":"1s"}}}`, "kubernetes", blocker, kdsTitle, false},
		{"min resync timeout", `{"metrics":{"mesh":{"minResyncTimeout":"5s","maxResyncTimeout":"0s"}}}`, "kubernetes", blocker, "metrics.mesh.minResyncTimeout ignored in 3.0", true},
		{"max resync timeout", `{"metrics":{"mesh":{"minResyncTimeout":"0s","maxResyncTimeout":"1m0s"}}}`, "kubernetes", blocker, "metrics.mesh.maxResyncTimeout ignored in 3.0", true},
		{"unset resync timeout", `{"metrics":{"mesh":{"minResyncTimeout":"0s"}}}`, "kubernetes", blocker, "metrics.mesh.minResyncTimeout ignored in 3.0", false},
		{"zone token issuer off on a zone", `{"dpServer":{"authn":{"zoneProxy":{"zoneToken":{"enableIssuer":false}}}}}`, "universal", blocker, issuerTitle, false},
		{"zone proxy authn none", `{"dpServer":{"authn":{"dpProxy":{"type":"dpToken"},"zoneProxy":{"type":"none"}}}}`, "universal", blocker, "Zone proxies need a dataplane token in 3.0", true},
		{"zone proxy authn none on k8s", `{"dpServer":{"authn":{"dpProxy":{"type":"serviceAccountToken"},"zoneProxy":{"type":"none"}}}}`, "kubernetes", blocker, "Zone proxies need a dataplane token in 3.0", false},
		{"all proxy authn none", `{"dpServer":{"authn":{"dpProxy":{"type":"none"},"zoneProxy":{"type":"none"}}}}`, "universal", blocker, "Zone proxies need a dataplane token in 3.0", false},
		{"outbounds not as VIPs", `{"experimental":{"kubeOutboundsAsVIPs":false}}`, "kubernetes", blocker, "Kubernetes outbounds as VIPs not enabled", true},
		{"outbounds not as VIPs off k8s", `{"experimental":{"kubeOutboundsAsVIPs":false}}`, "universal", blocker, "Kubernetes outbounds as VIPs not enabled", false},
		{"custom DNS CIDR", `{"dnsServer":{"CIDR":"250.0.0.0/8"}}`, "kubernetes", info, vipTitle, true},
		{"default DNS CIDR", `{"dnsServer":{"CIDR":"240.0.0.0/4","serviceVipEnabled":true}}`, "kubernetes", info, vipTitle, false},
		{"service VIPs off", `{"dnsServer":{"serviceVipEnabled":false}}`, "kubernetes", info, vipTitle, true},
		{"tag-first VIP model", `{"experimental":{"useTagFirstVirtualOutboundModel":true}}`, "kubernetes", info, vipTitle, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := goodK8sConfig()
			cfg.Environment = tc.env
			if err := json.Unmarshal([]byte(tc.patch), &cfg); err != nil {
				t.Fatal(err)
			}
			a := &auditor{rep: &collector{}}
			a.addCPConfigFindings(cfg, "")
			got := false
			for _, f := range a.rep.findings {
				got = got || (f.severity == tc.sev && f.title == tc.title)
			}
			if got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, a.rep.findings)
			}
		})
	}
}

// TestDroppedCPSettingsOnGlobal: a global audits its own mode-independent
// settings and the zone token issuer, but not the proxy-serving zone proxy
// authn one.
func TestDroppedCPSettingsOnGlobal(t *testing.T) {
	m := auditResponses(t, map[string]string{
		"/config": `{"mode":"global","environment":"universal","store":{"cache":{"enabled":false}},"dpServer":{"authn":{"dpProxy":{"type":"dpToken"},"zoneProxy":{"type":"none","zoneToken":{"enableIssuer":false}}}}}`,
	})
	if _, ok := findFinding(m, "blocker", cpConfigCategory, "Zone token issuer switch moved to multizone.global.kds.auth.zoneToken.enableIssuer"); !ok {
		t.Errorf("zone token issuer off not flagged on a global; findings: %+v", m.Findings)
	}
	if _, ok := findFinding(m, "blocker", cpConfigCategory, "Store cache can no longer be disabled"); !ok {
		t.Errorf("store cache not flagged on a global; findings: %+v", m.Findings)
	}
	if _, ok := findFinding(m, "blocker", cpConfigCategory, "Zone proxies need a dataplane token in 3.0"); ok {
		t.Errorf("zone proxy authn flagged on a global, which serves no proxies")
	}
}

// TestDeprecatedTransparentProxyFields: a Universal Dataplane still carrying the
// redirect ports or ipFamilyMode is informational (removed in 3.1, not 3.0).
func TestDeprecatedTransparentProxyFields(t *testing.T) {
	const title = "Dataplane configures transparent proxying through deprecated fields"
	for _, tc := range []struct {
		name string
		env  string
		tp   map[string]any
		want bool
	}{
		{"redirect ports", "universal", map[string]any{"redirectPortInbound": 15006, "redirectPortOutbound": 15001}, true},
		{"ip family mode", "universal", map[string]any{"ipFamilyMode": "IPv4"}, true},
		{"reachable backends only", "universal", map[string]any{"reachableBackends": map[string]any{"refs": []any{}}}, false},
		{"kubernetes sidecar", "kubernetes", map[string]any{"redirectPortInbound": 15006, "redirectPortOutbound": 15001}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditDataplane(t, map[string]any{
				"labels":     map[string]any{"kuma.io/env": tc.env, "kuma.io/workload": "dp-1"},
				"networking": map[string]any{"inbound": []any{map[string]any{"port": 8080}}, "transparentProxying": tc.tp},
			})
			if _, got := findFinding(m, "info", "Dataplane networking", title); got != tc.want {
				t.Errorf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
		})
	}
}

// TestUnauthenticatedAccessRoleBinding: a binding naming an unauthenticated
// group is reported with its roles; authenticated groups and users are not.
func TestUnauthenticatedAccessRoleBinding(t *testing.T) {
	const title = "AccessRoleBinding grants roles to unauthenticated callers"
	binding := func(subjects ...map[string]any) string {
		return listBody(t, map[string]any{"type": "AccessRoleBinding", "name": "default", "subjects": subjects, "roles": []any{"viewer", "admin"}})
	}
	group := func(name string) map[string]any { return map[string]any{"type": "Group", "name": name} }
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"mesh unauthenticated", binding(group("mesh-system:authenticated"), group("mesh-system:unauthenticated")), true},
		{"kubernetes unauthenticated", binding(group("system:unauthenticated")), true},
		{"authenticated only", binding(group("mesh-system:authenticated"), group("system:authenticated")), false},
		{"user named like the group", binding(map[string]any{"type": "User", "name": "system:unauthenticated"}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := auditResponses(t, map[string]string{"/access-role-bindings": tc.body})
			f, got := findFinding(m, "info", categoryAccessRoles, title)
			if got != tc.want {
				t.Fatalf("flagged = %v, want %v\nfindings: %+v", got, tc.want, m.Findings)
			}
			if got && (len(f.Examples) != 1 || f.Examples[0].Display() != "default (roles: admin, viewer)") {
				t.Errorf("examples = %v, want [default (roles: admin, viewer)]", f.Examples)
			}
		})
	}
}
