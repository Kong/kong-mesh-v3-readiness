package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// badK8sConfig is a Kubernetes CP config that trips every data-plane-relevant
// readiness check (4 blockers + 3 warnings).
func badK8sConfig() cpConfig {
	var c cpConfig
	c.Mode = "zone"
	c.Environment = "kubernetes"
	c.Experimental.AutoReachableServices = true                        // blocker
	c.Runtime.Kubernetes.Injector.Ebpf.Enabled = true                  // blocker (k8s)
	c.Runtime.Kubernetes.Injector.UnifiedResourceNamingEnabled = false // blocker (k8s)
	c.Experimental.InboundTagsDisabled = false                         // blocker
	c.Experimental.DeltaXds = false                                    // warning
	c.Experimental.KdsEventBasedWatchdog.Enabled = false               // warning
	c.Experimental.SidecarContainers = false                           // warning
	return c
}

func goodK8sConfig() cpConfig {
	var c cpConfig
	c.Mode = "zone"
	c.Environment = "kubernetes"
	c.Experimental.AutoReachableServices = false
	c.Runtime.Kubernetes.Injector.Ebpf.Enabled = false
	c.Runtime.Kubernetes.Injector.UnifiedResourceNamingEnabled = true
	c.Experimental.InboundTagsDisabled = true
	c.Experimental.DeltaXds = true
	c.Experimental.KdsEventBasedWatchdog.Enabled = true
	c.Experimental.SidecarContainers = true
	return c
}

func TestAddCPConfigFindings(t *testing.T) {
	t.Run("k8s bad config, unqualified examples", func(t *testing.T) {
		a := &auditor{rep: &report{}}
		a.addCPConfigFindings(badK8sConfig(), "")
		if got, want := a.rep.count(blocker), 4; got != want {
			t.Errorf("blockers = %d, want %d", got, want)
		}
		if got, want := a.rep.count(warning), 3; got != want {
			t.Errorf("warnings = %d, want %d", got, want)
		}
		for _, f := range a.rep.findings {
			for _, ex := range f.examples {
				if strings.HasPrefix(ex, "zone ") {
					t.Errorf("unqualified run leaked a zone-prefixed example: %q", ex)
				}
			}
		}
	})

	t.Run("zone-qualified examples", func(t *testing.T) {
		a := &auditor{rep: &report{}}
		a.addCPConfigFindings(badK8sConfig(), "zone-1")
		for _, f := range a.rep.findings {
			for _, ex := range f.examples {
				if !strings.HasPrefix(ex, "zone zone-1: ") {
					t.Errorf("finding %q example not zone-qualified: %q", f.title, ex)
				}
			}
		}
	})

	t.Run("good config is silent", func(t *testing.T) {
		a := &auditor{rep: &report{}}
		a.addCPConfigFindings(goodK8sConfig(), "")
		if n := len(a.rep.findings); n != 0 {
			t.Errorf("good config produced %d findings, want 0", n)
		}
	})

	t.Run("universal gates the injector-only checks", func(t *testing.T) {
		c := badK8sConfig()
		c.Environment = "universal"
		a := &auditor{rep: &report{}}
		a.addCPConfigFindings(c, "")
		// eBPF + unified-naming are injector (k8s) checks; the rest still fire.
		for _, f := range a.rep.findings {
			if f.title == "eBPF transparent proxy enabled" || f.title == "Unified resource naming not enabled" {
				t.Errorf("k8s-gated check %q fired on a Universal CP", f.title)
			}
		}
		if got, want := a.rep.count(blocker), 2; got != want { // autoReachable + inboundTags
			t.Errorf("universal blockers = %d, want %d", got, want)
		}
	})

	t.Run("global-on-k8s only fires for global", func(t *testing.T) {
		a := &auditor{rep: &report{}}
		a.addGlobalOnK8sFinding(badK8sConfig()) // mode=zone -> no-op
		if n := len(a.rep.findings); n != 0 {
			t.Fatalf("global-on-k8s fired for a zone CP (%d findings)", n)
		}
		g := badK8sConfig()
		g.Mode = "global"
		a.addGlobalOnK8sFinding(g)
		if a.rep.count(blocker) != 1 {
			t.Errorf("global-on-k8s did not fire for a global k8s CP")
		}
	})
}

func TestLatestZoneConfig(t *testing.T) {
	sub := func(cfg string) zoneSubscription { return zoneSubscription{Config: cfg} }
	cfgJSON := func(env string) string {
		b, _ := json.Marshal(cpConfig{Mode: "zone", Environment: env})
		return string(b)
	}

	t.Run("returns the freshest subscription with a config", func(t *testing.T) {
		zo := zoneOverview{}
		zo.ZoneInsight.Subscriptions = []zoneSubscription{
			sub(cfgJSON("universal")), sub(cfgJSON("kubernetes")),
		}
		cfg, ok := latestZoneConfig(zo)
		if !ok || cfg.Environment != "kubernetes" {
			t.Errorf("got (%+v, %v), want the last (kubernetes) config", cfg, ok)
		}
	})

	t.Run("skips trailing empty configs", func(t *testing.T) {
		zo := zoneOverview{}
		zo.ZoneInsight.Subscriptions = []zoneSubscription{sub(cfgJSON("kubernetes")), sub("")}
		cfg, ok := latestZoneConfig(zo)
		if !ok || cfg.Environment != "kubernetes" {
			t.Errorf("got (%+v, %v), want the earlier non-empty config", cfg, ok)
		}
	})

	t.Run("no usable config", func(t *testing.T) {
		cases := map[string][]zoneSubscription{
			"no subscriptions": nil,
			"all empty":        {sub(""), sub("")},
			"invalid json":     {sub("{not json")},
		}
		for name, subs := range cases {
			var zo zoneOverview
			zo.ZoneInsight.Subscriptions = subs
			if _, ok := latestZoneConfig(zo); ok {
				t.Errorf("%s: latestZoneConfig returned ok, want false", name)
			}
		}
	})
}
