package preflight

import (
	"encoding/json"
	"testing"
)

// badK8sConfig is a Kubernetes CP config that trips every data-plane-relevant
// readiness check (12 blockers, plus the informational outbound-default note).
func badK8sConfig() cpConfig {
	var c cpConfig
	c.Mode = "zone"
	c.Environment = "kubernetes"
	c.Experimental.AutoReachableServices = true                        // blocker
	c.Runtime.Kubernetes.Injector.Ebpf.Enabled = true                  // blocker (k8s)
	c.Runtime.Kubernetes.Injector.UnifiedResourceNamingEnabled = false // blocker (k8s)
	c.Experimental.InboundTagsDisabled = false                         // blocker
	c.Experimental.DeltaXds = false                                    // blocker
	c.Experimental.KdsEventBasedWatchdog.Enabled = false               // blocker
	c.Experimental.SidecarContainers = false                           // blocker
	c.ApiServer.Authn.Type = "adminClientCerts"                        // blocker
	c.ApiServer.Auth.ClientCertsDir = "/etc/kuma/client-certs"         // blocker
	zero := uint32(0)
	c.BootstrapServer.Params.ReadinessPort = &zero // blocker
	c.Experimental.ExposeZoneProxyMetrics = true   // blocker
	c.MonitoringAssignmentServer.Enabled = nil     // blocker (k8s, unset reads as true)
	c.Defaults.RestrictOutbound = nil              // info (unset reads as false)
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
	restricted := true
	c.Defaults.RestrictOutbound = &restricted
	c.ApiServer.Authn.Type = "tokens"
	readiness := uint32(9902)
	c.BootstrapServer.Params.ReadinessPort = &readiness
	mads := false
	c.MonitoringAssignmentServer.Enabled = &mads
	return c
}

func TestAddCPConfigFindings(t *testing.T) {
	t.Run("k8s bad config, unqualified examples", func(t *testing.T) {
		a := &auditor{rep: &collector{}}
		a.addCPConfigFindings(badK8sConfig(), "")
		if got, want := a.rep.count(blocker), 12; got != want {
			t.Errorf("blockers = %d, want %d", got, want)
		}
		for _, f := range a.rep.findings {
			for _, ex := range f.examples {
				if ex.Zone != "" {
					t.Errorf("unqualified run leaked a zone-scoped example: %+v", ex)
				}
			}
		}
	})

	t.Run("zone-qualified examples", func(t *testing.T) {
		a := &auditor{rep: &collector{}}
		a.addCPConfigFindings(badK8sConfig(), "zone-1")
		for _, f := range a.rep.findings {
			for _, ex := range f.examples {
				if ex.Zone != "zone-1" {
					t.Errorf("finding %q example not zone-qualified: %+v", f.title, ex)
				}
			}
		}
	})

	t.Run("good config is silent", func(t *testing.T) {
		a := &auditor{rep: &collector{}}
		a.addCPConfigFindings(goodK8sConfig(), "")
		if n := len(a.rep.findings); n != 0 {
			t.Errorf("good config produced %d findings, want 0", n)
		}
	})

	t.Run("universal gates the injector-only checks", func(t *testing.T) {
		c := badK8sConfig()
		c.Environment = "universal"
		a := &auditor{rep: &collector{}}
		a.addCPConfigFindings(c, "")
		// eBPF + unified-naming are injector (k8s) checks and MADS stays served
		// on Universal; the rest still fire.
		for _, f := range a.rep.findings {
			switch f.title {
			case "eBPF transparent proxy enabled", "Unified resource naming not enabled", "MADS not served on Kubernetes in 3.0":
				t.Errorf("k8s-gated check %q fired on a Universal CP", f.title)
			}
		}
		// 12 minus eBPF, unified naming and MADS.
		if got, want := a.rep.count(blocker), 9; got != want {
			t.Errorf("universal blockers = %d, want %d", got, want)
		}
	})

	t.Run("global-on-k8s only fires for global", func(t *testing.T) {
		a := &auditor{rep: &collector{}}
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
