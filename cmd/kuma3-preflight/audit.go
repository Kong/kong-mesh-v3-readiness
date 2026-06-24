package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// legacyType is a resource kind removed in Kuma 3.0; any instance is a blocker.
type legacyType struct {
	wsPath      string
	kind        string
	replacement string
}

// legacyMeshScoped lists removed mesh-scoped resources (classic policies + resources).
var legacyMeshScoped = []legacyType{
	{"traffic-permissions", "TrafficPermission", "MeshTrafficPermission (rules + spiffeID)"},
	{"traffic-routes", "TrafficRoute", "MeshHTTPRoute / MeshTCPRoute"},
	{"traffic-logs", "TrafficLog", "MeshAccessLog"},
	{"traffic-traces", "TrafficTrace", "MeshTrace"},
	{"fault-injections", "FaultInjection", "MeshFaultInjection"},
	{"health-checks", "HealthCheck", "MeshHealthCheck"},
	{"circuit-breakers", "CircuitBreaker", "MeshCircuitBreaker"},
	{"retries", "Retry", "MeshRetry"},
	{"timeouts", "Timeout", "MeshTimeout"},
	{"rate-limits", "RateLimit", "MeshRateLimit"},
	{"proxytemplates", "ProxyTemplate", "MeshProxyPatch"},
	{"virtual-outbounds", "VirtualOutbound", "unified naming + MeshService hostnames"},
	{"external-services", "ExternalService", "MeshExternalService"},
	{"meshgateways", "MeshGateway", "delegated gateway (Kong / third-party)"},
	{"meshgatewayroutes", "MeshGatewayRoute", "delegated gateway (Kong / third-party)"},
}

// newPolicyPaths are targetRef policies scanned for deprecated field usage.
var newPolicyPaths = []string{
	"meshtrafficpermissions", "meshfaultinjections", "meshtlses", "meshaccesslogs",
	"meshratelimits", "meshcircuitbreakers", "meshtimeouts", "meshhttproutes",
	"meshtcproutes", "meshretries", "meshhealthchecks", "meshloadbalancingstrategies",
	"meshproxypatches", "meshmetrics", "meshtraces", "meshpassthroughs",
}

var allowedTopLevelTargetRefKinds = map[string]bool{"Mesh": true, "Dataplane": true}

// allowedToTargetRefKinds is the permissive union of `to[].targetRef` kinds 3.0
// keeps for at least some policy types: `Mesh` (all outbound — the canonical
// default-policy form and the only kind permitted for MeshGateway-targeted
// policies), the Mesh*Service kinds and MeshHTTPRoute. 3.0 drops the subset/selector
// kinds (MeshSubset, MeshServiceSubset) and MeshGateway, which are what this flags.
// A single union (rather than a per-policy-type set) is safe: the CP rejects any
// per-policy-invalid kind at admission, so a kept-here-but-invalid-there combination
// cannot exist on an audited CP and this never yields a false negative.
var allowedToTargetRefKinds = map[string]bool{
	"Mesh": true, "MeshService": true, "MeshExternalService": true,
	"MeshMultiZoneService": true, "MeshHTTPRoute": true,
}

const exampleCap = 10

// policyRoleLabel marks CP-managed default policies. They use deprecated
// constructs (from, to: Mesh, proxyTypes) and must be updated before upgrading to
// 3.0, so the audit still flags them — marked as system-managed.
const policyRoleLabel = "kuma.io/policy-role"

func isSystem(it resourceItem) bool {
	return it.Labels[policyRoleLabel] == "system"
}

// auditOptions configures one audit run.
type auditOptions struct {
	meshFilter string
	// inspectDataplanes is the cap on how many dataplanes' Envoy config dumps to
	// fetch (0 = skip the expensive per-proxy inspection entirely).
	inspectDataplanes int
	// checkVersionCurrency enables the control-plane version-currency check.
	checkVersionCurrency bool
	// latestPatch is the latest 2.x patch to compare against (resolved by the
	// caller from --latest-version or the GitHub lookup; "" = could not determine).
	latestPatch string
}

type auditor struct {
	c                    *client
	meshFilter           string
	inspectDataplanes    int
	checkVersionCurrency bool
	latestPatch          string
	rep                  *report

	// /zones+insights is read by both the config and version fan-outs on a global;
	// memoize the (single) fetch so one global audit makes one round-trip for it.
	zonesItems  []resourceItem
	zonesFound  bool
	zonesErr    error
	zonesCached bool
}

// zoneInsights fetches /zones+insights once and caches the result (items, whether
// the endpoint was served, and any transport error) so the config and version
// fan-outs share a single round-trip.
func (a *auditor) zoneInsights(ctx context.Context) ([]resourceItem, bool, error) {
	if !a.zonesCached {
		a.zonesItems, a.zonesFound, a.zonesErr = a.c.list(ctx, "/zones+insights")
		a.zonesCached = true
	}
	return a.zonesItems, a.zonesFound, a.zonesErr
}

func audit(ctx context.Context, c *client, opts auditOptions) (*report, error) {
	idx, err := c.index(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to control plane: %w", err)
	}
	// A non-Kuma endpoint can answer GET / with 200 and an empty/foreign body.
	// Refuse to audit it rather than emit a misleading clean report.
	if idx.Version == "" {
		return nil, fmt.Errorf("endpoint at %s does not look like a Kuma control plane (GET / returned no version)", c.base)
	}

	a := &auditor{
		c: c, meshFilter: opts.meshFilter, inspectDataplanes: opts.inspectDataplanes,
		checkVersionCurrency: opts.checkVersionCurrency, latestPatch: opts.latestPatch,
		rep: &report{cp: idx},
	}

	meshes, found, err := c.list(ctx, "/meshes")
	if err != nil {
		return nil, fmt.Errorf("listing meshes: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("GET /meshes returned 404; is %s a Kuma control plane?", c.base)
	}
	for _, m := range meshes {
		if opts.meshFilter != "" && m.Name != opts.meshFilter {
			continue
		}
		a.rep.meshes = append(a.rep.meshes, m.Name)
		a.checkMeshSettings(m)
		a.checkName(m, "Mesh")
	}
	// A --mesh that matches nothing must not pass as a clean audit.
	if opts.meshFilter != "" && len(a.rep.meshes) == 0 {
		return nil, fmt.Errorf("mesh %q not found on the control plane", opts.meshFilter)
	}

	for _, check := range []func(context.Context) error{
		a.checkLegacyResources, a.checkNewPolicies, a.checkDataplanes,
		a.checkZoneProxies, a.checkResourceNames, a.checkMeshTrust,
		a.checkControlPlaneConfig, a.checkControlPlaneVersions,
		a.checkDataplaneVersions, a.checkDataplaneEnvoyConfig,
	} {
		if err := check(ctx); err != nil {
			return nil, err
		}
	}
	a.rep.manual = buildManualChecks(a.rep.k8sObserved)
	return a.rep, nil
}

// scopedPath returns the list path for a mesh-scoped resource, honoring --mesh.
// The mesh name is untrusted CLI input, so it is percent-escaped.
func (a *auditor) scopedPath(wsPath string) string {
	if a.meshFilter != "" {
		return "/meshes/" + url.PathEscape(a.meshFilter) + "/" + wsPath
	}
	return "/" + wsPath
}

// listColl lists a collection and records a coverage gap (instead of silently
// treating it as empty) when the endpoint is not reachable.
func (a *auditor) listColl(ctx context.Context, path string) ([]resourceItem, error) {
	items, found, err := a.c.list(ctx, path)
	if err != nil {
		return nil, err
	}
	if !found {
		a.rep.addGap(path, "endpoint returned 404 — NOT audited")
		return nil, nil
	}
	return items, nil
}

// listIfServed lists a collection, returning nil when the endpoint is
// unregistered (404) — for resource types newer than the CP may serve, where a
// 404 is "not applicable", not a coverage gap (cf. listColl).
func (a *auditor) listIfServed(ctx context.Context, path string) ([]resourceItem, error) {
	items, found, err := a.c.list(ctx, path)
	if err != nil || !found {
		return nil, err
	}
	return items, nil
}

// unmarshalSpec decodes the resource spec into v, recording a parse error +
// blocker (and returning false) when the spec is malformed. ref is supplied by
// the caller so system-tagging applies where relevant.
func (a *auditor) unmarshalSpec(it resourceItem, v any, ref string) bool {
	if err := json.Unmarshal(it.specBytes(), v); err != nil {
		a.rep.parseErrors++
		a.rep.add(blocker, "Unparseable resources", it.Type+" spec could not be parsed",
			"Could not parse this resource; audit it manually before upgrading.", ref)
		return false
	}
	return true
}

// ref formats the example reference for a flagged resource, marking CP-managed
// (policy-role: system) ones so the operator knows which defaults to update. It is
// side-effect free: the system tally is kept by countSystem, which counts a
// resource only when it actually yields a finding (ref is computed eagerly, before
// the checks run, so counting here would over-report resources that turn out clean).
func (a *auditor) ref(it resourceItem) string {
	if isSystem(it) {
		return qualified(it) + " (system — CP-managed, update before 3.0)"
	}
	return qualified(it)
}

// countSystem records a CP-managed (policy-role: system) resource in the system
// tally exactly once, and only when it produced at least one finding while being
// processed (total grew past totalBefore). This keeps the "N CP-managed resources"
// summary aligned with the findings the operator must act on, not every system
// resource scanned.
func (a *auditor) countSystem(it resourceItem, totalBefore int) {
	if isSystem(it) && a.rep.total > totalBefore {
		a.rep.systemFindings++
	}
}

func (a *auditor) checkMeshSettings(m resourceItem) {
	var spec meshSpec
	_ = json.Unmarshal(m.specBytes(), &spec) // Mesh inlines its spec at the top level
	ref := func(field string) string { return m.Name + " (" + field + ")" }

	if spec.Mtls != nil && (spec.Mtls.EnabledBackend != "" || len(spec.Mtls.Backends) > 0) {
		a.rep.add(blocker, "Mesh object settings", "Inline mTLS on Mesh",
			"Migrate `mesh.mtls` to MeshIdentity + MeshTrust.", ref("mtls"))
	}
	if spec.Networking != nil && spec.Networking.Outbound != nil && spec.Networking.Outbound.Passthrough != nil {
		a.rep.add(blocker, "Mesh object settings", "Passthrough on Mesh",
			"`mesh.networking.outbound.passthrough` is removed; use MeshPassthrough.", ref("networking.outbound.passthrough"))
	}
	if spec.Routing != nil {
		if spec.Routing.ZoneEgress != nil {
			a.rep.add(blocker, "Mesh object settings", "routing.zoneEgress on Mesh",
				"`mesh.routing.zoneEgress` is removed.", ref("routing.zoneEgress"))
		}
		if spec.Routing.DefaultForbidMeshExternalServiceAccess != nil {
			a.rep.add(blocker, "Mesh object settings", "defaultForbidMeshExternalServiceAccess on Mesh",
				"`mesh.routing.defaultForbidMeshExternalServiceAccess` is removed.", ref("routing.defaultForbidMeshExternalServiceAccess"))
		}
		if spec.Routing.LocalityAwareLoadBalancing != nil {
			a.rep.add(blocker, "Mesh object settings", "localityAwareLoadBalancing on Mesh",
				"Replace with MeshLoadBalancingStrategy.", ref("routing.localityAwareLoadBalancing"))
		}
	}
	for _, c := range []struct {
		present              bool
		title, detail, field string
	}{
		{hasJSON(spec.Metrics), "Inline metrics on Mesh", "Replace `mesh.metrics` with the MeshMetric policy.", "metrics"},
		{hasJSON(spec.Tracing), "Inline tracing on Mesh", "Replace `mesh.tracing` with the MeshTrace policy.", "tracing"},
		{hasJSON(spec.Logging), "Inline logging on Mesh", "Replace `mesh.logging` with the MeshAccessLog policy.", "logging"},
		{hasJSON(spec.Constraints), "Mesh membership constraints", "`mesh.constraints` (membership) is removed.", "constraints"},
	} {
		if c.present {
			a.rep.add(blocker, "Mesh object settings", c.title, c.detail, ref(c.field))
		}
	}
	mode := ""
	if spec.MeshServices != nil {
		mode = spec.MeshServices.Mode
	}
	if mode != "Exclusive" {
		shown := mode
		if shown == "" {
			shown = "Disabled"
		}
		a.rep.add(blocker, "MeshService mode", "meshServices.mode is not Exclusive",
			"3.0 requires `meshServices.mode: Exclusive` (it gates Zone Proxy, MeshIdentity and disables legacy kuma.io/service routing); migrate before upgrading (current: "+shown+").", m.Name)
	}
}

func (a *auditor) checkLegacyResources(ctx context.Context) error {
	for _, lt := range legacyMeshScoped {
		items, err := a.listColl(ctx, a.scopedPath(lt.wsPath))
		if err != nil {
			return fmt.Errorf("listing %s: %w", lt.wsPath, err)
		}
		for _, it := range items {
			before := a.rep.total
			a.rep.add(blocker, "Removed resources", lt.kind+" (removed in 3.0)",
				"Replace with "+lt.replacement+".", a.ref(it))
			a.countSystem(it, before)
		}
	}
	return nil
}

func (a *auditor) checkNewPolicies(ctx context.Context) error {
	for _, wsPath := range newPolicyPaths {
		items, err := a.listColl(ctx, a.scopedPath(wsPath))
		if err != nil {
			return fmt.Errorf("listing %s: %w", wsPath, err)
		}
		for _, it := range items {
			before := a.rep.total
			ref := a.ref(it)
			var spec policySpec
			if !a.unmarshalSpec(it, &spec, ref) {
				a.countSystem(it, before)
				continue
			}
			if len(spec.From) > 0 {
				a.rep.add(blocker, "Policy `from` field", it.Type+" uses `from`",
					"Rewrite `from` as `rules` (with spiffeID where applicable).", ref)
			}
			if spec.TargetRef != nil {
				if k := spec.TargetRef.Kind; k != "" && !allowedTopLevelTargetRefKinds[k] {
					a.rep.add(blocker, "Top-level targetRef kind", it.Type+" top-level targetRef.kind="+k,
						"Top-level targetRef must be Mesh or Dataplane; use labels.", ref)
				}
				if len(spec.TargetRef.ProxyTypes) > 0 {
					a.rep.add(blocker, "targetRef proxyTypes", it.Type+" uses targetRef.proxyTypes",
						"`proxyTypes` is removed (gateway support dropped).", ref)
				}
			}
			for _, to := range spec.To {
				if k := to.TargetRef.Kind; k != "" && !allowedToTargetRefKinds[k] {
					a.rep.add(blocker, "`to` targetRef kind", it.Type+" to[].targetRef.kind="+k,
						"`to` no longer accepts subset/selector or MeshGateway kinds; target Mesh, a Mesh*Service, or MeshHTTPRoute.", ref)
				}
			}
			a.checkPolicyFields(it, ref)
			a.countSystem(it, before)
		}
	}
	return nil
}

// checkPolicyFields flags per-policy deprecated fields visible in the spec but not
// covered by the generic from/targetRef/to checks. These are documented field
// deprecations/relocations; like every finding they are blockers. ref is reused
// from the caller so a system policy is counted once.
func (a *auditor) checkPolicyFields(it resourceItem, ref string) {
	spec := it.specBytes()
	switch it.Type {
	case "MeshAccessLog":
		var s struct {
			To []struct {
				Default backendConf `json:"default"`
			} `json:"to"`
			From []struct {
				Default backendConf `json:"default"`
			} `json:"from"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		confs := make([]backendConf, 0, len(s.To)+len(s.From))
		for _, t := range s.To {
			confs = append(confs, t.Default)
		}
		for _, f := range s.From {
			confs = append(confs, f.Default)
		}
		if hasOtelEndpoint(confs...) {
			a.addOtelEndpoint(it.Type, ref)
		}
	case "MeshTrace", "MeshMetric":
		var s struct {
			Default backendConf `json:"default"`
		}
		if json.Unmarshal(spec, &s) == nil && hasOtelEndpoint(s.Default) {
			a.addOtelEndpoint(it.Type, ref)
		}
	case "MeshHealthCheck":
		var s struct {
			To []struct {
				Default struct {
					HealthyPanicThreshold *json.RawMessage `json:"healthyPanicThreshold"`
				} `json:"default"`
			} `json:"to"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		for _, t := range s.To {
			if t.Default.HealthyPanicThreshold != nil {
				a.rep.add(blocker, "Relocated policy fields", "MeshHealthCheck uses healthyPanicThreshold",
					"`healthyPanicThreshold` moves to MeshCircuitBreaker in 3.0.", ref)
				break
			}
		}
	case "MeshLoadBalancingStrategy":
		var s struct {
			To []struct {
				Default struct {
					LoadBalancer *struct {
						RingHash *hashContainer `json:"ringHash"`
						Maglev   *hashContainer `json:"maglev"`
					} `json:"loadBalancer"`
				} `json:"default"`
			} `json:"to"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		var relocated, sourceIP bool
		for _, t := range s.To {
			lb := t.Default.LoadBalancer
			if lb == nil {
				continue
			}
			for _, hc := range []*hashContainer{lb.RingHash, lb.Maglev} {
				if hc == nil || len(hc.HashPolicies) == 0 {
					continue
				}
				relocated = true
				for _, hp := range hc.HashPolicies {
					if hp.Type == "SourceIP" {
						sourceIP = true
					}
				}
			}
		}
		if relocated {
			a.rep.add(blocker, "Relocated policy fields", "MeshLoadBalancingStrategy nests hashPolicies under loadBalancer",
				"Move `loadBalancer.{ringHash,maglev}.hashPolicies` up to `to[].default.hashPolicies`.", ref)
		}
		if sourceIP {
			a.rep.add(blocker, "Relocated policy fields", "MeshLoadBalancingStrategy uses SourceIP hash policy",
				"The `SourceIP` hash policy type is deprecated; use `Connection`.", ref)
		}
	}
}

func (a *auditor) addOtelEndpoint(typ, ref string) {
	a.rep.add(blocker, "OpenTelemetry endpoint", typ+" uses OpenTelemetry `endpoint`",
		"The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).", ref)
}

func (a *auditor) checkDataplanes(ctx context.Context) error {
	items, err := a.listColl(ctx, a.scopedPath("dataplanes"))
	if err != nil {
		return fmt.Errorf("listing dataplanes: %w", err)
	}
	for _, it := range items {
		var spec dataplaneSpec
		if !a.unmarshalSpec(it, &spec, qualified(it)) {
			continue
		}
		// A k8s-injected proxy proves Kubernetes is in the estate even when /config
		// is gated (Kong Mesh RBAC) and could not report the environment.
		if it.Labels["kuma.io/env"] == "kubernetes" {
			a.rep.k8sObserved = true
		}
		// Universal-only: the kuma.io/workload label drives Workload generation (the
		// 3.0 metrics/traces grouping dimension); without it the CP generates no
		// Workload for this proxy. On Kubernetes the injector sets it from the pod,
		// so only flag non-k8s dataplanes that are missing it.
		if it.Labels["kuma.io/env"] != "kubernetes" && it.Labels["kuma.io/workload"] == "" {
			a.rep.add(blocker, "Workload grouping", "Universal Dataplane missing kuma.io/workload label",
				"On Universal the `kuma.io/workload` label groups proxies into a Workload (the 3.0 metrics/traces dimension); without it no Workload is generated for this proxy. Add a `kuma.io/workload` label.", qualified(it))
		}
		// Universal-only: spec.probes is removed in 3.0. On Kubernetes probes are
		// derived from the pod and need no action, so only flag non-k8s dataplanes.
		if hasJSON(spec.Probes) && it.Labels["kuma.io/env"] != "kubernetes" {
			a.rep.add(blocker, "Dataplane probes", "Dataplane has a probes section",
				"Dataplane `spec.probes` is removed for Universal in 3.0 (app-probe-proxy supersedes it).", qualified(it))
		}
		// A per-proxy metrics backend (on k8s, translated from the deprecated
		// `prometheus.metrics.kuma.io/*` pod annotations) moves to MeshMetric.
		if hasJSON(spec.Metrics) {
			a.rep.add(blocker, "Dataplane metrics", "Dataplane has a per-proxy metrics override",
				"`Dataplane.spec.metrics` (from `prometheus.metrics.kuma.io/*` annotations on k8s) is deprecated; move per-proxy metrics to the MeshMetric policy.", qualified(it))
		}
		if spec.Networking == nil {
			continue
		}
		if tp := spec.Networking.TransparentProxying; tp != nil && len(tp.ReachableServices) > 0 {
			a.rep.add(blocker, "reachableServices", "Dataplane uses reachableServices",
				"Replace `reachableServices` with `reachableBackends` (MeshService-based).", qualified(it))
		}
		if hasJSON(spec.Networking.Gateway) {
			a.rep.add(blocker, "Gateway in Dataplane", "Dataplane has a gateway section",
				"The Dataplane `networking.gateway` section is removed; use a delegated gateway.", qualified(it))
		}
	}
	return nil
}

func (a *auditor) checkZoneProxies(ctx context.Context) error {
	for _, wsPath := range []string{"zoneingresses", "zoneegresses"} {
		items, err := a.listColl(ctx, "/"+wsPath)
		if err != nil {
			return fmt.Errorf("listing %s: %w", wsPath, err)
		}
		for _, it := range items {
			a.rep.add(blocker, "Zone proxies", wsPath+" present",
				"Separate ZoneIngress/ZoneEgress resources are replaced by the unified Zone Proxy (Listener types embedded in the Dataplane), which functions only in `meshServices.mode: Exclusive`; plan the migration before upgrading to 3.0.", it.Name)
		}
	}
	return nil
}

// checkResourceNames flags resource names that are not valid RFC-1035 DNS labels
// (deprecated in 3.0). These resource types are newer than the legacy set; a 404
// means the CP version does not serve them, which is not a coverage gap.
func (a *auditor) checkResourceNames(ctx context.Context) error {
	for _, rc := range []struct{ wsPath, kind string }{
		{"meshservices", "MeshService"},
		{"meshexternalservices", "MeshExternalService"},
		{"meshmultizoneservices", "MeshMultiZoneService"},
	} {
		items, err := a.listIfServed(ctx, a.scopedPath(rc.wsPath))
		if err != nil {
			return fmt.Errorf("listing %s: %w", rc.wsPath, err)
		}
		for _, it := range items {
			a.checkName(it, rc.kind)
		}
	}
	return nil
}

// checkMeshTrust flags MeshTrust resources still carrying the deprecated
// spec.origin (moved to status.origin in 3.0).
func (a *auditor) checkMeshTrust(ctx context.Context) error {
	items, err := a.listIfServed(ctx, a.scopedPath("meshtrusts"))
	if err != nil {
		return fmt.Errorf("listing meshtrusts: %w", err)
	}
	for _, it := range items {
		var spec struct {
			Origin json.RawMessage `json:"origin"`
		}
		if json.Unmarshal(it.specBytes(), &spec) == nil && hasJSON(spec.Origin) {
			a.rep.add(blocker, "Relocated policy fields", "MeshTrust uses spec.origin",
				"`spec.origin` is deprecated; it moves to `status.origin` in 3.0.", qualified(it))
		}
	}
	return nil
}

// cpConfig captures only the control-plane settings the readiness checks inspect.
// The full GET /config payload is large and carries secrets (e.g. a masked DB
// password); decode just these fields (cf. the resource decode anti-pattern) so
// unknown fields are ignored and the body never has to be echoed.
type cpConfig struct {
	Mode         string `json:"mode"`
	Environment  string `json:"environment"`
	Experimental struct {
		AutoReachableServices bool `json:"autoReachableServices"`
		DeltaXds              bool `json:"deltaXds"`
		SidecarContainers     bool `json:"sidecarContainers"`
		InboundTagsDisabled   bool `json:"inboundTagsDisabled"`
		KdsEventBasedWatchdog struct {
			Enabled bool `json:"enabled"`
		} `json:"kdsEventBasedWatchdog"`
	} `json:"experimental"`
	Runtime struct {
		Kubernetes struct {
			Injector struct {
				UnifiedResourceNamingEnabled bool `json:"unifiedResourceNamingEnabled"`
				Ebpf                         struct {
					Enabled bool `json:"enabled"`
				} `json:"ebpf"`
			} `json:"injector"`
			// WorkloadLabels is the prioritized pod-label list the CP uses to
			// generate the kuma.io/workload label (the 3.0 metrics/traces grouping
			// dimension). Empty means it falls back to the pod ServiceAccount name.
			WorkloadLabels []string `json:"workloadLabels"`
		} `json:"kubernetes"`
	} `json:"runtime"`
}

const cpConfigCategory = "Control plane configuration"

// checkControlPlaneConfig audits the live CP settings exposed by GET /config for
// 3.0 readiness. The data-plane-relevant settings (injector + experimental flags)
// only govern the CP that actually runs proxies, so they are audited on the CP we
// connect to — UNLESS that CP is global. A global CP injects nothing; its own
// injector/experimental settings are inert, while every zone already reports its
// config to the global over KDS (ZoneInsight). So for a global we audit only its
// global-specific risk here and fan out to each zone's config (one global audit
// then covers the whole multizone estate). A CP that does not serve /config (404,
// older builds) is a coverage gap, never a clean pass.
func (a *auditor) checkControlPlaneConfig(ctx context.Context) error {
	var cfg cpConfig
	status, err := a.c.getJSON(ctx, "/config", &cfg)
	switch {
	case err != nil && (status == http.StatusUnauthorized || status == http.StatusForbidden):
		// Kong Mesh gates /config behind RBAC. Missing/insufficient auth must not
		// abort the whole audit — every ungated resource check already ran — so
		// record a coverage gap (inconclusive) instead of a misleading hard failure.
		a.rep.addGap("/config", "requires authentication — pass --token to audit control-plane settings (NOT audited)")
		return nil
	case err != nil:
		// Any other read failure (timeout, decode, non-2xx) is a /config-specific
		// coverage gap, not a dead CP: earlier checks already reached the CP.
		a.rep.addGap("/config", "could not read /config — control-plane settings NOT audited")
		return nil
	case status == http.StatusNotFound:
		a.rep.addGap("/config", "endpoint returned 404 — control-plane settings NOT audited")
		return nil
	}
	// GET / does not expose the CP mode on most builds; /config is authoritative,
	// so stamp the report with it — otherwise a report can't say which CP (or
	// which mode) it audited.
	if cfg.Mode != "" {
		a.rep.cp.Mode = cfg.Mode
	}

	a.addGlobalOnK8sFinding(cfg) // a no-op unless this CP is itself global

	if strings.EqualFold(cfg.Environment, "kubernetes") {
		// The connected CP itself runs on Kubernetes (standalone, zone, or a k8s
		// global). A global returns early below without reaching addCPConfigFindings,
		// so a k8s global with no k8s zones would otherwise hide the Kubernetes-only
		// manual checks despite the audit positively observing Kubernetes here.
		a.rep.k8sObserved = true
	}

	if strings.EqualFold(cfg.Mode, "global") {
		// The global's own injector/experimental flags govern no proxies; audit
		// each zone's config instead, which the global aggregates in ZoneInsight.
		return a.checkZoneControlPlaneConfigs(ctx)
	}
	// Standalone or a directly-connected zone CP: audit the config we reached.
	a.addCPConfigFindings(cfg, "")
	return nil
}

// addGlobalOnK8sFinding flags a Global CP running on Kubernetes, a deployment
// mode dropped in 3.0. It fires only for mode=global on k8s, so it is safe to
// call on any CP's config.
func (a *auditor) addGlobalOnK8sFinding(cfg cpConfig) {
	if strings.EqualFold(cfg.Environment, "kubernetes") && strings.EqualFold(cfg.Mode, "global") {
		a.rep.add(blocker, cpConfigCategory, "Global control plane on Kubernetes",
			"Global CP on Kubernetes is dropped as a deployment mode in 3.0; migrate the global CP to Universal.",
			"mode=global")
	}
}

// addCPConfigFindings audits the data-plane-relevant CP settings (injector +
// experimental flags) of one control plane's config: flags for features removed
// in 3.0 and settings that become the default and should be enabled and
// validated first — all reported as blockers. The Kubernetes-injector knobs are gated on
// environment so Universal CPs (which have no injector) are not flagged for
// missing them. zone is "" for the CP the tool connects to, or the zone name when
// the config was sourced from a global's ZoneInsight; it qualifies each example
// reference so per-zone findings merge under one title while still naming origin.
func (a *auditor) addCPConfigFindings(cfg cpConfig, zone string) {
	onK8s := strings.EqualFold(cfg.Environment, "kubernetes")
	if onK8s {
		// A standalone/zone CP on k8s, or a k8s zone reached via a global's
		// ZoneInsight fan-out — either way Kubernetes is in the estate.
		a.rep.k8sObserved = true
	}
	ref := func(s string) string {
		if zone != "" {
			return "zone " + zone + ": " + s
		}
		return s
	}

	// Hard removals — the upgrade breaks while these are in use.
	if cfg.Experimental.AutoReachableServices {
		a.rep.add(blocker, cpConfigCategory, "autoReachableServices enabled",
			"`autoReachableServices` is removed entirely in 3.0; stop relying on it before upgrading.",
			ref("experimental.autoReachableServices=true"))
	}
	if onK8s && cfg.Runtime.Kubernetes.Injector.Ebpf.Enabled {
		a.rep.add(blocker, cpConfigCategory, "eBPF transparent proxy enabled",
			"The eBPF transparent proxy is removed in 3.0; switch to the iptables transparent proxy.",
			ref("runtime.kubernetes.injector.ebpf.enabled=true"))
	}

	// Required 3.0 baseline — the upgrade assumes these are already on (they pair
	// with meshServices.mode: Exclusive), so an estate without them is broken on 3.0.
	if onK8s && !cfg.Runtime.Kubernetes.Injector.UnifiedResourceNamingEnabled {
		a.rep.add(blocker, cpConfigCategory, "Unified resource naming not enabled",
			"3.0 assumes the unified (KRI-based) resource naming model; enable `unifiedResourceNamingEnabled` and validate before upgrading.",
			ref("runtime.kubernetes.injector.unifiedResourceNamingEnabled=false"))
	}
	if !cfg.Experimental.InboundTagsDisabled {
		a.rep.add(blocker, cpConfigCategory, "Inbound tags still enabled",
			"3.0 runs with inbound tags disabled (label-based MeshService selection); set `inboundTagsDisabled: true` and validate before upgrading.",
			ref("experimental.inboundTagsDisabled=false"))
	}

	// Settings that become the default in 3.0 — enable and validate before upgrading.
	if !cfg.Experimental.DeltaXds {
		a.rep.add(blocker, cpConfigCategory, "Delta xDS not enabled",
			"Delta xDS becomes the only xDS mode in 3.0; enable `deltaXds` and validate first.",
			ref("experimental.deltaXds=false"))
	}
	if !cfg.Experimental.KdsEventBasedWatchdog.Enabled {
		a.rep.add(blocker, cpConfigCategory, "KDS event-based watchdog not enabled",
			"The KDS event-based watchdog moves to the default in 3.0; enable it and validate first.",
			ref("experimental.kdsEventBasedWatchdog.enabled=false"))
	}
	if !cfg.Experimental.SidecarContainers {
		a.rep.add(blocker, cpConfigCategory, "Native sidecar containers not enabled",
			"Native sidecar containers move to the default in 3.0; enable `sidecarContainers` and validate first.",
			ref("experimental.sidecarContainers=false"))
	}

	// Workload grouping (metrics/traces dimension): with no workloadLabels set the
	// CP derives the kuma.io/workload label from each pod's ServiceAccount. That is
	// valid but only useful if ServiceAccounts are distinct per workload — a cluster
	// left on the `default` ServiceAccount collapses every proxy into one workload.
	if onK8s && len(cfg.Runtime.Kubernetes.WorkloadLabels) == 0 {
		a.rep.add(warning, cpConfigCategory, "Workload labels not configured",
			"`runtime.kubernetes.workloadLabels` is unset, so the `kuma.io/workload` label (the 3.0 metrics/traces grouping dimension) is derived from each pod's ServiceAccount. Ensure ServiceAccounts are distinct per workload, or set `workloadLabels`, or proxies collapse into a single default workload.",
			ref("runtime.kubernetes.workloadLabels unset"))
	}
}

// zoneOverview is the slice of GET /zones+insights this audit reads: each zone's
// KDS subscriptions, which carry the zone CP's own config (the zone sends it on
// every (re)connect).
type zoneOverview struct {
	ZoneInsight struct {
		Subscriptions []zoneSubscription `json:"subscriptions"`
	} `json:"zoneInsight"`
}

// zoneSubscription is one zone->global KDS subscription. Config is the zone CP's
// config as a JSON string — config.ConfigForDisplay on the zone, i.e. the same
// sanitized payload GET /config serves (secrets already redacted), so it is safe
// to read here and carries the exact fields addCPConfigFindings inspects. Version
// carries the zone CP's own reported version (kumaCp.version), letting a global
// audit read every connected zone's version with no extra round-trips.
type zoneSubscription struct {
	Config  string `json:"config"`
	Version struct {
		KumaCp struct {
			Version string `json:"version"`
		} `json:"kumaCp"`
	} `json:"version"`
}

// latestZoneVersion returns the most recent subscription's reported zone CP
// version (zones re-send it on each (re)connect, so the last non-empty one is the
// freshest). It returns false when no subscription carried a version.
func latestZoneVersion(zo zoneOverview) (string, bool) {
	subs := zo.ZoneInsight.Subscriptions
	for i := len(subs) - 1; i >= 0; i-- {
		if v := subs[i].Version.KumaCp.Version; v != "" {
			return v, true
		}
	}
	return "", false
}

// checkZoneControlPlaneConfigs audits the data-plane-relevant CP settings of
// every zone of a global CP, sourcing each zone's config from ZoneInsight so a
// single audit of the global covers all zones. A zone that has reported no
// config, or whose collection is unreachable, is a coverage gap — never a silent
// pass (an unobserved zone is not a clean zone).
func (a *auditor) checkZoneControlPlaneConfigs(ctx context.Context) error {
	items, found, err := a.zoneInsights(ctx)
	if err != nil {
		// Same rationale as /config: an unreadable zones overview (e.g. auth) is a
		// coverage gap, not a reason to abort the whole global audit.
		a.rep.addGap("/zones+insights", "could not read /zones+insights — per-zone control-plane settings NOT audited (pass --token if the CP requires auth)")
		return nil
	}
	if !found {
		a.rep.addGap("/zones+insights", "endpoint returned 404 — per-zone control-plane settings NOT audited")
		return nil
	}
	if len(items) == 0 {
		a.rep.add(info, cpConfigCategory, "No zones connected to the global control plane",
			"This global CP reports no zones, so no per-zone control-plane settings were audited; re-run once zones connect.",
			"zones=0")
		return nil
	}
	for _, it := range items {
		var zo zoneOverview
		if err := json.Unmarshal(it.specBytes(), &zo); err != nil {
			a.rep.addGap("/zones+insights ("+it.Name+")", "zone insight could not be parsed — config NOT audited")
			continue
		}
		cfg, ok := latestZoneConfig(zo)
		if !ok {
			a.rep.addGap("/zones+insights ("+it.Name+")",
				"zone reported no control-plane config over KDS — config NOT audited (upgrade the zone CP or audit the zone directly)")
			continue
		}
		a.addCPConfigFindings(cfg, it.Name)
	}
	return nil
}

// latestZoneConfig returns the most recent subscription's parsed config (zones
// re-send it on each (re)connect, so the last one with a config is the freshest).
// It returns false when no subscription carried a config or it cannot be parsed.
func latestZoneConfig(zo zoneOverview) (cpConfig, bool) {
	subs := zo.ZoneInsight.Subscriptions
	for i := len(subs) - 1; i >= 0; i-- {
		if subs[i].Config == "" {
			continue
		}
		var cfg cpConfig
		if err := json.Unmarshal([]byte(subs[i].Config), &cfg); err != nil {
			return cpConfig{}, false
		}
		return cfg, true
	}
	return cpConfig{}, false
}

const cpVersionCategory = "Control plane version"

// checkControlPlaneVersions flags control planes not on the latest 2.x patch (the
// only supported 3.0 upgrade source). It checks the CP the tool connects to and,
// for a global, fans out to every connected zone's CP version (read from the same
// /zones+insights payload checkControlPlaneConfig uses) so one global audit covers
// the whole estate. The check runs only when enabled by the caller; if the latest
// patch could not be determined it is a coverage gap (never a silent pass).
func (a *auditor) checkControlPlaneVersions(ctx context.Context) error {
	if !a.checkVersionCurrency {
		return nil
	}
	if a.latestPatch == "" {
		a.rep.addGap("github.com/kumahq/kuma/releases",
			fmt.Sprintf("could not determine the latest 2.%d patch — control-plane version currency NOT audited (pass --latest-version to set it explicitly)", upgradeTargetMinor))
		return nil
	}
	latestMaj, latestMin, latestPatch, ok := parseSemver(a.latestPatch)
	if !ok {
		a.rep.addGap("--latest-version",
			"latest version "+a.latestPatch+" is not valid semver — version currency NOT audited")
		return nil
	}
	// The check is scoped to the 2.<target> line; a baseline outside it (a stray
	// --latest-version) would make every comparison nonsensical — a gap, not a
	// contradictory finding.
	if latestMaj != 2 || latestMin != upgradeTargetMinor {
		a.rep.addGap("--latest-version",
			fmt.Sprintf("latest version %s is not a 2.%d patch — version currency NOT audited", a.latestPatch, upgradeTargetMinor))
		return nil
	}
	detail := fmt.Sprintf("Upgrade to the latest 2.%d patch (%s) before upgrading to 3.0; an older 2.x patch or minor is not a supported upgrade source.", upgradeTargetMinor, a.latestPatch)

	a.flagIfBehind(a.rep.cp.Version, "control plane", latestMin, latestPatch, detail)

	// Fan out to connected zones unless we KNOW this CP is not a global. The Kuma
	// GET / index carries no mode, so cp.Mode is only set when /config was readable
	// — if it gapped out (e.g. RBAC without --token) mode is "". Skipping the
	// fan-out on unknown mode would silently miss every stale zone (a fake-clean),
	// so attempt it; a non-global CP answers /zones+insights with 404 and is skipped.
	if strings.EqualFold(a.rep.cp.Mode, "zone") || strings.EqualFold(a.rep.cp.Mode, "standalone") {
		return nil
	}
	return a.checkZoneVersions(ctx, latestMin, latestPatch, detail)
}

// flagIfBehind records a blocker when version is an older 2.x release than the
// latest target patch. An unparseable version is a coverage gap (it cannot be
// proven current), not a silent pass. origin labels the source in the example ref.
func (a *auditor) flagIfBehind(version, origin string, latestMin, latestPatch int, detail string) {
	maj, min, patch, ok := parseSemver(version)
	if !ok {
		a.rep.addGap("version ("+origin+")",
			"reported version "+version+" is not valid semver — version currency NOT audited")
		return
	}
	if behind(maj, min, patch, latestMin, latestPatch) {
		a.rep.add(blocker, cpVersionCategory,
			fmt.Sprintf("Control plane behind the latest 2.%d patch", upgradeTargetMinor),
			detail, origin+" ("+version+")")
	}
}

// checkZoneVersions audits every connected zone's CP version on a global, reading
// each zone's reported version from ZoneInsight. An unreadable overview or a zone
// that reported no version is a coverage gap, never a silent pass.
func (a *auditor) checkZoneVersions(ctx context.Context, latestMin, latestPatch int, detail string) error {
	items, found, err := a.zoneInsights(ctx)
	if err != nil {
		a.rep.addGap("/zones+insights (versions)",
			"could not read /zones+insights — per-zone control-plane versions NOT audited (pass --token if the CP requires auth)")
		return nil
	}
	if !found {
		// 404 means this CP does not serve ZoneInsight (a zone/standalone, not a
		// global), so there are no zones to fan out to — not a coverage gap.
		return nil
	}
	// An estate with no zones is already reported by checkControlPlaneConfig.
	for _, it := range items {
		var zo zoneOverview
		if err := json.Unmarshal(it.specBytes(), &zo); err != nil {
			a.rep.addGap("/zones+insights ("+it.Name+", version)",
				"zone insight could not be parsed — version NOT audited")
			continue
		}
		v, ok := latestZoneVersion(zo)
		if !ok {
			a.rep.addGap("/zones+insights ("+it.Name+", version)",
				"zone reported no control-plane version over KDS — version NOT audited")
			continue
		}
		a.flagIfBehind(v, "zone "+it.Name, latestMin, latestPatch, detail)
	}
	return nil
}

// dpInsight captures just the per-subscription version data exposed by
// /dataplanes+insights — enough to read the control plane's own compatibility
// verdict for each connected proxy, plus the dependency versions kuma-dp reports
// (e.g. a bundled `coredns`, which signals the legacy embedded-DNS path).
type dpInsight struct {
	DataplaneInsight struct {
		Subscriptions []struct {
			Version struct {
				KumaDp struct {
					Version          string `json:"version"`
					KumaCpCompatible *bool  `json:"kumaCpCompatible"`
				} `json:"kumaDp"`
				Envoy struct {
					Version string `json:"version"`
				} `json:"envoy"`
				Dependencies map[string]string `json:"dependencies"`
			} `json:"version"`
		} `json:"subscriptions"`
	} `json:"dataplaneInsight"`
}

// checkDataplaneVersions flags data planes the control plane itself reports as
// version-incompatible (`kumaCpCompatible: false`): they are already outside the
// supported CP/DP skew window and must be upgraded before a major-version bump.
// Sourced from /dataplanes+insights (the data behind the GUI dashboard), so no
// version parsing is reimplemented here — the CP's verdict is authoritative.
func (a *auditor) checkDataplaneVersions(ctx context.Context) error {
	items, err := a.listColl(ctx, a.scopedPath("dataplanes+insights"))
	if err != nil {
		return fmt.Errorf("listing dataplane insights: %w", err)
	}
	for _, it := range items {
		var ins dpInsight
		// Insights are not policy specs; a decode failure is skipped, not counted
		// as a parse error (the tool survives CP version skew by ignoring it).
		if json.Unmarshal(it.specBytes(), &ins) != nil {
			continue
		}
		subs := ins.DataplaneInsight.Subscriptions
		if len(subs) == 0 {
			continue
		}
		last := subs[len(subs)-1].Version
		kd := last.KumaDp
		if kd.KumaCpCompatible != nil && !*kd.KumaCpCompatible {
			a.rep.add(blocker, "Dataplane version", "Dataplane is version-incompatible with the control plane",
				"The control plane reports this proxy's kuma-dp version as incompatible; bring it into the supported skew window before upgrading to 3.0.",
				qualified(it)+" (kuma-dp "+kd.Version+")")
		}
		// A reported `coredns` dependency means kuma-dp launched the bundled
		// CoreDNS, i.e. the proxy is on the legacy CoreDNS + Envoy DNS-filter
		// path that 3.0 removes. This is a free, every-proxy signal from a
		// payload already fetched here; --inspect-dataplanes deep-confirms it.
		if v := last.Dependencies["coredns"]; v != "" {
			a.rep.add(blocker, "Dataplane DNS", "Dataplane uses the legacy embedded CoreDNS",
				"This proxy reports a bundled CoreDNS dependency; 3.0 removes the CoreDNS + Envoy DNS-filter path — upgrade kuma-dp.",
				qualified(it)+" (coredns "+v+")")
		}
	}
	return nil
}

// dnsFilterMarker is the Envoy UDP DNS filter name; its presence in a proxy's
// config dump means that proxy still uses the built-in DNS path 3.0 removes.
var dnsFilterMarker = []byte("envoy.filters.udp.dns_filter")

// checkDataplaneEnvoyConfig is the opt-in deep check (--inspect-dataplanes N):
// it fetches up to N dataplanes' Envoy config dumps and flags use of the legacy
// Envoy DNS filter. Each dump is large, so this is an O(N) heavy fetch gated
// behind the flag; it records how many proxies it actually sampled so a partial
// sweep never reads as full coverage.
func (a *auditor) checkDataplaneEnvoyConfig(ctx context.Context) error {
	if a.inspectDataplanes <= 0 {
		return nil
	}
	items, err := a.listColl(ctx, a.scopedPath("dataplanes"))
	if err != nil {
		return fmt.Errorf("listing dataplanes for inspection: %w", err)
	}
	limit := a.inspectDataplanes
	if limit > len(items) {
		limit = len(items)
	}
	inspected := 0
	for _, it := range items[:limit] {
		path := "/meshes/" + url.PathEscape(it.Mesh) + "/dataplanes/" + url.PathEscape(it.Name) + "/xds"
		var dump json.RawMessage
		status, err := a.c.getJSON(ctx, path, &dump)
		if err != nil || status == http.StatusNotFound {
			continue // best-effort: skip offline / unreadable proxies
		}
		inspected++
		if bytes.Contains(dump, dnsFilterMarker) {
			a.rep.add(blocker, "Dataplane DNS", "Dataplane uses the legacy Envoy DNS filter",
				"This proxy's Envoy config still uses the built-in `envoy.filters.udp.dns_filter`; 3.0 drops the Envoy DNS filter for the embedded DNS server — upgrade kuma-dp.",
				qualified(it))
		}
	}
	if inspected < len(items) {
		a.rep.add(info, "Dataplane DNS", "Envoy config inspected for a sample of dataplanes",
			fmt.Sprintf("Inspected the Envoy config of %d of %d dataplane(s); raise --inspect-dataplanes to cover more.", inspected, len(items)),
			fmt.Sprintf("%d/%d", inspected, len(items)))
	}
	return nil
}

var rfc1035Label = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)

// validRFC1035 mirrors apimachineryvalidation.NameIsDNS1035Label (stdlib-only): a
// lowercase DNS label, at most 63 chars, starting with a letter.
func validRFC1035(name string) bool {
	return name != "" && len(name) <= 63 && rfc1035Label.MatchString(name)
}

// displayName strips the k8s ".<namespace>" suffix the REST API appends, so name
// validation runs on the logical resource name (matching the CP's own check).
func displayName(it resourceItem) string {
	if ns := it.Labels["k8s.kuma.io/namespace"]; ns != "" {
		return strings.TrimSuffix(it.Name, "."+ns)
	}
	return it.Name
}

func (a *auditor) checkName(it resourceItem, kind string) {
	if name := displayName(it); !validRFC1035(name) {
		a.rep.add(blocker, "Non-RFC-1035 names", kind+" name is not a valid RFC-1035 DNS label",
			"Rename to a lowercase RFC-1035 DNS label (≤63 chars, starting with a letter); non-conforming names are deprecated in 3.0.", qualified(it))
	}
}

func qualified(it resourceItem) string {
	if it.Mesh != "" {
		return it.Mesh + "/" + it.Name
	}
	return it.Name
}

func hasJSON(raw json.RawMessage) bool {
	s := string(raw)
	return s != "" && s != "null" && s != "{}" && s != "[]"
}

type meshSpec struct {
	Mtls *struct {
		EnabledBackend string            `json:"enabledBackend"`
		Backends       []json.RawMessage `json:"backends"`
	} `json:"mtls"`
	Networking *struct {
		Outbound *struct {
			Passthrough *bool `json:"passthrough"`
		} `json:"outbound"`
	} `json:"networking"`
	Routing *struct {
		ZoneEgress                             *bool `json:"zoneEgress"`
		DefaultForbidMeshExternalServiceAccess *bool `json:"defaultForbidMeshExternalServiceAccess"`
		LocalityAwareLoadBalancing             *bool `json:"localityAwareLoadBalancing"`
	} `json:"routing"`
	Metrics      json.RawMessage `json:"metrics"`
	Tracing      json.RawMessage `json:"tracing"`
	Logging      json.RawMessage `json:"logging"`
	Constraints  json.RawMessage `json:"constraints"`
	MeshServices *struct {
		Mode string `json:"mode"`
	} `json:"meshServices"`
}

type policySpec struct {
	TargetRef *targetRef  `json:"targetRef"`
	From      []ruleEntry `json:"from"`
	To        []ruleEntry `json:"to"`
}

type targetRef struct {
	Kind       string   `json:"kind"`
	ProxyTypes []string `json:"proxyTypes"`
}

type ruleEntry struct {
	TargetRef targetRef `json:"targetRef"`
}

type dataplaneSpec struct {
	Probes     json.RawMessage `json:"probes"`
	Metrics    json.RawMessage `json:"metrics"`
	Networking *struct {
		Gateway             json.RawMessage `json:"gateway"`
		TransparentProxying *struct {
			ReachableServices []string `json:"reachableServices"`
		} `json:"transparentProxying"`
	} `json:"networking"`
}

// backendConf captures the OpenTelemetry backend `endpoint` shared by
// MeshAccessLog/MeshTrace/MeshMetric (deprecated in favor of backendRef).
type backendConf struct {
	Backends []struct {
		OpenTelemetry *struct {
			Endpoint string `json:"endpoint"`
		} `json:"openTelemetry"`
	} `json:"backends"`
}

type hashContainer struct {
	HashPolicies []struct {
		Type string `json:"type"`
	} `json:"hashPolicies"`
}

func hasOtelEndpoint(confs ...backendConf) bool {
	for _, c := range confs {
		for _, b := range c.Backends {
			if b.OpenTelemetry != nil && b.OpenTelemetry.Endpoint != "" {
				return true
			}
		}
	}
	return false
}

// manualChecks are 3.0 drops that cannot be detected from CP resources alone.
// Settings exposed by GET /config (unified naming, inbound tags, experimental
// flags, autoReachableServices, global-on-k8s, eBPF transparent proxy, k8s
// workloadLabels) are audited automatically by checkControlPlaneConfig,
// Universal proxies missing the kuma.io/workload label by checkDataplanes, and
// the legacy CoreDNS path by checkDataplaneVersions (a reported `coredns`
// dependency) plus the --inspect-dataplanes deep check, so none is repeated here.
var manualChecks = []manualCheck{
	{Title: "Gateway API / GAMMA usage migrated off built-in support"},
	{Title: "Old inspect APIs removed (switch to the new inspect API)"},
	{
		Title: "Rotate legacy HMAC256 signing keys (pre-1.4.x) to asymmetric RSA/ECDSA",
		Detail: "Pre-1.4.x Kuma signed dataplane, zone and user tokens with a symmetric " +
			"HMAC256 key; 1.4+ uses asymmetric RSA (RS256). Kuma 3.0 removes the HMAC256 " +
			"verification fallback, so any token still signed by a legacy symmetric key — and " +
			"the leftover key Secret itself — stops validating after the upgrade and the " +
			"affected proxies or users can no longer authenticate. The control-plane API " +
			"never exposes signing-key bytes (they are sensitive), so the tool cannot detect " +
			"this for you. The script below reads the token-signing-key Secrets directly and " +
			"classifies each: an RSA key is PEM/DER and parses, a legacy HMAC256 key is raw " +
			"bytes that do not. It needs secret-read access (cluster-admin on Kubernetes, an " +
			"admin token on Universal) plus jq and openssl, and never prints key material. Run " +
			"the section for your deployment, then rotate anything flagged LEGACY to RSA with " +
			"`kumactl generate signing-key` and reissue tokens before upgrading.",
		Command: `# Detect pre-1.4.x HMAC256 token signing keys (must be asymmetric RSA before 3.0).
# Needs: jq, openssl + secret-read access. Never prints key material.
# Run the section matching your deployment.

classify() {  # reads a base64 key on stdin, prints a verdict
  b64=$(cat)
  if printf %s "$b64" | base64 -d 2>/dev/null | head -c 40 | grep -qa BEGIN; then
    echo "OK (RSA PEM)"
  elif printf %s "$b64" | base64 -d 2>/dev/null | openssl rsa -inform DER -noout 2>/dev/null; then
    echo "OK (RSA DER)"
  else
    echo "LEGACY HMAC256 -> ROTATE"
  fi
}

# --- Kubernetes (CP namespace; set NS=kuma-system for open-source Kuma) ---
NS=kong-mesh-system
kubectl -n "$NS" get secret -o json \
  | jq -r '.items[]
      | select(.type | test("kuma.io/(global-)?secret"))
      | select(.metadata.name | test("token-signing-key"))
      | select(.data.value != null)
      | [.metadata.name, .data.value] | @tsv' \
  | while read -r name val; do
      printf '%-45s %s\n' "$name" "$(printf %s "$val" | classify)"
    done

# --- Universal (point kumactl at the CP) ---
kumactl get global-secrets -o json \
  | jq -r '.items[]
      | select(.name | test("token-signing-key"))
      | select(.data != null)
      | [.name, .data] | @tsv' \
  | while read -r name data; do
      printf '%-45s %s\n' "$name" "$(printf %s "$data" | classify)"
    done
for mesh in $(kumactl get meshes -o json | jq -r '.items[].name'); do
  kumactl get secrets --mesh "$mesh" -o json \
    | jq -r '.items[]
        | select(.name | test("token-signing-key"))
        | select(.data != null)
        | [.name, .data] | @tsv' \
    | while read -r name data; do
        printf '%-25s %-30s %s\n' "$mesh" "$name" "$(printf %s "$data" | classify)"
      done
done`,
	},
}

// kubernetesManualChecks are appended only when the audit observed Kubernetes in
// the estate (see report.k8sObserved). They are Kubernetes-object concerns the CP
// API cannot reveal, so showing them on a Universal-only run would be noise.
var kubernetesManualChecks = []manualCheck{
	{
		Title: "Replace the `kuma.io/mesh` annotation with the `kuma.io/mesh` label",
		Detail: "On Kubernetes a Pod or Namespace is bound to a non-default mesh through " +
			"`kuma.io/mesh`, which can be set as either an annotation or a label. Kuma 2.x " +
			"still reads the annotation but logs a deprecation warning; 3.0 honors only the " +
			"label. The control-plane API exposes only the resolved mesh name, not which " +
			"metadata field set it, so the tool cannot detect this for you. You have to " +
			"inspect the cluster objects directly. Move every `kuma.io/mesh` annotation to a " +
			"label with the same value on Pods, Namespaces, and any other namespaced Kuma " +
			"resource. The command below lists offenders; empty output means there is " +
			"nothing left to fix.",
		Command: `kubectl get ns,pods -A -o json | jq -r '.items[] | select(.metadata.annotations["kuma.io/mesh"]) | [.kind, .metadata.namespace, .metadata.name] | map(select(. != null and . != "")) | join("/")'`,
	},
	{
		Title: "Pod resources instead of container resources",
		Detail: "On Kubernetes the 3.0 injector sets the sidecar's CPU and memory at the " +
			"pod level (`spec.resources`) instead of on each injected container. This is a " +
			"behavior change in the injector, not a setting you flip, and the control-plane " +
			"API exposes neither pod resource specs nor the cluster's Kubernetes version, so " +
			"the tool cannot check it for you. Pod-level resources are on by default from " +
			"Kubernetes 1.34; on 1.32-1.33 (or with the `PodLevelResources` feature gate " +
			"turned off) the injected proxy ends up with no requests or limits unless you " +
			"enable the gate or fall back to `ContainerPatch`. The command below reports your " +
			"API server version and whether action is needed.",
		Command: `kubectl version -o json | jq -r '(.serverVersion.minor | gsub("[^0-9]";"") | tonumber) as $m | "K8s " + .serverVersion.major + "." + .serverVersion.minor + (if $m >= 34 then ": pod-level resources on by default — no action" else ": enable the PodLevelResources feature gate or use ContainerPatch" end)'`,
	},
}

// buildManualChecks returns the manual checklist for a run, appending the
// Kubernetes-only items when the audit positively observed Kubernetes.
func buildManualChecks(k8sObserved bool) []manualCheck {
	checks := append([]manualCheck{}, manualChecks...)
	if k8sObserved {
		checks = append(checks, kubernetesManualChecks...)
	}
	return checks
}
