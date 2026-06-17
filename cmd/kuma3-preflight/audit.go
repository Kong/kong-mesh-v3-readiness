package main

import (
	"context"
	"encoding/json"
	"fmt"
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

var allowedToTargetRefKinds = map[string]bool{
	"MeshService": true, "MeshExternalService": true, "MeshMultiZoneService": true,
}

const exampleCap = 10

// policyRoleLabel marks CP-managed default policies. They use deprecated
// constructs (from, to: Mesh, proxyTypes) and must be updated before upgrading to
// 3.0, so the audit still flags them — marked as system-managed.
const policyRoleLabel = "kuma.io/policy-role"

func isSystem(it resourceItem) bool {
	return it.Labels[policyRoleLabel] == "system"
}

type auditor struct {
	c          *client
	meshFilter string
	rep        *report
}

func audit(ctx context.Context, c *client, meshFilter string) (*report, error) {
	idx, err := c.index(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to control plane: %w", err)
	}
	// A non-Kuma endpoint can answer GET / with 200 and an empty/foreign body.
	// Refuse to audit it rather than emit a misleading clean report.
	if idx.Version == "" {
		return nil, fmt.Errorf("endpoint at %s does not look like a Kuma control plane (GET / returned no version)", c.base)
	}

	a := &auditor{c: c, meshFilter: meshFilter, rep: &report{cp: idx}}

	meshes, found, err := c.list(ctx, "/meshes")
	if err != nil {
		return nil, fmt.Errorf("listing meshes: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("GET /meshes returned 404; is %s a Kuma control plane?", c.base)
	}
	for _, m := range meshes {
		if meshFilter != "" && m.Name != meshFilter {
			continue
		}
		a.rep.meshes = append(a.rep.meshes, m.Name)
		a.checkMeshSettings(m)
		a.checkName(m, "Mesh")
	}
	// A --mesh that matches nothing must not pass as a clean audit.
	if meshFilter != "" && len(a.rep.meshes) == 0 {
		return nil, fmt.Errorf("mesh %q not found on the control plane", meshFilter)
	}

	for _, check := range []func(context.Context) error{
		a.checkLegacyResources, a.checkNewPolicies, a.checkDataplanes,
		a.checkZoneProxies, a.checkResourceNames, a.checkMeshTrust,
	} {
		if err := check(ctx); err != nil {
			return nil, err
		}
	}
	a.rep.manual = manualChecks
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
// warning (and returning false) when the spec is malformed. ref is supplied by
// the caller so system-tagging applies where relevant.
func (a *auditor) unmarshalSpec(it resourceItem, v any, ref string) bool {
	if err := json.Unmarshal(it.specBytes(), v); err != nil {
		a.rep.parseErrors++
		a.rep.add(warning, "Unparseable resources", it.Type+" spec could not be parsed",
			"Could not parse this resource; audit it manually before upgrading.", ref)
		return false
	}
	return true
}

// ref formats the example reference for a flagged resource, marking CP-managed
// (policy-role: system) ones so the operator knows which defaults to update.
func (a *auditor) ref(it resourceItem) string {
	if isSystem(it) {
		a.rep.systemFindings++
		return qualified(it) + " (system — CP-managed, update before 3.0)"
	}
	return qualified(it)
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
		a.rep.add(warning, "MeshService mode", "meshServices.mode is not Exclusive",
			"Move to `meshServices.mode: Exclusive` before upgrading (current: "+shown+").", m.Name)
	}
}

func (a *auditor) checkLegacyResources(ctx context.Context) error {
	for _, lt := range legacyMeshScoped {
		items, err := a.listColl(ctx, a.scopedPath(lt.wsPath))
		if err != nil {
			return fmt.Errorf("listing %s: %w", lt.wsPath, err)
		}
		for _, it := range items {
			a.rep.add(blocker, "Removed resources", lt.kind+" (removed in 3.0)",
				"Replace with "+lt.replacement+".", a.ref(it))
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
			ref := a.ref(it)
			var spec policySpec
			if !a.unmarshalSpec(it, &spec, ref) {
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
					a.rep.add(warning, "targetRef proxyTypes", it.Type+" uses targetRef.proxyTypes",
						"`proxyTypes` is removed (gateway support dropped).", ref)
				}
			}
			for _, to := range spec.To {
				if k := to.TargetRef.Kind; k != "" && !allowedToTargetRefKinds[k] {
					a.rep.add(warning, "`to` targetRef kind", it.Type+" to[].targetRef.kind="+k,
						"`to` may only target MeshService/MeshExternalService/MeshMultiZoneService.", ref)
				}
			}
			a.checkPolicyFields(it, ref)
		}
	}
	return nil
}

// checkPolicyFields flags per-policy deprecated fields visible in the spec but not
// covered by the generic from/targetRef/to checks. These are documented field
// deprecations/relocations (not hard 3.0 removals), so they are warnings. ref is
// reused from the caller so a system policy is counted once.
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
				a.rep.add(warning, "Relocated policy fields", "MeshHealthCheck uses healthyPanicThreshold",
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
			a.rep.add(warning, "Relocated policy fields", "MeshLoadBalancingStrategy nests hashPolicies under loadBalancer",
				"Move `loadBalancer.{ringHash,maglev}.hashPolicies` up to `to[].default.hashPolicies`.", ref)
		}
		if sourceIP {
			a.rep.add(warning, "Relocated policy fields", "MeshLoadBalancingStrategy uses SourceIP hash policy",
				"The `SourceIP` hash policy type is deprecated; use `Connection`.", ref)
		}
	}
}

func (a *auditor) addOtelEndpoint(typ, ref string) {
	a.rep.add(warning, "OpenTelemetry endpoint", typ+" uses OpenTelemetry `endpoint`",
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
		// Universal-only: spec.probes is removed in 3.0. On Kubernetes probes are
		// derived from the pod and need no action, so only flag non-k8s dataplanes.
		if hasJSON(spec.Probes) && it.Labels["kuma.io/env"] != "kubernetes" {
			a.rep.add(warning, "Dataplane probes", "Dataplane has a probes section",
				"Dataplane `spec.probes` is removed for Universal in 3.0 (app-probe-proxy supersedes it).", qualified(it))
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
			a.rep.add(info, "Zone proxies", wsPath+" present",
				"ZoneIngress/ZoneEgress are superseded by the unified Zone Proxy in Exclusive mode.", it.Name)
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
			a.rep.add(warning, "Relocated policy fields", "MeshTrust uses spec.origin",
				"`spec.origin` is deprecated; it moves to `status.origin` in 3.0.", qualified(it))
		}
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
		a.rep.add(warning, "Non-RFC-1035 names", kind+" name is not a valid RFC-1035 DNS label",
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
var manualChecks = []string{
	"Unified resource naming enabled (`dataPlane.features.unifiedResourceNaming: true`)",
	"Inbound tags disabled (`KUMA_EXPERIMENTAL_INBOUND_TAGS_DISABLED=true`)",
	"Experimental flags moved to defaults: deltaXds (becomes the only option), kdsEventBasedWatchdog, sidecarContainers",
	"autoReachableServices removed entirely — stop relying on it",
	"Global control plane on Kubernetes is dropped as a deployment mode",
	"Gateway API / GAMMA usage migrated off built-in support",
	"Observability: KRI-based config only; `install observability` command removed; metrics-via-Dataplane-annotations removed",
	"DNS: CoreDNS + Envoy DNS filter removed; eBPF transparent proxy removed",
	"Old inspect APIs removed (switch to the new inspect API)",
	"Pod resources instead of container resources",
	"Adopt the Workload resource for proxy grouping (metrics/traces dimension) instead of kuma.io/service tags",
	"Rotate legacy HMAC256 signing keys (pre-1.4.x) to asymmetric RSA/ECDSA",
	"Replace the `kuma.io/mesh` annotation with the `kuma.io/mesh` label",
	"Routing MeshExternalService through a specific zone is removed",
}
