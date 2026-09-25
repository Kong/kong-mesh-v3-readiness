package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// docBase is the Kong Mesh developer-docs root. The doc* values below point at
// the page (or section anchor) explaining the 3.0 replacement API/feature for
// each finding, surfaced in the report so an operator can jump straight to the
// migration target. Keep them here (next to the checks) so the link lives with
// the behavior, per the "audit.go is behavior" rule.
const docBase = "https://developer.konghq.com"

const (
	docMeshTrafficPermission = docBase + "/mesh/policies/meshtrafficpermission/"
	docMeshHTTPRoute         = docBase + "/mesh/policies/meshhttproute/"
	docMeshAccessLog         = docBase + "/mesh/policies/meshaccesslog/"
	docMeshTrace             = docBase + "/mesh/policies/meshtrace/"
	docMeshFaultInjection    = docBase + "/mesh/policies/meshfaultinjection/"
	docMeshHealthCheck       = docBase + "/mesh/policies/meshhealthcheck/"
	docMeshCircuitBreaker    = docBase + "/mesh/policies/meshcircuitbreaker/"
	docMeshRetry             = docBase + "/mesh/policies/meshretry/"
	docMeshTimeout           = docBase + "/mesh/policies/meshtimeout/"
	docMeshRateLimit         = docBase + "/mesh/policies/meshratelimit/"
	docMeshProxyPatch        = docBase + "/mesh/policies/meshproxypatch/"
	docMeshMetric            = docBase + "/mesh/policies/meshmetric/"
	docMeshLoadBalancing     = docBase + "/mesh/policies/meshloadbalancingstrategy/"
	docMeshPassthrough       = docBase + "/mesh/policies/meshpassthrough/"
	docPolicies              = docBase + "/mesh/policies-introduction/"

	docMeshService          = docBase + "/mesh/meshservice/"
	docMeshServiceExclusive = docBase + "/mesh/meshservice/#exclusive"
	docReachableBackends    = docBase + "/mesh/meshservice/#reachablebackends"
	docMeshExternalService  = docBase + "/mesh/meshexternalservice/"
	docHostnameGenerator    = docBase + "/mesh/hostnamegenerator/"

	docMeshIdentity     = docBase + "/mesh/issue-identity-with-meshidentity/"
	docDelegatedGateway = docBase + "/mesh/gateway-delegated/"
	docZoneProxies      = docBase + "/mesh/zone-proxies/"
	docZoneEgress       = docBase + "/mesh/zone-egress/"
	docDNS              = docBase + "/mesh/dns/"
	docTransparentProxy = docBase + "/mesh/transparent-proxying/"
	docDataPlaneProxy   = docBase + "/mesh/data-plane-proxy/"
	docAnnotations      = docBase + "/mesh/annotations/"
	docOtelCollector    = docBase + "/mesh/deploy-an-opentelemetry-collector/"
	docUniversal        = docBase + "/mesh/universal/"
	docKumaCPReference  = docBase + "/mesh/reference/kuma-cp/"
	docUpgrade          = docBase + "/mesh/upgrade/"
)

// legacyType is a resource kind removed in Kuma 3.0; any instance is a blocker.
// policy marks the classic Kuma 1.x *policy* types (traffic-permissions, retries,
// …) so they render under the Policies group; the rest are networking/gateway
// resources that stay under Removed resources (see removedCategory).
type legacyType struct {
	wsPath      string
	kind        string
	replacement string
	doc         string
	policy      bool
}

// legacyMeshScoped lists removed mesh-scoped resources (classic policies + resources).
var legacyMeshScoped = []legacyType{
	{"traffic-permissions", "TrafficPermission", "MeshTrafficPermission (rules + spiffeID)", docMeshTrafficPermission, true},
	{"traffic-routes", "TrafficRoute", "MeshHTTPRoute / MeshTCPRoute", docMeshHTTPRoute, true},
	{"traffic-logs", "TrafficLog", "MeshAccessLog", docMeshAccessLog, true},
	{"traffic-traces", "TrafficTrace", "MeshTrace", docMeshTrace, true},
	{"fault-injections", "FaultInjection", "MeshFaultInjection", docMeshFaultInjection, true},
	{"health-checks", "HealthCheck", "MeshHealthCheck", docMeshHealthCheck, true},
	{"circuit-breakers", "CircuitBreaker", "MeshCircuitBreaker", docMeshCircuitBreaker, true},
	{"retries", "Retry", "MeshRetry", docMeshRetry, true},
	{"timeouts", "Timeout", "MeshTimeout", docMeshTimeout, true},
	{"rate-limits", "RateLimit", "MeshRateLimit", docMeshRateLimit, true},
	{"proxytemplates", "ProxyTemplate", "MeshProxyPatch", docMeshProxyPatch, true},
	{"virtual-outbounds", "VirtualOutbound", "unified naming + MeshService hostnames", docMeshService, false},
	{"external-services", "ExternalService", "MeshExternalService", docMeshExternalService, false},
	{"meshgateways", "MeshGateway", "delegated gateway (Kong / third-party)", docDelegatedGateway, false},
	{"meshgatewayroutes", "MeshGatewayRoute", "delegated gateway (Kong / third-party)", docDelegatedGateway, false},
}

// Categories for removed kinds. Removed classic policies render under the Policies
// group; removed networking/gateway resources under Removed resources.
const (
	categoryRemovedPolicy    = "Removed policies"
	categoryRemovedResources = "Removed resources"
)

// restrictOutboundRemediation closes both outbound-deny findings for proxies
// whose control plane leaves the switch unset. 2.14 backports it, so either
// answer can be applied and validated on 2.x rather than discovered on 3.0.
const restrictOutboundRemediation = "This applies because `defaults.restrictOutbound` is not set on the control plane governing these proxies, so 3.0 applies its new default: set it explicitly to `false` (and keep it on 3.0) to keep today's behavior through the upgrade, or to `true` to enforce the 3.0 behavior now and validate it."

// removedCategory picks the finding category (and thus display group) for a
// removed kind: classic policies group with the other policy findings, resources
// stay under Removed resources.
func removedCategory(policy bool) string {
	if policy {
		return categoryRemovedPolicy
	}
	return categoryRemovedResources
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

const ExampleCap = 10

// policyRoleLabel marks CP-managed default policies. They use deprecated
// constructs (from, to: Mesh, proxyTypes) and must be updated before upgrading to
// 3.0, so the audit still flags them — marked as system-managed.
const policyRoleLabel = "kuma.io/policy-role"

// Dataplane labels the checks read. envLabel/zoneLabel are stamped by the control
// plane; gatewayLabel and serviceAccountLabel change meaning in 3.0 (see
// checkDataplaneLabels), and listenerZoneIngressLabel marks a unified Zone Proxy.
const (
	envLabel                 = "kuma.io/env"
	zoneLabel                = "kuma.io/zone"
	gatewayLabel             = "kuma.io/gateway"
	serviceAccountLabel      = "k8s.kuma.io/service-account"
	listenerZoneIngressLabel = "kuma.io/listener-zoneingress"
)

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
	// skipAuditedCPVersion excludes only the audited control plane's own patch
	// level from the version-currency check; connected zones are still checked.
	skipAuditedCPVersion bool
}

type auditor struct {
	c                    *client
	meshFilter           string
	inspectDataplanes    int
	checkVersionCurrency bool
	latestPatch          string
	skipAuditedCPVersion bool
	rep                  *collector

	// /zones+insights is read by both the config and version fan-outs on a global;
	// memoize the (single) fetch so one global audit makes one round-trip for it.
	zonesItems  []resourceItem
	zonesFound  bool
	zonesErr    error
	zonesCached bool

	resourceLimitGapRecorded bool

	// listCache memoizes collection reads by path.
	listCache map[string]listResult

	// passthroughOff and tpProxies (the transparent proxies checkOutboundDefaults
	// records) narrow checkPassthroughDefault to the proxies the flip can affect.
	passthroughOff map[string]bool
	tpProxies      []resourceItem

	// outboundModes holds defaults.restrictOutbound per proxy-governing control
	// plane: key "" for the audited CP, a zone name for each zone behind a global.
	// See outboundModeFor.
	outboundModes map[string]outboundMode

	// zoneProxyZones is the set of Universal zones observed terminating cross-zone
	// traffic (a ZoneIngress, or a Dataplane already carrying a ZoneIngress
	// listener). checkMeshZoneAddresses requires a MeshZoneAddress for each.
	zoneProxyZones map[string]bool
	// meshZones maps each mesh to the zones its Dataplanes were observed in, so
	// checkMeshZoneAddresses can tell a zone-spanning mesh from a zone-local one.
	meshZones map[string]map[string]bool
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

func audit(ctx context.Context, c *client, opts auditOptions) (*collector, error) {
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
		skipAuditedCPVersion: opts.skipAuditedCPVersion,
		rep:                  &collector{cp: idx},
	}

	meshes, found, err := c.list(ctx, "/meshes")
	meshesHitResourceLimit := false
	if err != nil {
		var listErr *listError
		if !errors.As(err, &listErr) || listErr.kind != listErrResourceLimit {
			return nil, fmt.Errorf("listing meshes: %w", err)
		}
		meshesHitResourceLimit = true
		a.rep.addGap("/meshes", collectionReadGapReason(err))
		a.resourceLimitGapRecorded = true
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
	if opts.meshFilter != "" && len(a.rep.meshes) == 0 && !meshesHitResourceLimit {
		return nil, fmt.Errorf("mesh %q not found on the control plane", opts.meshFilter)
	}

	for _, check := range []func(context.Context) error{
		a.checkLegacyResources, a.checkRemovedEnterprisePolicies, a.checkNewPolicies, a.checkDataplanes,
		a.checkZoneProxies, a.checkZoneNames, a.checkMeshZoneAddresses,
		a.checkResourceNames, a.checkMeshTrust,
		a.checkControlPlaneConfig,
		// Both read defaults.restrictOutbound, which checkControlPlaneConfig resolves;
		// checkPassthroughDefault also reads the meshes checkOutboundDefaults records.
		a.checkOutboundDefaults, a.checkPassthroughDefault,
		a.checkControlPlaneVersions,
		a.checkDataplaneVersions, a.checkDataplaneEnvoyConfig,
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := check(ctx); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
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

func collectionReadGapReason(err error) string {
	var reqErr *requestError
	if errors.As(err, &reqErr) {
		switch reqErr.kind {
		case requestErrStatus:
			if reqErr.status == http.StatusUnauthorized || reqErr.status == http.StatusForbidden {
				return fmt.Sprintf("collection read failed — status %d (authentication failed; check --token) — NOT audited", reqErr.status)
			}
			return fmt.Sprintf("collection read failed — status %d — NOT audited", reqErr.status)
		case requestErrDecode:
			return "collection read failed — response could not be decoded — NOT audited"
		default:
			return "collection read failed — request failed — NOT audited"
		}
	}
	var listErr *listError
	if errors.As(err, &listErr) {
		switch listErr.kind {
		case listErrCursorLoop, listErrPageLimit:
			return "collection read failed — pagination did not converge — NOT audited"
		case listErrCursorParse:
			return "collection read failed — pagination cursor was invalid — NOT audited"
		case listErrResourceLimit:
			return fmt.Sprintf("resource read ceiling reached while reading this collection — configured ceiling (%d resources); audit may be incomplete", listErr.limit)
		}
	}
	return "collection read failed — NOT audited"
}

type listResult struct {
	items    []resourceItem
	observed bool
}

// listColl lists a collection and records a coverage gap (instead of silently
// treating it as empty) when the collection cannot be read.
func (a *auditor) listColl(ctx context.Context, path string) []resourceItem {
	items, _ := a.listCollObserved(ctx, path)
	return items
}

// listCollObserved also reports whether the collection was read: a check that
// concludes something from a resource's absence must not fire on a coverage gap.
// Memoized by path, so a shared collection costs one round-trip and one gap.
func (a *auditor) listCollObserved(ctx context.Context, path string) ([]resourceItem, bool) {
	if r, cached := a.listCache[path]; cached {
		return r.items, r.observed
	}
	items, observed := a.readColl(ctx, path)
	if a.listCache == nil {
		a.listCache = map[string]listResult{}
	}
	a.listCache[path] = listResult{items: items, observed: observed}
	return items, observed
}

func (a *auditor) readColl(ctx context.Context, path string) ([]resourceItem, bool) {
	items, found, err := a.c.list(ctx, path)
	if err != nil {
		var listErr *listError
		if ctx.Err() == nil && (!errors.As(err, &listErr) || listErr.kind != listErrResourceLimit || !a.resourceLimitGapRecorded) {
			a.rep.addGap(path, collectionReadGapReason(err))
			if errors.As(err, &listErr) && listErr.kind == listErrResourceLimit {
				a.resourceLimitGapRecorded = true
			}
		}
		return items, false
	}
	if !found {
		a.rep.addGap(path, "endpoint returned 404 — NOT audited")
		return nil, false
	}
	return items, true
}

// listIfServed lists a collection, returning nil when the endpoint is
// unregistered (404) — for resource types newer than the CP may serve, where a
// 404 is "not applicable", not a coverage gap (cf. listColl).
func (a *auditor) listIfServed(ctx context.Context, path string) []resourceItem {
	items, found, err := a.c.list(ctx, path)
	if err != nil {
		var listErr *listError
		if ctx.Err() == nil && (!errors.As(err, &listErr) || listErr.kind != listErrResourceLimit || !a.resourceLimitGapRecorded) {
			a.rep.addGap(path, collectionReadGapReason(err))
			if errors.As(err, &listErr) && listErr.kind == listErrResourceLimit {
				a.resourceLimitGapRecorded = true
			}
		}
		return items
	}
	if !found {
		return nil
	}
	return items
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
// Summary aligned with the findings the operator must act on, not every system
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
		a.rep.addDoc(blocker, "Mesh object settings", "Inline mTLS on Mesh",
			"Migrate `mesh.mtls` to MeshIdentity + MeshTrust.", docMeshIdentity, ref("mtls"))
	}
	if spec.Networking != nil && spec.Networking.Outbound != nil && spec.Networking.Outbound.Passthrough != nil {
		a.rep.addDoc(blocker, "Mesh object settings", "Passthrough on Mesh",
			"`mesh.networking.outbound.passthrough` is removed; use MeshPassthrough.", docMeshPassthrough, ref("networking.outbound.passthrough"))
		// A mesh that already turns passthrough off has no external egress for 3.0
		// to take away when it flips the no-policy default to None.
		if !*spec.Networking.Outbound.Passthrough {
			if a.passthroughOff == nil {
				a.passthroughOff = map[string]bool{}
			}
			a.passthroughOff[m.Name] = true
		}
	}
	if spec.Routing != nil {
		if spec.Routing.ZoneEgress != nil {
			a.rep.addDoc(blocker, "Mesh object settings", "routing.zoneEgress on Mesh",
				"`mesh.routing.zoneEgress` is removed.", docZoneEgress, ref("routing.zoneEgress"))
		}
		if spec.Routing.DefaultForbidMeshExternalServiceAccess != nil {
			a.rep.addDoc(blocker, "Mesh object settings", "defaultForbidMeshExternalServiceAccess on Mesh",
				"`mesh.routing.defaultForbidMeshExternalServiceAccess` is removed.", docMeshExternalService, ref("routing.defaultForbidMeshExternalServiceAccess"))
		}
		if spec.Routing.LocalityAwareLoadBalancing != nil {
			a.rep.addDoc(blocker, "Mesh object settings", "localityAwareLoadBalancing on Mesh",
				"Replace with MeshLoadBalancingStrategy.", docMeshLoadBalancing, ref("routing.localityAwareLoadBalancing"))
		}
	}
	for _, c := range []struct {
		present                   bool
		title, detail, doc, field string
	}{
		{hasJSON(spec.Metrics), "Inline metrics on Mesh", "Replace `mesh.metrics` with the MeshMetric policy.", docMeshMetric, "metrics"},
		{hasJSON(spec.Tracing), "Inline tracing on Mesh", "Replace `mesh.tracing` with the MeshTrace policy.", docMeshTrace, "tracing"},
		{hasJSON(spec.Logging), "Inline logging on Mesh", "Replace `mesh.logging` with the MeshAccessLog policy.", docMeshAccessLog, "logging"},
		{hasJSON(spec.Constraints), "Mesh membership constraints", "`mesh.constraints` (membership) is removed.", docKumaCPReference, "constraints"},
	} {
		if c.present {
			a.rep.addDoc(blocker, "Mesh object settings", c.title, c.detail, c.doc, ref(c.field))
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
		a.rep.addDoc(blocker, "MeshService mode", "meshServices.mode is not Exclusive",
			"3.0 requires `meshServices.mode: Exclusive` (it gates Zone Proxy, MeshIdentity and disables legacy kuma.io/service routing); migrate before upgrading (current: "+shown+").", docMeshServiceExclusive, m.Name)
	}
}

func (a *auditor) checkLegacyResources(ctx context.Context) error {
	for _, lt := range legacyMeshScoped {
		items := a.listColl(ctx, a.scopedPath(lt.wsPath))
		for _, it := range items {
			before := a.rep.total
			a.rep.addDoc(blocker, removedCategory(lt.policy), lt.kind+" (removed in 3.0)",
				"Replace with "+lt.replacement+".", lt.doc, a.ref(it))
			a.countSystem(it, before)
		}
	}
	return nil
}

// checkRemovedEnterprisePolicies flags Kong Mesh (enterprise) policies removed in
// 3.0 — any instance is a blocker. These are enterprise-only, so an OSS Kuma CP
// 404s the collection; listIfServed treats that as "not served" (not a coverage
// gap), unlike checkLegacyResources whose collections every CP serves.
func (a *auditor) checkRemovedEnterprisePolicies(ctx context.Context) error {
	for _, rp := range []struct{ wsPath, kind, detail, doc string }{
		{
			"meshglobalratelimits", "MeshGlobalRateLimit",
			"MeshGlobalRateLimit is removed in 3.0 with no direct replacement (global rate limiting is dropped); remove these policies before upgrading.",
			docPolicies,
		},
	} {
		items := a.listIfServed(ctx, a.scopedPath(rp.wsPath))
		for _, it := range items {
			before := a.rep.total
			a.rep.addDoc(blocker, categoryRemovedPolicy, rp.kind+" (removed in 3.0)", rp.detail, rp.doc, a.ref(it))
			a.countSystem(it, before)
		}
	}
	return nil
}

func (a *auditor) checkNewPolicies(ctx context.Context) error {
	for _, wsPath := range newPolicyPaths {
		items := a.listColl(ctx, a.scopedPath(wsPath))
		for _, it := range items {
			before := a.rep.total
			ref := a.ref(it)
			var spec policySpec
			if !a.unmarshalSpec(it, &spec, ref) {
				a.countSystem(it, before)
				continue
			}
			if len(spec.From) > 0 {
				a.rep.addDoc(blocker, "Policy `from` field", it.Type+" uses `from`",
					"Rewrite `from` as `rules` (with spiffeID where applicable).", docMeshTrafficPermission, ref)
			}
			if spec.TargetRef != nil {
				if k := spec.TargetRef.Kind; k != "" && !allowedTopLevelTargetRefKinds[k] {
					a.rep.addDoc(blocker, "Top-level targetRef kind", it.Type+" top-level targetRef.kind="+k,
						"Top-level targetRef must be Mesh or Dataplane; use labels.", docPolicies, ref)
				}
				if len(spec.TargetRef.ProxyTypes) > 0 {
					a.rep.addDoc(blocker, "targetRef proxyTypes", it.Type+" uses targetRef.proxyTypes",
						"`proxyTypes` is removed (gateway support dropped).", docDelegatedGateway, ref)
				}
			}
			for _, to := range spec.To {
				if k := to.TargetRef.Kind; k != "" && !allowedToTargetRefKinds[k] {
					a.rep.addDoc(blocker, "`to` targetRef kind", it.Type+" to[].targetRef.kind="+k,
						"`to` no longer accepts subset/selector or MeshGateway kinds; target Mesh, a Mesh*Service, or MeshHTTPRoute.", docPolicies, ref)
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
				a.rep.addDoc(blocker, "Relocated policy fields", "MeshHealthCheck uses healthyPanicThreshold",
					"`healthyPanicThreshold` moves to MeshCircuitBreaker in 3.0.", docMeshCircuitBreaker, ref)
				break
			}
		}
	case "MeshHTTPRoute":
		var s struct {
			To []struct {
				Rules []httpRouteRule `json:"rules"`
			} `json:"to"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		var emptyMatches, noCatchAll bool
		for _, t := range s.To {
			if len(t.Rules) == 0 {
				continue
			}
			for _, r := range t.Rules {
				if len(r.Matches) == 0 {
					emptyMatches = true
				}
			}
			if !hasCatchAllRule(t.Rules) {
				noCatchAll = true
			}
		}
		switch {
		case emptyMatches:
			a.rep.addDoc(blocker, "MeshHTTPRoute routing", "MeshHTTPRoute rule has no matches",
				"A rule with an empty `matches` list generates no Envoy routes at all — the Universal API accepts it, but nothing is emitted for it. In 3.0 a request that matches no rule of an applicable MeshHTTPRoute gets a `404` instead of falling through to the destination, so every request to this destination fails after the upgrade. Give the rule at least one match (`path: {type: PathPrefix, value: /}` matches everything).",
				docMeshHTTPRoute, ref)
		case noCatchAll:
			a.rep.addDoc(info, "MeshHTTPRoute routing", "MeshHTTPRoute has no catch-all rule",
				"In 3.0 a request that matches no rule of an applicable MeshHTTPRoute gets a `404` instead of falling through to the destination. This route matches only some requests, so if it exists to anchor a MeshTimeout/MeshRetry/MeshAccessLog the unmatched traffic starts failing after the upgrade. Review it and add a catch-all rule (`path: {type: PathPrefix, value: /}` with no other matchers) if the fall-through is intended.",
				docMeshHTTPRoute, ref)
		}
	case "MeshLoadBalancingStrategy":
		var s struct {
			To []struct {
				TargetRef targetRef `json:"targetRef"`
				Default   struct {
					LoadBalancer *struct {
						RingHash *hashContainer `json:"ringHash"`
						Maglev   *hashContainer `json:"maglev"`
					} `json:"loadBalancer"`
					LocalityAwareness *struct {
						CrossZone *json.RawMessage `json:"crossZone"`
					} `json:"localityAwareness"`
				} `json:"default"`
			} `json:"to"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		var relocated, sourceIP bool
		for _, t := range s.To {
			// An empty crossZone object still fails 3.0 validation, so test for the
			// key's presence rather than hasJSON (which treats `{}` as absent).
			if la := t.Default.LocalityAwareness; la != nil && la.CrossZone != nil && string(*la.CrossZone) != "null" && t.TargetRef.Kind != "MeshMultiZoneService" {
				a.rep.addDoc(blocker, "Cross-zone load balancing", "MeshLoadBalancingStrategy crossZone targets a non-MeshMultiZoneService",
					"3.0 accepts `localityAwareness.crossZone` only when the `to[].targetRef.kind` is MeshMultiZoneService; this policy would be rejected on write. Retarget it at a MeshMultiZoneService (kind: "+targetRefKindOrEmpty(t.TargetRef)+").",
					docMeshLoadBalancing, ref)
			}
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
			a.rep.addDoc(blocker, "Relocated policy fields", "MeshLoadBalancingStrategy nests hashPolicies under loadBalancer",
				"Move `loadBalancer.{ringHash,maglev}.hashPolicies` up to `to[].default.hashPolicies`.", docMeshLoadBalancing, ref)
		}
		if sourceIP {
			a.rep.addDoc(blocker, "Relocated policy fields", "MeshLoadBalancingStrategy uses SourceIP hash policy",
				"The `SourceIP` hash policy type is deprecated; use `Connection`.", docMeshLoadBalancing, ref)
		}
	}
}

func (a *auditor) addOtelEndpoint(typ, ref string) {
	a.rep.addDoc(blocker, "OpenTelemetry endpoint", typ+" uses OpenTelemetry `endpoint`",
		"The OpenTelemetry `endpoint` field is deprecated; use `backendRef` (MeshOpenTelemetryBackend).", docOtelCollector, ref)
}

func (a *auditor) checkDataplanes(ctx context.Context) error {
	items := a.listColl(ctx, a.scopedPath("dataplanes"))
	for _, it := range items {
		var spec dataplaneSpec
		if !a.unmarshalSpec(it, &spec, qualified(it)) {
			continue
		}
		// A k8s-injected proxy proves Kubernetes is in the estate even when /config
		// is gated (Kong Mesh RBAC) and could not report the environment.
		onK8s := it.Labels[envLabel] == "kubernetes"
		if onK8s {
			a.rep.k8sObserved = true
		}
		// A proxy already carrying a ZoneIngress listener is a unified Zone Proxy;
		// like a standalone ZoneIngress it makes its zone a cross-zone destination,
		// which 3.0 addresses through MeshZoneAddress (checkMeshZoneAddresses).
		if it.Labels[listenerZoneIngressLabel] != "" && !onK8s {
			a.noteZoneProxy(it.Labels[zoneLabel])
		}
		a.noteMeshZone(it.Mesh, it.Labels[zoneLabel])
		// Universal-only: the kuma.io/workload label drives Workload generation (the
		// 3.0 metrics/traces grouping dimension); without it the CP generates no
		// Workload for this proxy. On Kubernetes the injector sets it from the pod,
		// so only flag non-k8s dataplanes that are missing it.
		if !onK8s && it.Labels["kuma.io/workload"] == "" {
			a.rep.addDoc(blocker, "Workload grouping", "Universal Dataplane missing kuma.io/workload label",
				"On Universal the `kuma.io/workload` label groups proxies into a Workload (the 3.0 metrics/traces dimension); without it no Workload is generated for this proxy. Add a `kuma.io/workload` label.", docAnnotations, qualified(it))
		}
		// Universal-only: spec.probes is removed in 3.0. On Kubernetes probes are
		// derived from the pod and need no action, so only flag non-k8s dataplanes.
		if hasJSON(spec.Probes) && !onK8s {
			a.rep.addDoc(blocker, "Dataplane probes", "Dataplane has a probes section",
				"Dataplane `spec.probes` is removed for Universal in 3.0 (app-probe-proxy supersedes it).", docDataPlaneProxy, qualified(it))
		}
		// A per-proxy metrics backend (on k8s, translated from the deprecated
		// `prometheus.metrics.kuma.io/*` pod annotations) moves to MeshMetric.
		if hasJSON(spec.Metrics) {
			a.rep.addDoc(blocker, "Dataplane metrics", "Dataplane has a per-proxy metrics override",
				"`Dataplane.spec.metrics` (from `prometheus.metrics.kuma.io/*` annotations on k8s) is deprecated; move per-proxy metrics to the MeshMetric policy.", docMeshMetric, qualified(it))
		}
		a.checkDataplaneLabels(it, onK8s)
		a.checkDataplaneNetworking(it, spec, onK8s)
	}
	return nil
}

// checkDataplaneLabels flags the two Dataplane labels whose meaning changes in
// 3.0: the delegated-gateway marker (only "true" marks a gateway now) and the
// Kubernetes ServiceAccount label, which 3.0 treats as control-plane-owned.
func (a *auditor) checkDataplaneLabels(it resourceItem, onK8s bool) {
	// 3.0 marks a delegated gateway with the kuma.io/gateway *label* and reads it
	// as a boolean: only "true" is a gateway. Universal-only: on Kubernetes the
	// label is recomputed from the Pod's kuma.io/gateway annotation on every
	// reconcile (and deleted when the Pod is not a gateway), so a stray value
	// there fixes itself — and "set it to true" would be actively wrong advice.
	if v, ok := it.Labels[gatewayLabel]; !onK8s && ok && v != "true" && v != "false" {
		a.rep.addDoc(blocker, "Gateway in Dataplane", "Dataplane kuma.io/gateway label is not a boolean",
			"3.0 marks a delegated gateway with the `kuma.io/gateway` label and accepts only `true`/`false`; any other value (e.g. the 2.x `enabled` annotation value) leaves the proxy silently unmarked as a gateway. Set the label to `true` (current: "+v+").",
			docDelegatedGateway, qualified(it))
	}
	// k8s.kuma.io/service-account is computed by the control plane from the Pod and
	// feeds the proxy's identity. In 3.0 the admission webhook rejects a
	// user-applied resource carrying it, and xDS auth refuses a proxy whose label
	// does not match its Pod's ServiceAccount. On Kubernetes the label is
	// legitimate on every CP-created Dataplane and the API cannot tell those from
	// GitOps-applied copies (a manual check covers that); on Universal there is no
	// ServiceAccount at all, so the label can only be a copied leftover.
	if !onK8s && it.Labels[serviceAccountLabel] != "" {
		a.rep.addDoc(blocker, "Dataplane identity", "Universal Dataplane carries the k8s.kuma.io/service-account label",
			"`k8s.kuma.io/service-account` is a control-plane-computed Kubernetes identity label; on Universal it has no source and 3.0 rejects user-applied resources that carry it. Remove the label from this Dataplane before upgrading.",
			docMeshIdentity, qualified(it))
	}
}

// checkDataplaneNetworking flags networking fields 3.0 rejects on write, drops
// from the proto, or silently ignores. The hand-written-Universal-only ones are
// gated on env: on Kubernetes the control plane generates the Dataplane and a 3.0
// control plane regenerates it, so there is nothing for an operator to migrate.
func (a *auditor) checkDataplaneNetworking(it resourceItem, spec dataplaneSpec, onK8s bool) {
	net := spec.Networking
	if net == nil {
		return
	}
	if !onK8s {
		// 3.0 reserves networking.gateway and marks a delegated gateway with the
		// kuma.io/gateway label instead. A 2.x Universal gateway carries the marker
		// only in the spec (2.x never computes the label), so on 3.0 it silently
		// becomes a proxy with no inbounds and no gateway marking, selected by no
		// policy. Builtin gateways have no replacement at all.
		if g := net.Gateway; g != nil {
			switch {
			case strings.EqualFold(g.Type, "BUILTIN"):
				a.rep.addDoc(blocker, "Gateway in Dataplane", "Dataplane is a builtin gateway",
					"`networking.gateway.type: BUILTIN` is removed in 3.0 along with the rest of Kuma's own gateway support; migrate this proxy to a delegated gateway (Kong or another third-party) before upgrading.",
					docDelegatedGateway, qualified(it))
			case it.Labels[gatewayLabel] != "true":
				a.rep.addDoc(blocker, "Gateway in Dataplane", "Dataplane marks a gateway with networking.gateway",
					"3.0 reserves `networking.gateway` and marks a delegated gateway with the `kuma.io/gateway: \"true\"` label instead. This proxy still carries the marker in its spec and does not carry the label, so on 3.0 it becomes a proxy with no inbounds and no gateway marking, selected by no policy. Set the `kuma.io/gateway` label to `\"true\"` before upgrading.",
					docDelegatedGateway, qualified(it))
			}
		}
		if net.AdvertisedAddress != "" {
			a.rep.addDoc(blocker, "Dataplane networking", "Dataplane uses networking.advertisedAddress",
				"`networking.advertisedAddress` is removed in 3.0 (the proto field is reserved); drop it and advertise the address through the zone proxy configuration instead.",
				docDataPlaneProxy, qualified(it))
		}
		for _, in := range net.Inbound {
			if len(in.Tags) > 0 {
				a.rep.addDoc(blocker, "Dataplane networking", "Dataplane uses networking.inbound[].tags",
					"`networking.inbound[].tags` is removed in 3.0 (the proto field is reserved); move the tags to Dataplane labels and select proxies through MeshService. This pairs with `experimental.inboundTagsDisabled: true` on the control plane.",
					docMeshService, qualified(it))
				break
			}
		}
		for _, out := range net.Outbound {
			if !hasJSON(out.BackendRef) {
				a.rep.addDoc(blocker, "Dataplane networking", "Dataplane outbound has no backendRef",
					"3.0 rejects `networking.outbound[]` entries without a `backendRef` on write and NACKs them over KDS; replace tag-based outbounds with a `backendRef` pointing at a MeshService, MeshExternalService or MeshMultiZoneService.",
					docMeshService, qualified(it))
				break
			}
		}
	}
	tp := net.TransparentProxying
	if tp == nil {
		return
	}
	if len(tp.ReachableServices) > 0 {
		a.rep.addDoc(blocker, "reachableServices", "Dataplane uses reachableServices",
			"Replace `reachableServices` with `reachableBackends` (MeshService-based).", docReachableBackends, qualified(it))
	}
	// Only the named entries matter: a list that also carries `*` already grants
	// direct access to everything, so 3.0 dropping per-service matching changes
	// nothing for it.
	if !slices.Contains(tp.DirectAccessServices, "*") && len(tp.DirectAccessServices) > 0 {
		a.rep.addDoc(blocker, "Dataplane networking", "Dataplane names individual directAccessServices",
			"3.0 honors only the `*` entry in `networking.transparentProxying.directAccessServices` — per-service matching relied on a removed tag and is silently ignored, so this proxy loses direct access entirely. Replace the named services with `*`, or drop direct access for this proxy.",
			docTransparentProxy, qualified(it))
	}
}

// dpOverview is the /dataplanes+insights slice checkOutboundDefaults reads: the
// Dataplane spec (nested under "dataplane") plus the transparent-proxy block
// kuma-dp reports in its node metadata. Both are needed — a proxy can enable
// transparent proxying through kuma-dp alone, with nothing in its spec.
type dpOverview struct {
	Dataplane struct {
		Networking *dataplaneNetworking `json:"networking"`
	} `json:"dataplane"`
	DataplaneInsight struct {
		Metadata struct {
			TransparentProxy *struct {
				Redirect struct {
					Inbound  trafficFlow `json:"inbound"`
					Outbound trafficFlow `json:"outbound"`
				} `json:"redirect"`
			} `json:"transparentProxy"`
		} `json:"metadata"`
	} `json:"dataplaneInsight"`
}

type trafficFlow struct {
	Enabled bool `json:"enabled"`
}

// transparentProxy reports whether the 3.0 reachable-backends default applies to
// this proxy. kuma-dp's reported config wins over the spec's legacy redirect
// ports, mirroring the control plane's precedence (tproxy_dp.GetDataplaneConfig).
func (o dpOverview) transparentProxy() bool {
	if tp := o.DataplaneInsight.Metadata.TransparentProxy; tp != nil {
		return tp.Redirect.Inbound.Enabled || tp.Redirect.Outbound.Enabled
	}
	tp := o.Dataplane.Networking.transparentProxying()
	return tp.RedirectPortInbound != 0 || tp.RedirectPortOutbound != 0
}

// checkOutboundDefaults flags the proxies 3.0 leaves with no outbounds at all.
// Absence-triggered — the proxy that configures nothing is the one that breaks —
// so it reports one "N of M" summary per environment, each with that
// environment's fix. Reads /dataplanes+insights for kuma-dp's own transparent-proxy
// config, which /dataplanes cannot show.
func (a *auditor) checkOutboundDefaults(ctx context.Context) error {
	items, observed := a.listCollObserved(ctx, a.scopedPath("dataplanes+insights"))
	if !observed {
		return nil
	}
	// [0] = Universal, [1] = Kubernetes, indexed by the onK8s flag; denied and
	// refs are further split by the governing control plane's outboundMode.
	var total [2]int
	var denied [2][3]int
	var refs [2][3][]string
	for _, it := range items {
		var ov dpOverview
		// Not a policy spec: a decode failure is skipped, not counted as a parse
		// error (checkDataplanes covers the spec itself).
		if json.Unmarshal(it.specBytes(), &ov) != nil {
			continue
		}
		if !ov.transparentProxy() {
			continue
		}
		// A builtin gateway cannot exist on 3.0 at all, so its outbounds are moot.
		if g := ov.Dataplane.Networking.gateway(); strings.EqualFold(g, "BUILTIN") {
			continue
		}
		a.tpProxies = append(a.tpProxies, it)
		env := 0
		if it.Labels[envLabel] == "kubernetes" {
			env = 1
		}
		total[env]++
		if ov.Dataplane.Networking.keepsOutbounds() {
			continue
		}
		mode := a.outboundModeFor(it)
		denied[env][mode]++
		if len(refs[env][mode]) < ExampleCap {
			refs[env][mode] = append(refs[env][mode], qualified(it))
		}
	}
	for _, mode := range []outboundMode{outboundUnset, outboundAllowed, outboundRestricted} {
		a.addOutboundDenyFinding("Universal Dataplanes", "Universal",
			"Add `networking.transparentProxying.reachableBackends.refs` to each Dataplane, naming the MeshServices the workload actually calls",
			mode, denied[0][mode], total[0], refs[0][mode])
		a.addOutboundDenyFinding("Kubernetes dataplanes", "Kubernetes",
			"Add the `kuma.io/reachable-backends` annotation to each Pod (the control plane copies it onto the Dataplane), naming the MeshServices the workload actually calls",
			mode, denied[1][mode], total[1], refs[1][mode])
	}
	return nil
}

// addOutboundDenyFinding reports the proxies without reachableBackends governed
// by control planes in one outboundMode. Only an unset switch breaks on upgrade:
// a pinned `false` keeps allow-all on 3.0, and `true` already denies today.
func (a *auditor) addOutboundDenyFinding(subject, env, fix string, mode outboundMode, denied, total int, refs []string) {
	sev := info
	var impact string
	switch mode {
	case outboundUnset:
		sev = blocker
		impact = "In 2.x an unset `reachableBackends` means *every* destination in the mesh; 3.0 flips that default to none, so these proxies get no outbound clusters and every in-mesh call they make fails. " +
			fix + ". " + restrictOutboundRemediation
	case outboundAllowed:
		impact = "`defaults.restrictOutbound` is explicitly `false` here, which 3.0 honors, so these proxies keep reaching every destination after the upgrade as long as the 3.0 control plane keeps that setting. " +
			"Setting `reachableBackends` is still recommended — it lists exactly what the workload may reach, improving security, and keeps its proxy configuration small, improving control plane and proxy performance — and it is required before switching to `true`. " + fix + "."
	case outboundRestricted:
		// The CP already denies what 3.0 will, so the upgrade changes nothing for
		// these proxies; a proxy that calls nothing in the mesh is correct as is.
		impact = "`defaults.restrictOutbound` is already `true` here, so the upgrade does not change these proxies: they resolve no in-mesh outbound clusters today. That is correct for a workload that calls nothing in the mesh. For any other, setting `reachableBackends` is recommended — it lists exactly what the workload may reach, improving security, and keeps its proxy configuration small, improving control plane and proxy performance. " + fix + "."
	}
	a.rep.addSummary(sev, "Outbound defaults", subject+" have no reachableBackends",
		fmt.Sprintf("%d of %d transparent-proxy %s data plane proxies define neither `reachableBackends` nor an outbound with a `backendRef`. %s",
			denied, total, env, impact),
		docReachableBackends, denied, refs)
}

// checkPassthroughDefault flags transparent proxies that lose external egress
// when 3.0 stops giving a proxy matched by no MeshPassthrough a passthrough
// cluster. Selection is read from the control plane (`_resources/dataplanes`,
// the matcher xDS uses) rather than reimplemented, since it depends on zone
// origin, namespace role and KRI names; a mesh whose selection cannot be read
// is a coverage gap, never flagged. Meshes that already turn passthrough off
// are skipped.
func (a *auditor) checkPassthroughDefault(ctx context.Context) error {
	items, observed := a.listCollObserved(ctx, a.scopedPath("meshpassthroughs"))
	if !observed || len(a.tpProxies) == 0 {
		return nil
	}
	affectedMeshes := map[string]bool{}
	for _, it := range a.tpProxies {
		affectedMeshes[it.Mesh] = !a.passthroughOff[it.Mesh]
	}
	selected := map[string]bool{}
	unresolved := map[string]bool{}
	for _, p := range items {
		if !affectedMeshes[p.Mesh] || unresolved[p.Mesh] || p.Labels["kuma.io/effect"] == "shadow" {
			continue
		}
		path := "/meshes/" + url.PathEscape(p.Mesh) + "/meshpassthroughs/" + url.PathEscape(p.Name) + "/_resources/dataplanes"
		dps, found, err := a.c.list(ctx, path)
		var listErr *listError
		switch {
		case err != nil && errors.As(err, &listErr) && listErr.kind == listErrResourceLimit:
			if !a.resourceLimitGapRecorded {
				a.rep.addGap(path, collectionReadGapReason(err))
				a.resourceLimitGapRecorded = true
			}
			unresolved[p.Mesh] = true
		case err != nil:
			a.rep.addGap(path, collectionReadGapReason(err)+" (passthrough default NOT audited for mesh "+p.Mesh+")")
			unresolved[p.Mesh] = true
		case !found:
			a.rep.addGap(path, "endpoint returned 404 — passthrough default NOT audited for mesh "+p.Mesh)
			unresolved[p.Mesh] = true
		}
		for _, dp := range dps {
			selected[p.Mesh+"/"+dp.Name] = true
		}
	}
	var refs [3][]string
	var affected [3]int
	eligible := 0
	for _, it := range a.tpProxies {
		if !affectedMeshes[it.Mesh] || unresolved[it.Mesh] {
			continue
		}
		eligible++
		if selected[it.Mesh+"/"+it.Name] {
			continue
		}
		mode := a.outboundModeFor(it)
		affected[mode]++
		if len(refs[mode]) < ExampleCap {
			refs[mode] = append(refs[mode], qualified(it))
		}
	}
	const fix = "Add a MeshPassthrough selecting every proxy that needs external egress, or model those destinations as MeshExternalServices."
	for _, mode := range []outboundMode{outboundUnset, outboundAllowed, outboundRestricted} {
		sev := blocker
		var impact string
		switch mode {
		case outboundUnset:
			impact = "In 2.x a proxy matched by no MeshPassthrough still gets a passthrough cluster, so anything the application dials that the mesh does not know about still leaves the proxy; 3.0 makes the no-policy case behave like `passthroughMode: None` and drops that traffic. " +
				fix + " " + restrictOutboundRemediation
		case outboundAllowed:
			sev = info
			impact = "`defaults.restrictOutbound` is explicitly `false` here, which 3.0 honors, so these proxies keep their passthrough cluster after the upgrade as long as the 3.0 control plane keeps that setting. " +
				"Selecting them with a MeshPassthrough is required before switching to `true`. " + fix
		case outboundRestricted:
			impact = "`defaults.restrictOutbound` is already `true` here, so a proxy matched by no MeshPassthrough has no passthrough cluster today and its external egress is already dropped — the upgrade will not change that. " + fix
		}
		a.rep.addSummary(sev, "Outbound defaults", "Transparent proxies selected by no MeshPassthrough",
			fmt.Sprintf("%d of %d transparent-proxy data plane proxies are selected by no MeshPassthrough. %s", affected[mode], eligible, impact),
			docMeshPassthrough, affected[mode], refs[mode])
	}
	return nil
}

func (a *auditor) checkZoneProxies(ctx context.Context) error {
	for _, wsPath := range []string{"zoneingresses", "zoneegresses"} {
		items := a.listColl(ctx, "/"+wsPath)
		for _, it := range items {
			// A ZoneIngress makes its zone a cross-zone destination, which is what
			// MeshZoneAddress has to advertise in 3.0 (checkMeshZoneAddresses).
			if wsPath == "zoneingresses" && it.Labels[envLabel] == "universal" {
				a.noteZoneProxy(zoneOf(it))
			}
			a.rep.addDoc(blocker, "Zone proxies", wsPath+" present",
				"Separate ZoneIngress/ZoneEgress resources are replaced by the unified Zone Proxy (Listener types embedded in the Dataplane), which functions only in `meshServices.mode: Exclusive`; plan the migration before upgrading to 3.0.", docZoneProxies, it.Name)
		}
	}
	return nil
}

// noteZoneProxy records that a zone terminates cross-zone traffic on Universal.
// An unnamed zone (a standalone CP, or a resource with no zone attribution) is
// dropped: MeshZoneAddress is a per-zone requirement and cannot be checked
// without one.
func (a *auditor) noteZoneProxy(zone string) {
	if zone == "" {
		return
	}
	if a.zoneProxyZones == nil {
		a.zoneProxyZones = map[string]bool{}
	}
	a.zoneProxyZones[zone] = true
}

// noteMeshZone records that a mesh has proxies in a zone. A mesh present in two
// or more zones is one whose services can be consumed across zones, which is the
// precondition for needing a MeshZoneAddress (see checkMeshZoneAddresses).
func (a *auditor) noteMeshZone(mesh, zone string) {
	if mesh == "" || zone == "" {
		return
	}
	if a.meshZones == nil {
		a.meshZones = map[string]map[string]bool{}
	}
	if a.meshZones[mesh] == nil {
		a.meshZones[mesh] = map[string]bool{}
	}
	a.meshZones[mesh][zone] = true
}

// zoneOf attributes a resource to a zone: the kuma.io/zone label a global stamps
// on every KDS-synced resource, falling back to the ZoneIngress/ZoneEgress `zone`
// spec field (which a zone CP serves without the label).
func zoneOf(it resourceItem) string {
	if z := it.Labels[zoneLabel]; z != "" {
		return z
	}
	var spec struct {
		Zone string `json:"zone"`
	}
	if json.Unmarshal(it.specBytes(), &spec) != nil {
		return ""
	}
	return spec.Zone
}

// checkZoneNames flags Zone names that are not RFC-1035 DNS labels. In 3.0 a zone
// control plane refuses to start unless its name is a label and the global rejects
// it on connect, while the Helm chart still accepts dots — so a zone named
// `eu.west` passes `helm upgrade` and then crash-loops. Only a global stores Zone
// resources (they are not synced down to zones), so a 404 means "no zones here",
// not a coverage gap; a directly audited zone CP is covered by its own
// `multizone.zone.name` in checkControlPlaneConfig instead.
func (a *auditor) checkZoneNames(ctx context.Context) error {
	for _, it := range a.listIfServed(ctx, "/zones") {
		a.addZoneNameFinding(displayName(it), it.Name)
	}
	return nil
}

// addZoneNameFinding records the non-RFC-1035 zone-name blocker for one zone. ref
// names the zone as the report should show it (the resource name on a global, the
// configured name on a directly audited zone CP).
func (a *auditor) addZoneNameFinding(name, ref string) {
	if name == "" || validRFC1035(name) {
		return
	}
	a.rep.addDoc(blocker, "Non-RFC-1035 names", "Zone name is not a valid RFC-1035 DNS label",
		"A 3.0 zone control plane refuses to start unless its name is a lowercase RFC-1035 DNS label (\u226463 chars, starting with a letter), and the global rejects the zone on connect. The Helm chart still accepts dots, so such a zone upgrades cleanly and then crash-loops \u2014 rename it before upgrading.",
		docUpgrade, ref)
}

// checkMeshZoneAddresses flags a mesh/zone pair that needs a MeshZoneAddress and
// has none. In 3.0 cross-zone MeshService traffic to a zone stays down until a
// MeshZoneAddress advertises that zone's ingress address, and the resource is
// mesh-scoped: every mesh whose services are consumed from another zone needs its
// own in the zone that serves them. Three preconditions keep this off estates
// that cannot be affected: a multi-zone global (a single zone has no cross-zone
// traffic to lose), a mesh with proxies in two or more zones (a zone-local mesh
// is never consumed across zones), and a Universal zone proxy — on Kubernetes the
// 3.0 control plane creates the resource itself from the zone-proxy Service, so
// there is nothing for an operator to do.
func (a *auditor) checkMeshZoneAddresses(ctx context.Context) error {
	if len(a.zoneProxyZones) == 0 {
		return nil
	}
	zones, found, err := a.zoneInsights(ctx)
	if err != nil || !found || len(zones) < 2 {
		// Not a multi-zone global (or the zones overview already gapped out in
		// checkControlPlaneConfig, which reports it once).
		return nil
	}
	required := a.requiredZoneAddresses()
	if len(required) == 0 {
		return nil
	}
	path := a.scopedPath("meshzoneaddresses")
	addrs, served, err := a.c.list(ctx, path)
	if err != nil {
		a.rep.addGap(path, collectionReadGapReason(err))
		return nil
	}
	if !served {
		// The CP does not serve MeshZoneAddress, so cross-zone 3.0 readiness cannot
		// be observed here at all. That is a coverage gap, not an implicit pass.
		a.rep.addGap(path, "endpoint returned 404 — this control plane does not serve MeshZoneAddress; per-zone cross-zone readiness NOT audited (upgrade to the latest 2.14 patch, which registers the resource)")
		return nil
	}
	covered := map[string]bool{}
	for _, it := range addrs {
		if z := zoneOf(it); z != "" && it.Mesh != "" {
			covered[it.Mesh+"/"+z] = true
		}
	}
	for _, mz := range required {
		if covered[mz] {
			continue
		}
		mesh, zone, _ := strings.Cut(mz, "/")
		a.rep.addDoc(blocker, "Zone proxies", "Mesh has no MeshZoneAddress for a zone it spans",
			"MeshZoneAddress is mesh-scoped: every mesh whose services are consumed from another zone needs its own resource in the zone that serves them, or cross-zone MeshService traffic to that mesh is down on 3.0. This mesh has proxies in more than one zone and this zone terminates cross-zone traffic on Universal, but no MeshZoneAddress in the mesh advertises it. 2.14 already registers the type, so create it before upgrading. (Kubernetes zones are not flagged — there the 3.0 control plane creates the resource from the zone-proxy Service.)",
			docZoneProxies, "mesh "+mesh+", zone "+zone)
	}
	return nil
}

// requiredZoneAddresses returns the sorted "<mesh>/<zone>" pairs that need a
// MeshZoneAddress: each zone-spanning mesh crossed with the Universal zones that
// terminate cross-zone traffic and hold proxies of that mesh.
func (a *auditor) requiredZoneAddresses() []string {
	var required []string
	for mesh, zones := range a.meshZones {
		if len(zones) < 2 {
			continue
		}
		for zone := range zones {
			if a.zoneProxyZones[zone] {
				required = append(required, mesh+"/"+zone)
			}
		}
	}
	slices.Sort(required)
	return required
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
		items := a.listIfServed(ctx, a.scopedPath(rc.wsPath))
		for _, it := range items {
			a.checkName(it, rc.kind)
		}
	}
	return nil
}

// checkMeshTrust flags MeshTrust resources still carrying the deprecated
// spec.origin (moved to status.origin in 3.0).
func (a *auditor) checkMeshTrust(ctx context.Context) error {
	items := a.listIfServed(ctx, a.scopedPath("meshtrusts"))
	for _, it := range items {
		var spec struct {
			Origin json.RawMessage `json:"origin"`
		}
		if json.Unmarshal(it.specBytes(), &spec) == nil && hasJSON(spec.Origin) {
			a.rep.addDoc(blocker, "Relocated policy fields", "MeshTrust uses spec.origin",
				"`spec.origin` is deprecated; it moves to `status.origin` in 3.0.", docMeshIdentity, qualified(it))
		}
	}
	return nil
}

// cpConfig captures only the control-plane settings the readiness checks inspect.
// The full GET /config payload is large and carries secrets (e.g. a masked DB
// password); decode just these fields (cf. the resource decode anti-pattern) so
// unknown fields are ignored and the body never has to be echoed.
type cpConfig struct {
	Mode        string `json:"mode"`
	Environment string `json:"environment"`
	// Multizone carries the zone CP's own configured name — the only place a
	// directly audited zone CP exposes it (Zone resources live on the global and
	// are not synced down), so it is what checkZoneNames falls back to there.
	Multizone struct {
		Zone struct {
			Name string `json:"name"`
		} `json:"zone"`
	} `json:"multizone"`
	Experimental struct {
		AutoReachableServices bool `json:"autoReachableServices"`
		DeltaXds              bool `json:"deltaXds"`
		SidecarContainers     bool `json:"sidecarContainers"`
		InboundTagsDisabled   bool `json:"inboundTagsDisabled"`
		KdsEventBasedWatchdog struct {
			Enabled bool `json:"enabled"`
		} `json:"kdsEventBasedWatchdog"`
	} `json:"experimental"`
	// Defaults.RestrictOutbound is absent on a control plane older than the 2.14
	// patch that added it; there, as when it is unset, the permissive 2.x
	// behavior applies, so nil reads as false.
	Defaults struct {
		RestrictOutbound *bool `json:"restrictOutbound"`
	} `json:"defaults"`
	Runtime struct {
		Kubernetes struct {
			Injector struct {
				UnifiedResourceNamingEnabled bool `json:"unifiedResourceNamingEnabled"`
				Ebpf                         struct {
					Enabled bool `json:"enabled"`
				} `json:"ebpf"`
			} `json:"injector"`
		} `json:"kubernetes"`
	} `json:"runtime"`
}

const cpConfigCategory = "Control plane configuration"

// cpConfigDetail renders every Control plane configuration finding as one fixed
// sentence, so the report reads the same way for an operator and stays parseable
// for downstream consumers (e.g. the Konnect console) instead of each check
// phrasing its own remediation. The finding's doc link carries the "why".
func cpConfigDetail(field, from, to string) string {
	return fmt.Sprintf("the field %s value has to be changed from %s to %s", field, from, to)
}

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
		a.rep.addDoc(blocker, cpConfigCategory, "Global control plane on Kubernetes",
			cpConfigDetail("mode", "global", "universal"),
			docUniversal, "mode=global")
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

	// Only for the CP we connected to: on a global, /zones is authoritative for
	// every zone name (checkZoneNames), so checking the fanned-out zone configs
	// too would double-count the same zone.
	if zone == "" {
		a.addZoneNameFinding(cfg.Multizone.Zone.Name, "multizone.zone.name="+cfg.Multizone.Zone.Name)
	}

	// Hard removals — the upgrade breaks while these are in use.
	if cfg.Experimental.AutoReachableServices {
		a.rep.addDoc(blocker, cpConfigCategory, "autoReachableServices enabled",
			cpConfigDetail("experimental.autoReachableServices", "true", "false"),
			docReachableBackends, ref("experimental.autoReachableServices=true"))
	}
	if onK8s && cfg.Runtime.Kubernetes.Injector.Ebpf.Enabled {
		a.rep.addDoc(blocker, cpConfigCategory, "eBPF transparent proxy enabled",
			cpConfigDetail("runtime.kubernetes.injector.ebpf.enabled", "true", "false"),
			docTransparentProxy, ref("runtime.kubernetes.injector.ebpf.enabled=true"))
	}

	// Required 3.0 baseline — the upgrade assumes these are already on (they pair
	// with meshServices.mode: Exclusive), so an estate without them is broken on 3.0.
	if onK8s && !cfg.Runtime.Kubernetes.Injector.UnifiedResourceNamingEnabled {
		a.rep.addDoc(blocker, cpConfigCategory, "Unified resource naming not enabled",
			cpConfigDetail("runtime.kubernetes.injector.unifiedResourceNamingEnabled", "false", "true"),
			docKumaCPReference, ref("runtime.kubernetes.injector.unifiedResourceNamingEnabled=false"))
	}
	if !cfg.Experimental.InboundTagsDisabled {
		a.rep.addDoc(blocker, cpConfigCategory, "Inbound tags still enabled",
			cpConfigDetail("experimental.inboundTagsDisabled", "false", "true"),
			docMeshService, ref("experimental.inboundTagsDisabled=false"))
	}

	// Settings that become the default in 3.0 — enable and validate before upgrading.
	if !cfg.Experimental.DeltaXds {
		a.rep.addDoc(blocker, cpConfigCategory, "Delta xDS not enabled",
			cpConfigDetail("experimental.deltaXds", "false", "true"),
			docKumaCPReference, ref("experimental.deltaXds=false"))
	}
	if !cfg.Experimental.KdsEventBasedWatchdog.Enabled {
		a.rep.addDoc(blocker, cpConfigCategory, "KDS event-based watchdog not enabled",
			cpConfigDetail("experimental.kdsEventBasedWatchdog.enabled", "false", "true"),
			docKumaCPReference, ref("experimental.kdsEventBasedWatchdog.enabled=false"))
	}
	if !cfg.Experimental.SidecarContainers {
		a.rep.addDoc(blocker, cpConfigCategory, "Native sidecar containers not enabled",
			cpConfigDetail("experimental.sidecarContainers", "false", "true"),
			docKumaCPReference, ref("experimental.sidecarContainers=false"))
	}
	a.noteOutboundDefault(cfg, zone, ref)
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
	for _, s := range slices.Backward(subs) {
		if v := s.Version.KumaCp.Version; v != "" {
			return v, true
		}
	}
	return "", false
}

// outboundMode is defaults.restrictOutbound as the operator set it, not as it
// takes effect: since kumahq/kuma#18862 the field is a pointer that /config
// serves as null when unset, so an explicit `false` pin — which 3.0 honors — is
// distinguishable from the 2.14 default that 3.0 flips.
type outboundMode int

const (
	// outboundUnset also covers a control plane predating the switch (every 2.14
	// patch up to 2.14.5), which omits the field and behaves as `false` today.
	outboundUnset outboundMode = iota
	outboundAllowed
	outboundRestricted
)

func outboundModeOf(v *bool) outboundMode {
	switch {
	case v == nil:
		return outboundUnset
	case *v:
		return outboundRestricted
	default:
		return outboundAllowed
	}
}

func (m outboundMode) String() string {
	switch m {
	case outboundAllowed:
		return "false"
	case outboundRestricted:
		return "true"
	default:
		return "unset"
	}
}

// noteOutboundDefault records the defaults.restrictOutbound mode of the control
// plane governing zone's proxies ("" for the audited CP) and reports what the
// upgrade does to it. Unset and pinned `false` are info: the per-proxy and
// per-mesh consequences are gated by checkOutboundDefaults and
// checkPassthroughDefault, which read the mode recorded here.
func (a *auditor) noteOutboundDefault(cfg cpConfig, zone string, ref func(string) string) {
	mode := outboundModeOf(cfg.Defaults.RestrictOutbound)
	if a.outboundModes == nil {
		a.outboundModes = map[string]outboundMode{}
	}
	a.outboundModes[zone] = mode
	switch mode {
	case outboundUnset:
		a.rep.addDoc(info, cpConfigCategory, "Default outbound changes in 3.0",
			"`defaults.restrictOutbound` is not set, so it follows the default: `false` on 2.14 and `true` in 3.0. After the upgrade a proxy with no `reachableBackends` reaches nothing and a proxy matched by no MeshPassthrough loses outbound passthrough. "+
				"To keep today's behavior, set it explicitly to `false` before upgrading and keep that setting on 3.0. To adopt the 3.0 behavior, set it to `true` now and validate — the control plane then denies exactly what 3.0 will, so the proxies and meshes this report flags break here instead of after the upgrade.",
			docReachableBackends, ref("defaults.restrictOutbound="+mode.String()))
	case outboundAllowed:
		a.rep.addDoc(info, cpConfigCategory, "Outbound default pinned to 2.x behavior",
			"`defaults.restrictOutbound` is explicitly `false`, which 3.0 honors, so proxies without `reachableBackends` keep reaching every destination and proxies no MeshPassthrough selects keep passthrough after the upgrade. "+
				"Keep the setting (`KUMA_DEFAULTS_RESTRICT_OUTBOUND=false`) in the 3.0 control plane configuration — dropping it applies the 3.0 default of `true`. It keeps the permissive behavior 3.0 turns off by default, so plan to define `reachableBackends` and MeshPassthrough and then switch it to `true`.",
			docReachableBackends, ref("defaults.restrictOutbound="+mode.String()))
	case outboundRestricted:
	}
}

// outboundModeFor returns the defaults.restrictOutbound mode of the control
// plane governing it: the audited CP when that runs proxies, otherwise its zone's
// as reported to the global. A zone whose config was not observed (a coverage gap
// recorded by checkZoneControlPlaneConfigs) is treated as unset, the case the
// upgrade breaks.
func (a *auditor) outboundModeFor(it resourceItem) outboundMode {
	if m, ok := a.outboundModes[""]; ok {
		return m
	}
	return a.outboundModes[zoneOf(it)]
}

// checkZoneControlPlaneConfigs audits the data-plane-relevant CP settings of
// every zone of a global CP, sourcing each zone's config from ZoneInsight so a
// single audit of the global covers all zones. A zone that has reported no
// config, or whose collection is unreachable, is a coverage gap — never a silent
// pass (an unobserved zone is not a clean zone).
func (a *auditor) checkZoneControlPlaneConfigs(ctx context.Context) error {
	items, found, err := a.zoneInsights(ctx)
	zonesHitResourceLimit := false
	if err != nil {
		var listErr *listError
		if !errors.As(err, &listErr) || listErr.kind != listErrResourceLimit {
			// Same rationale as /config: an unreadable zones overview (e.g. auth) is a
			// coverage gap, not a reason to abort the whole global audit.
			a.rep.addGap("/zones+insights", "could not read /zones+insights — per-zone control-plane settings NOT audited (pass --token if the CP requires auth)")
			return nil
		}
		if !a.resourceLimitGapRecorded {
			a.rep.addGap("/zones+insights", collectionReadGapReason(err))
			a.resourceLimitGapRecorded = true
		}
		zonesHitResourceLimit = true
	}
	if !found {
		a.rep.addGap("/zones+insights", "endpoint returned 404 — per-zone control-plane settings NOT audited")
		return nil
	}
	if len(items) == 0 {
		if zonesHitResourceLimit {
			return nil
		}
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
	for _, s := range slices.Backward(subs) {
		if s.Config == "" {
			continue
		}
		var cfg cpConfig
		if err := json.Unmarshal([]byte(s.Config), &cfg); err != nil {
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
			fmt.Sprintf("could not determine the latest 2.%d patch — control-plane version currency NOT audited (pass --latest-version to set it explicitly)", UpgradeTargetMinor))
		return nil
	}
	latestMaj, latestMin, latestPatch, ok := ParseSemver(a.latestPatch)
	if !ok {
		a.rep.addGap("--latest-version",
			"latest version "+a.latestPatch+" is not valid semver — version currency NOT audited")
		return nil
	}
	// The check is scoped to the 2.<target> line; a baseline outside it (a stray
	// --latest-version) would make every comparison nonsensical — a gap, not a
	// contradictory finding.
	if latestMaj != 2 || latestMin != UpgradeTargetMinor {
		a.rep.addGap("--latest-version",
			fmt.Sprintf("latest version %s is not a 2.%d patch — version currency NOT audited", a.latestPatch, UpgradeTargetMinor))
		return nil
	}
	// Emitted only once the latest-patch prerequisite above is satisfied, so the
	// "zones are still audited" claim is true rather than aspirational.
	if a.skipAuditedCPVersion {
		a.rep.add(info, cpVersionCategory, "Audited control plane version check out of scope",
			"The caller excluded the audited control plane's own patch level from this check; "+
				"it was NOT checked against the latest 2.x line. Connected zone control planes are still audited.",
			"control plane ("+a.rep.cp.Version+")")
	}
	detail := fmt.Sprintf("Upgrade to the latest 2.%d patch (%s) before upgrading to 3.0; an older 2.x patch or minor is not a supported upgrade source.", UpgradeTargetMinor, a.latestPatch)

	if !a.skipAuditedCPVersion {
		a.flagIfBehind(a.rep.cp.Version, "control plane", latestMin, latestPatch, detail)
	}

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
	maj, minor, patch, ok := ParseSemver(version)
	if !ok {
		a.rep.addGap("version ("+origin+")",
			"reported version "+version+" is not valid semver — version currency NOT audited")
		return
	}
	if behind(maj, minor, patch, latestMin, latestPatch) {
		a.rep.addDoc(blocker, cpVersionCategory,
			fmt.Sprintf("Control plane behind the latest 2.%d patch", UpgradeTargetMinor),
			detail, docUpgrade, origin+" ("+version+")")
	}
}

// checkZoneVersions audits every connected zone's CP version on a global, reading
// each zone's reported version from ZoneInsight. An unreadable overview or a zone
// that reported no version is a coverage gap, never a silent pass.
func (a *auditor) checkZoneVersions(ctx context.Context, latestMin, latestPatch int, detail string) error {
	items, found, err := a.zoneInsights(ctx)
	if err != nil {
		var listErr *listError
		if !errors.As(err, &listErr) || listErr.kind != listErrResourceLimit {
			a.rep.addGap("/zones+insights (versions)",
				"could not read /zones+insights — per-zone control-plane versions NOT audited (pass --token if the CP requires auth)")
			return nil
		}
		if !a.resourceLimitGapRecorded {
			a.rep.addGap("/zones+insights", collectionReadGapReason(err))
			a.resourceLimitGapRecorded = true
		}
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
		// Metadata is the proxy's last-reported xDS node metadata (added to
		// DataplaneInsight in Kuma 2.10). Features is the capability list kuma-dp
		// advertises, letting the audit check per-proxy 3.0 readiness without an
		// Envoy config dump.
		Metadata struct {
			Features []string `json:"features"`
		} `json:"metadata"`
	} `json:"dataplaneInsight"`
}

// featureUnifiedNaming is the kuma-dp flag for the unified (KRI-based) resource
// naming model Kuma 3.0 mandates. kuma-dp advertises it only when the CP has
// unified naming enabled and the proxy has (re)connected since, so a connected
// proxy whose advertised features omit it is not emitting unified names — the CP
// flag is off, or on but the proxy has not reconnected yet.
const featureUnifiedNaming = "feature-unified-resource-naming"

// checkDataplaneVersions flags data planes the control plane itself reports as
// version-incompatible (`kumaCpCompatible: false`): they are already outside the
// supported CP/DP skew window and must be upgraded before a major-version bump.
// Sourced from /dataplanes+insights (the data behind the GUI dashboard), so no
// version parsing is reimplemented here — the CP's verdict is authoritative.
func (a *auditor) checkDataplaneVersions(ctx context.Context) error {
	items := a.listColl(ctx, a.scopedPath("dataplanes+insights"))
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
			a.rep.addDoc(blocker, "Dataplane version", "Dataplane is version-incompatible with the control plane",
				"The control plane reports this proxy's kuma-dp version as incompatible; bring it into the supported skew window before upgrading to 3.0.",
				docUpgrade, qualified(it)+" (kuma-dp "+kd.Version+")")
		}
		// A reported `coredns` dependency means kuma-dp launched the bundled
		// CoreDNS, i.e. the proxy is on the legacy CoreDNS + Envoy DNS-filter
		// path that 3.0 removes. This is a free, every-proxy signal from a
		// payload already fetched here; --inspect-dataplanes deep-confirms it.
		if v := last.Dependencies["coredns"]; v != "" {
			a.rep.addDoc(blocker, "Dataplane DNS", "Dataplane uses the legacy embedded CoreDNS",
				"This proxy reports a bundled CoreDNS dependency; 3.0 removes the CoreDNS + Envoy DNS-filter path — upgrade kuma-dp.",
				docDNS, qualified(it)+" (coredns "+v+")")
		}
		// unified-resource-naming is advertised only when the CP has it enabled and
		// the proxy has (re)connected since, so a proxy whose feature list omits it
		// is not yet on unified naming — the per-proxy blast radius of the CP-level
		// "Unified resource naming not enabled" check, and how stragglers are caught
		// once the CP flag is on. An empty list (older CP that reported no metadata)
		// is not conclusive, so it is skipped rather than flagged as a false gap.
		if feats := ins.DataplaneInsight.Metadata.Features; len(feats) > 0 && !slices.Contains(feats, featureUnifiedNaming) {
			a.rep.addDoc(blocker, "Dataplane features", "Dataplane is not using unified resource naming",
				"This proxy does not advertise the `feature-unified-resource-naming` capability, so it is not emitting the unified (KRI-based) resource names Kuma 3.0 requires. Enable `unifiedResourceNamingEnabled` on the control plane (if not already) and restart/re-inject the proxy so it adopts unified naming before upgrading.",
				docKumaCPReference, qualified(it))
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
	items := a.listColl(ctx, a.scopedPath("dataplanes"))
	inspected := 0
	for i, it := range items {
		if i >= a.inspectDataplanes {
			break
		}
		path := "/meshes/" + url.PathEscape(it.Mesh) + "/dataplanes/" + url.PathEscape(it.Name) + "/xds"
		var dump json.RawMessage
		status, err := a.c.getJSON(ctx, path, &dump)
		if err != nil || status == http.StatusNotFound {
			continue // best-effort: skip offline / unreadable proxies
		}
		inspected++
		if bytes.Contains(dump, dnsFilterMarker) {
			a.rep.addDoc(blocker, "Dataplane DNS", "Dataplane uses the legacy Envoy DNS filter",
				"This proxy's Envoy config still uses the built-in `envoy.filters.udp.dns_filter`; 3.0 drops the Envoy DNS filter for the embedded DNS server — upgrade kuma-dp.",
				docDNS, qualified(it))
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
		a.rep.addDoc(blocker, "Non-RFC-1035 names", kind+" name is not a valid RFC-1035 DNS label",
			"Rename to a lowercase RFC-1035 DNS label (≤63 chars, starting with a letter); non-conforming names are deprecated in 3.0.", docHostnameGenerator, qualified(it))
	}
}

func qualified(it resourceItem) string {
	name := it.Name
	if it.Mesh != "" {
		name = it.Mesh + "/" + it.Name
	}
	// On a global CP, resources synced from zones carry kuma.io/zone. Append it as a
	// parsable suffix so the report can attribute (and filter) the finding by zone.
	// The mesh stays the leading segment, so mesh attribution is unaffected.
	if z := it.Labels["kuma.io/zone"]; z != "" {
		name += " [zone:" + z + "]"
	}
	return name
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

// gatewaySection is the Dataplane's 2.x networking.gateway block: the field 3.0
// reserves in favor of the kuma.io/gateway label. Type defaults to DELEGATED.
type gatewaySection struct {
	Type string `json:"type"`
}

type dataplaneSpec struct {
	Probes     json.RawMessage      `json:"probes"`
	Metrics    json.RawMessage      `json:"metrics"`
	Networking *dataplaneNetworking `json:"networking"`
}

// dataplaneNetworking is shared by the spec decoder (checkDataplanes) and the
// overview decoder (checkOutboundDefaults).
type dataplaneNetworking struct {
	AdvertisedAddress string          `json:"advertisedAddress"`
	Gateway           *gatewaySection `json:"gateway"`
	Inbound           []struct {
		Tags map[string]string `json:"tags"`
	} `json:"inbound"`
	Outbound []struct {
		BackendRef json.RawMessage `json:"backendRef"`
	} `json:"outbound"`
	TransparentProxying *transparentProxying `json:"transparentProxying"`
}

// transparentProxying is the Dataplane's transparentProxying block. The redirect
// ports are the pre-3.0 way to declare transparent proxying. ReachableBackends
// stays raw: only presence matters, and an empty `{"refs":[]}` is a deliberate
// deny, not an absence.
type transparentProxying struct {
	ReachableServices    []string        `json:"reachableServices"`
	DirectAccessServices []string        `json:"directAccessServices"`
	ReachableBackends    json.RawMessage `json:"reachableBackends"`
	RedirectPortInbound  uint32          `json:"redirectPortInbound"`
	RedirectPortOutbound uint32          `json:"redirectPortOutbound"`
}

func (n *dataplaneNetworking) transparentProxying() transparentProxying {
	if n == nil || n.TransparentProxying == nil {
		return transparentProxying{}
	}
	return *n.TransparentProxying
}

func (n *dataplaneNetworking) gateway() string {
	if n == nil || n.Gateway == nil {
		return ""
	}
	return n.Gateway.Type
}

// keepsOutbounds reports whether this proxy still gets outbound clusters on 3.0:
// it either selects destinations explicitly (any reachableBackends value), or
// defines a backendRef outbound, which short-circuits resolution entirely.
func (n *dataplaneNetworking) keepsOutbounds() bool {
	if n == nil {
		return false
	}
	if raw := n.transparentProxying().ReachableBackends; len(raw) > 0 && string(raw) != "null" {
		return true
	}
	for _, out := range n.Outbound {
		if hasJSON(out.BackendRef) {
			return true
		}
	}
	return false
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

// httpRouteRule is one MeshHTTPRoute routing rule; only its matches matter here.
type httpRouteRule struct {
	Matches []httpRouteMatch `json:"matches"`
}

// httpRouteMatch is the subset of a MeshHTTPRoute match the catch-all test needs:
// the path plus the three matchers that, when present, narrow a rule.
type httpRouteMatch struct {
	Path *struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"path"`
	Method      *string           `json:"method"`
	QueryParams []json.RawMessage `json:"queryParams"`
	Headers     []json.RawMessage `json:"headers"`
}

// hasCatchAllRule reports whether any rule matches every request: a match that no
// method, query-parameter or header matcher narrows, and whose path is either the
// `/` prefix or absent (an unset path constrains nothing, so `matches: [{}]`
// matches everything just as `PathPrefix: /` does).
//
// A rule with an empty `matches` LIST is a different thing and is NOT a catch-all
// — route generation iterates the matches, so it emits no routes at all (handled
// separately as a blocker by the caller).
func hasCatchAllRule(rules []httpRouteRule) bool {
	for _, r := range rules {
		for _, m := range r.Matches {
			if m.Method != nil || len(m.QueryParams) > 0 || len(m.Headers) > 0 {
				continue
			}
			if m.Path == nil || (m.Path.Type == "PathPrefix" && m.Path.Value == "/") {
				return true
			}
		}
	}
	return false
}

// targetRefKindOrEmpty renders a targetRef kind for a finding message, naming an
// unset kind explicitly rather than leaving a dangling "kind: ".
func targetRefKindOrEmpty(tr targetRef) string {
	if tr.Kind == "" {
		return "unset"
	}
	return tr.Kind
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
// workloadLabels, the zone CP's own name) are audited automatically by
// checkControlPlaneConfig, Universal Dataplane labels and networking fields by
// checkDataplanes, zone names and per-zone MeshZoneAddress coverage by
// checkZoneNames/checkMeshZoneAddresses, and the legacy CoreDNS path by
// checkDataplaneVersions (a reported `coredns` dependency) plus the
// --inspect-dataplanes deep check, so none is repeated here.
var manualChecks = []ManualCheck{
	{
		Title: "Old inspect APIs removed (switch to the new inspect API)",
		Detail: "Kuma 3.0 removes the old dataplane rules-inspection endpoint (`_rules`) and " +
			"keeps only the redesigned, KRI-based inspect API. The dropped endpoint returned " +
			"every policy's rules for a proxy in one nested blob (fromRules/toRules/inboundRules/" +
			"toResourceRules), and it goes away together with `kuma.io/service` routing support. " +
			"The new API splits that into per-scope endpoints that reference resources by KRI, " +
			"listed below. The control-plane API cannot tell you which clients still call the old " +
			"endpoint, whether that's kumactl, the GUI, dashboards, scripts, or monitoring, so you " +
			"have to find and migrate those consumers yourself; a 2.x kumactl or GUI pointed at a " +
			"3.0 CP gets a 404. Upgrade kumactl and the GUI to their 3.0 builds, which already use " +
			"the new endpoints.",
		Command: `# Removed in 3.0
GET /meshes/{mesh}/dataplanes/{name}/_rules

# Replacement endpoints (new KRI-based inspect API)
GET /meshes/{mesh}/dataplanes/{name}/_layout
GET /meshes/{mesh}/dataplanes/{name}/_policies
GET /meshes/{mesh}/dataplanes/{name}/_inbounds/{inbound_kri}/_policies
GET /meshes/{mesh}/dataplanes/{name}/_outbounds/{outbound_kri}/_policies
GET /meshes/{mesh}/dataplanes/{name}/_outbounds/{outbound_kri}/_routes
GET /meshes/{mesh}/dataplanes/{name}/_outbounds/{outbound_kri}/_routes/{route_kri}/_policies`,
	},
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
			"admin token on Universal) plus jq and openssl, and never prints key material. " +
			"Paste the whole script — each section runs only where its CLI is present — then " +
			"rotate anything flagged LEGACY to RSA with `kumactl generate signing-key` and " +
			"reissue tokens before upgrading.",
		Command: `# Detect pre-1.4.x HMAC256 token signing keys (must be asymmetric RSA before 3.0).
# Needs: jq, openssl + secret-read access. Never prints key material.
# Safe to paste whole: each section runs only if its CLI is present.

classify() {  # reads a base64 key on stdin, prints a verdict
  b64=$(cat)
  if printf %s "$b64" | base64 -d 2>/dev/null | openssl rsa -noout 2>/dev/null; then
    echo "OK (RSA PEM)"
  elif printf %s "$b64" | base64 -d 2>/dev/null | openssl rsa -inform DER -noout 2>/dev/null; then
    echo "OK (RSA DER)"
  else
    echo "LEGACY HMAC256 -> ROTATE"
  fi
}

# --- Kubernetes (CP namespace; set NS=kuma-system for open-source Kuma) ---
if command -v kubectl >/dev/null 2>&1; then
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
fi

# --- Universal (point kumactl at the CP) ---
if command -v kumactl >/dev/null 2>&1; then
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
  done
fi`,
	},
	{
		Title: "Re-check kumactl access on a Helm-installed Universal control plane",
		Detail: "A Universal control plane installed from the Helm chart no longer treats " +
			"loopback callers as admin: the chart sets " +
			"`KUMA_API_SERVER_AUTHN_LOCALHOST_IS_ADMIN=false` in 3.0, where 2.x left the " +
			"built-in default of `true`. Operators who reach the API with `kubectl exec` or " +
			"`kubectl port-forward` plus kumactl and no token lose access the moment the " +
			"upgrade rolls out. The control-plane API cannot tell you how the CP was " +
			"installed or how your operators authenticate, so the tool cannot detect this " +
			"for you. The catch is the ordering: the bootstrap admin token can only be read " +
			"over loopback *while the old default is still in effect*, so issue and store a " +
			"real admin user token BEFORE upgrading. The commands below do that against the " +
			"running 2.x CP; skip this item entirely on Kubernetes-mode control planes.",
		Command: `# Run against the 2.x Universal CP, over loopback, BEFORE the upgrade.
# 1. Confirm loopback is still admin (should print the admin user).
kumactl get global-secrets >/dev/null && echo "loopback admin still works"

# 2. Mint a long-lived admin token and store it in your secret manager.
kumactl generate user-token --name upgrade-admin --group mesh-system:admin --valid-for 8760h

# 3. Point kumactl at the CP with that token and verify it works without loopback.
kumactl config control-planes add --name upgraded --address https://<cp-host>:5682 --auth-type=tokens --auth-conf token=<token>
kumactl get meshes`,
	},
}

// kubernetesManualChecks are appended only when the audit observed Kubernetes in
// the estate (see report.k8sObserved). They are Kubernetes-object concerns the CP
// API cannot reveal, so showing them on a Universal-only run would be noise.
var kubernetesManualChecks = []ManualCheck{
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
		Title: "Drop the `kuma.io/tags` Pod annotation",
		Detail: "`kuma.io/tags` let a Pod add arbitrary tags to its Dataplane inbounds. " +
			"Kuma 3.0 has no reader for the annotation at all — it is not deprecated with a " +
			"warning, it is simply ignored — and inbound tags themselves are gone " +
			"(`networking.inbound[].tags` is a reserved proto field). Anything selecting or " +
			"routing on a tag that only existed because of this annotation stops matching " +
			"after the upgrade. The control-plane API exposes the resulting tags but not " +
			"which annotation produced them, so the tool cannot attribute them for you. " +
			"Find the Pods still setting it, then move the values to Pod labels and select " +
			"the workloads through MeshService instead. Empty output means there is nothing " +
			"left to fix.",
		Command: `kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.annotations["kuma.io/tags"]) | [.metadata.namespace, .metadata.name, .metadata.annotations["kuma.io/tags"]] | @tsv'`,
	},
	{
		Title: "Remove `k8s.kuma.io/service-account` from hand-applied Dataplanes",
		Detail: "The `k8s.kuma.io/service-account` label is computed by the control plane " +
			"from the Pod and feeds the proxy's identity. In 3.0 the admission webhook " +
			"rejects any Dataplane create or update that carries it unless the caller is the " +
			"control plane itself or is listed in `runtime.kubernetes.allowedUsers`, and xDS " +
			"auth refuses a proxy whose label does not match its Pod's ServiceAccount. A " +
			"GitOps pipeline that captured a live Dataplane and replays it — label included — " +
			"starts failing to apply, and the proxies stop connecting. Every Dataplane the " +
			"control plane created is owned by its Pod, so the ones with no ownerReference " +
			"are the hand-applied copies; the API alone cannot make that distinction, which " +
			"is why this is a manual check. The command lists them: drop the label (and the " +
			"matching annotation) from the manifests in your repository. Empty output means " +
			"there is nothing left to fix.",
		Command: `kubectl get dataplanes.kuma.io -A -o json | jq -r '.items[] | select((.metadata.ownerReferences // []) | length == 0) | select(.metadata.labels["k8s.kuma.io/service-account"] // .metadata.annotations["k8s.kuma.io/service-account"]) | [.metadata.namespace, .metadata.name] | @tsv'`,
	},
}

// buildManualChecks returns the manual checklist for a run, appending the
// Kubernetes-only items when the audit positively observed Kubernetes.
func buildManualChecks(k8sObserved bool) []ManualCheck {
	checks := append([]ManualCheck{}, manualChecks...)
	if k8sObserved {
		checks = append(checks, kubernetesManualChecks...)
	}
	return checks
}
