package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
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
	docMeshOPA               = docBase + "/mesh/policies/meshopa/"
	docPolicies              = docBase + "/mesh/policies-introduction/"

	docMeshService          = docBase + "/mesh/meshservice/"
	docMeshServiceExclusive = docBase + "/mesh/meshservice/#exclusive"
	docReachableBackends    = docBase + "/mesh/meshservice/#reachablebackends"
	docMeshExternalService  = docBase + "/mesh/meshexternalservice/"
	docHostnameGenerator    = docBase + "/mesh/hostnamegenerator/"

	docMeshIdentity     = docBase + "/mesh/issue-identity-with-meshidentity/"
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
	docRBAC             = docBase + "/mesh/rbac/"
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
	{"meshgateways", "MeshGateway", gatewayReplacement, docUpgrade, false},
	{"meshgatewayroutes", "MeshGatewayRoute", gatewayReplacement, docUpgrade, false},
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

// enterprisePolicyPaths are Kong Mesh (enterprise) targetRef policies scanned by
// the same checks as newPolicyPaths. An OSS Kuma CP 404s them, so they are listed
// with listIfServed: a 404 there is "not served", not a coverage gap.
var enterprisePolicyPaths = []string{"meshopas"}

// removedEnterprisePolicy is a Kong Mesh (enterprise) resource kind removed in 3.0.
type removedEnterprisePolicy struct{ wsPath, kind, detail, doc string }

// removedEnterprisePolicies lists the Kong Mesh policies removed in 3.0; any
// instance is a blocker (checkRemovedEnterprisePolicies).
var removedEnterprisePolicies = []removedEnterprisePolicy{
	{
		"meshglobalratelimits", "MeshGlobalRateLimit",
		"MeshGlobalRateLimit is removed in 3.0 with no direct replacement (global rate limiting is dropped); remove these policies before upgrading.",
		docPolicies,
	},
	{
		"opa-policies", "OPAPolicy",
		"The legacy OPAPolicy resource and its CRD are removed in 3.0, so a leftover OPAPolicy is no longer enforced and cannot be re-applied. Migrate each one to a MeshOPA policy (top-level `targetRef` kind Mesh or Dataplane) and delete it before upgrading. A MeshOPA with `agentConfig` or `appendPolicies` must use the typed data source shape before the global control plane is upgraded, which needs a 2.14 patch that accepts it (see the MeshOPA data source finding).",
		docMeshOPA,
	},
}

// removedCoreKinds are the remaining resource types a 2.14 control plane
// registers and 3.0 does not (besides legacyMeshScoped and
// removedEnterprisePolicies); removedKindNames folds all three together.
var removedCoreKinds = []string{"ServiceInsight", "ZoneIngress", "ZoneIngressInsight", "ZoneEgress", "ZoneEgressInsight"}

// removedKindNames is the set of resource type names 3.0 no longer registers, so
// any reference to one by name (an AccessRole/AccessAudit `types[]` entry) is
// rejected.
func removedKindNames() map[string]bool {
	names := map[string]bool{}
	for _, lt := range legacyMeshScoped {
		names[lt.kind] = true
	}
	for _, rp := range removedEnterprisePolicies {
		names[rp.kind] = true
	}
	for _, k := range removedCoreKinds {
		names[k] = true
	}
	return names
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
// plane; 3.0 removes gatewayLabel (checkGatewayMarking) and owns
// serviceAccountLabel (checkDataplaneLabels); listenerZoneIngressLabel marks a
// unified Zone Proxy.
const (
	envLabel                 = "kuma.io/env"
	zoneLabel                = "kuma.io/zone"
	kubeNamespaceLabel       = "k8s.kuma.io/namespace"
	gatewayLabel             = "kuma.io/gateway"
	protocolTag              = "kuma.io/protocol"
	serviceAccountLabel      = "k8s.kuma.io/service-account"
	listenerZoneIngressLabel = "kuma.io/listener-zoneingress"
	listenerZoneEgressLabel  = "kuma.io/listener-zoneegress"
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
	// externalServiceMeshes are the meshes with a MeshExternalService, recorded by
	// checkServiceResources for checkExternalServiceIdentity.
	externalServiceMeshes map[string]bool
	// meshMTLS records, for every audited mesh, whether it still has Mesh mTLS,
	// so checkMeshServiceSpec knows where a ServiceTag identity is stale.
	meshMTLS map[string]bool

	c                    *client
	meshFilter           string
	inspectDataplanes    int
	checkVersionCurrency bool
	latestPatch          string
	skipAuditedCPVersion bool
	// EXC:FILE011:the connected zone CP's own name; fills the KRI zone segment of label-less local resources (3.0 materializes the zone on read)
	cpZone string
	// EXC:FILE011:/config was readable early; when it was not, the CP's mode is unknown and a label-less resource might be zone-local
	configKnown bool
	// EXC:FILE011:the connected CP is a zone or standalone, not a global; a Mesh KRI resolves only at the global
	cpNotGlobal bool
	rep         *collector

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

	// cniEnabled records, keyed like outboundModes, the Kubernetes control planes
	// that run the CNI, so checkDataplaneFeatures flags only pods the 3.0 CNI
	// plugin will refuse.
	cniEnabled map[string]bool

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

	// EXC:FILE011:the CP's own zone name fills the KRI zone segment of label-less local resources (3.0 materializes the zone on read)
	var zoneCfg struct {
		Mode      string `json:"mode"`
		Multizone struct {
			Zone struct {
				Name string `json:"name"`
			} `json:"zone"`
		} `json:"multizone"`
	}
	if status, err := a.c.getJSON(ctx, "/config", &zoneCfg); err == nil && status == http.StatusOK {
		a.configKnown = true
		// 3.0 removes the standalone mode, and such a CP upgrades to a zone
		// with the same configured (or "default") name, so both stamp.
		if strings.EqualFold(zoneCfg.Mode, "zone") || strings.EqualFold(zoneCfg.Mode, "standalone") {
			a.cpZone = zoneCfg.Multizone.Zone.Name
			if a.cpZone == "" {
				a.cpZone = "default"
			}
			a.cpNotGlobal = true
		}
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
	a.stampZone(meshes)
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
		a.checkLegacyResources, a.checkRemovedEnterprisePolicies, a.checkAccessControl, a.checkNewPolicies, a.checkDataplanes,
		a.checkZoneProxies, a.checkZoneNames, a.checkMeshZoneAddresses,
		a.checkServiceResources, a.checkExternalServiceIdentity, a.checkMeshTrust,
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
	a.rep.manual = buildManualChecks(a.rep.k8sObserved, a.rep.cp.Product == productKongMesh)
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

// stampZone fills a local resource's missing kuma.io/zone with the connected
// zone CP's own name: 2.x stamps the label on write, but a resource created
// before that and never re-applied carries none, and 3.0 materializes it on
// read — the KRI must carry it to resolve on the upgraded CP. A resource
// synced down from the global (kuma.io/origin: global) keeps no zone.
func (a *auditor) stampZone(items []resourceItem) {
	if a.configKnown && a.cpZone == "" {
		return
	}
	for i := range items {
		it := &items[i]
		if it.Type == "Zone" {
			continue
		}
		// EXC:FILE011:a Mesh is global-scoped and SkipKDSHash — its KRI resolves only at the global, never at a zone CP
		if it.Type == "Mesh" && a.cpNotGlobal {
			it.zoneUnknown = true
			continue
		}
		if it.Labels[zoneLabel] != "" || it.Labels["kuma.io/origin"] == "global" {
			continue
		}
		if a.cpZone != "" {
			if it.Labels == nil {
				it.Labels = map[string]string{}
			}
			it.Labels[zoneLabel] = a.cpZone
			continue
		}
		// EXC:FILE011:zone CP, zone unreadable -> an empty-zone KRI mis-resolves on 3.0 (non-local hash name, 404)
		it.zoneUnknown = true
	}
}

// listCollObserved also reports whether the collection was read: a check that
// concludes something from a resource's absence must not fire on a coverage gap.
// Memoized by path, so a shared collection costs one round-trip and one gap.
func (a *auditor) listCollObserved(ctx context.Context, path string) ([]resourceItem, bool) {
	if r, cached := a.listCache[path]; cached {
		return r.items, r.observed
	}
	items, observed := a.readColl(ctx, path)
	a.stampZone(items)
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
		// EXC:FILE011:a resource-limit hit still returns the admitted partial items — they must carry the zone too
		a.stampZone(items)
		return items, false
	}
	if !found {
		a.rep.addGap(path, "endpoint returned 404 — NOT audited")
		return nil, false
	}
	a.stampZone(items)
	return items, true
}

// listIfServed lists a collection, returning nil when the endpoint is
// unregistered (404) — for resource types newer than the CP may serve, where a
// 404 is "not applicable", not a coverage gap (cf. listColl).
func (a *auditor) listIfServed(ctx context.Context, path string) []resourceItem {
	items, _ := a.listServed(ctx, path)
	return items
}

// listServed is listIfServed that also reports whether the result is complete:
// false after a read error, which is recorded as a coverage gap.
func (a *auditor) listServed(ctx context.Context, path string) ([]resourceItem, bool) {
	items, found, err := a.c.list(ctx, path)
	if err != nil {
		var listErr *listError
		if ctx.Err() == nil && (!errors.As(err, &listErr) || listErr.kind != listErrResourceLimit || !a.resourceLimitGapRecorded) {
			a.rep.addGap(path, collectionReadGapReason(err))
			if errors.As(err, &listErr) && listErr.kind == listErrResourceLimit {
				a.resourceLimitGapRecorded = true
			}
		}
		// EXC:FILE011:a resource-limit hit still returns the admitted partial items — they must carry the zone too
		a.stampZone(items)
		return items, false
	}
	if !found {
		return nil, true
	}
	a.stampZone(items)
	return items, true
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

// ref formats the example of a flagged resource, marking CP-managed
// (policy-role: system) ones so the operator knows which defaults to update.
// It is side-effect free: the system tally is kept by countSystem, which
// counts a resource only when it actually yields a finding (ref is computed
// eagerly, before the checks run, so counting here would over-report
// resources that turn out clean).
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
	ref := func(field string) string { return qualifiedNote(m, field) }

	if spec.Mtls != nil && (spec.Mtls.EnabledBackend != "" || len(spec.Mtls.Backends) > 0) {
		a.rep.addDoc(blocker, "Mesh object settings", "Inline mTLS on Mesh",
			"Migrate `mesh.mtls` to MeshIdentity + MeshTrust.", docMeshIdentity, ref("mtls"))
	}
	if a.meshMTLS == nil {
		a.meshMTLS = map[string]bool{}
	}
	// Kuma's MTLSEnabled: only an enabled backend issues certificates.
	a.meshMTLS[m.Name] = spec.Mtls != nil && spec.Mtls.EnabledBackend != ""
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
			"3.0 requires `meshServices.mode: Exclusive` (it gates Zone Proxy, MeshIdentity and disables legacy kuma.io/service routing); migrate before upgrading (current: "+shown+").", docMeshServiceExclusive, qualified(m))
	}
	if spec.SkipCreatingInitialPolicies != nil {
		skipped := strings.Join(spec.SkipCreatingInitialPolicies, ", ")
		if skipped == "" {
			skipped = "* (empty list)"
		}
		a.rep.addDoc(blocker, "Mesh object settings", "skipCreatingInitialPolicies on Mesh",
			"3.0 removes `mesh.skipCreatingInitialPolicies` (kumahq/kuma#18661): it stops creating default policies for new Meshes altogether, so the field does nothing on the upgraded control plane — it is ignored, the stored Mesh keeps loading and a manifest that still sets it applies without an error, but the first write to the Mesh drops the field. Remove it from every Mesh manifest (GitOps included) before upgrading. Mind the rollback: after that first write, rolling the mesh's control plane back to 2.14 creates the default policies (`mesh-timeout-all-<mesh>`, `mesh-circuit-breaker-all-<mesh>`, `mesh-retry-all-<mesh>`) again — including for a mesh whose list deliberately suppressed them (current value: "+skipped+").",
			docUpgrade, ref("skipCreatingInitialPolicies"))
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
	for _, rp := range removedEnterprisePolicies {
		items := a.listIfServed(ctx, a.scopedPath(rp.wsPath))
		for _, it := range items {
			before := a.rep.total
			a.rep.addDoc(blocker, categoryRemovedPolicy, rp.kind+" (removed in 3.0)", rp.detail, rp.doc, a.ref(it))
			a.countSystem(it, before)
		}
	}
	return nil
}

// productKongMesh is the `product` the Kong Mesh CP reports on `GET /`.
const productKongMesh = "Kong Mesh"

// categoryAccessRoles groups the Kong Mesh RBAC (AccessRole/AccessAudit) findings.
const categoryAccessRoles = "Access roles"

// rbacTargetRef is an AccessRole qualifier targetRef. The 2.14 qualifier has no
// `labels`, so `name` is its only way to narrow a kind. `tags` and `mesh` are not
// decoded: `mesh` was never matched on, and 2.14 accepts `tags` only next to kinds
// 3.0 rejects anyway (MeshSubset, MeshServiceSubset, MeshService) or next to
// MeshMultiZoneService, which has no 2.14 validator branch (unlikely in practice).
type rbacTargetRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type rbacQualifier struct {
	TargetRef *rbacTargetRef `json:"targetRef"`
	From      *struct {
		TargetRef *rbacTargetRef `json:"targetRef"`
	} `json:"from"`
	To *struct {
		TargetRef *rbacTargetRef `json:"targetRef"`
	} `json:"to"`
	Sources      json.RawMessage `json:"sources"`
	Destinations json.RawMessage `json:"destinations"`
	Selectors    json.RawMessage `json:"selectors"`
}

// rbacRule is an AccessRole or AccessAudit rule (AccessAudit has no `when`).
type rbacRule struct {
	Types  []string        `json:"types"`
	Mesh   string          `json:"mesh"`
	Access []string        `json:"access"`
	When   []rbacQualifier `json:"when"`
}

// jsonSet reports a JSON value that is present at all, `{}` included: a proto
// message field set to an empty object still counts as set.
func jsonSet(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// checkAccessControl flags Kong Mesh RBAC resources (global-scoped AccessRole and
// AccessAudit) that 3.0 rejects on write or matches differently, and
// AccessRoleBindings open to unauthenticated callers. All are enterprise-only,
// so an OSS Kuma CP 404s them (listIfServed: not a gap), while a 403 from a
// token without RBAC read access is a coverage gap.
func (a *auditor) checkAccessControl(ctx context.Context) error {
	removed := removedKindNames()
	for _, rc := range []struct{ wsPath, kind string }{
		{"access-roles", "AccessRole"},
		{"accessaudits", "AccessAudit"},
	} {
		for _, it := range a.listIfServed(ctx, "/"+rc.wsPath) {
			ref := a.ref(it)
			var spec struct {
				Rules []rbacRule `json:"rules"`
			}
			if a.unmarshalSpec(it, &spec, ref) {
				a.checkRBACRules(rc.kind, spec.Rules, removed, ref)
				if rc.kind == "AccessRole" {
					a.checkConfigAccess(spec.Rules, ref)
				}
			}
		}
	}
	for _, it := range a.listIfServed(ctx, "/access-role-bindings") {
		a.checkUnauthenticatedBinding(it)
	}
	return nil
}

// unauthenticatedGroups are the groups every caller without a credential
// carries: Kong Mesh's own, and Kubernetes' for requests through the webhook.
var unauthenticatedGroups = []string{"mesh-system:unauthenticated", "system:unauthenticated"}

type rbacSubject struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// checkUnauthenticatedBinding flags an AccessRoleBinding that grants roles to
// callers without a credential. 2.x binds `admin` to them by default; 3.0 stops
// doing so for new control planes but keeps an existing binding as it is.
func (a *auditor) checkUnauthenticatedBinding(it resourceItem) {
	ref := a.ref(it)
	var spec struct {
		Subjects []rbacSubject `json:"subjects"`
		Roles    []string      `json:"roles"`
	}
	if !a.unmarshalSpec(it, &spec, ref) || len(spec.Roles) == 0 {
		return
	}
	if !slices.ContainsFunc(spec.Subjects, func(s rbacSubject) bool {
		return strings.EqualFold(s.Type, "Group") && slices.Contains(unauthenticatedGroups, s.Name)
	}) {
		return
	}
	roles := slices.Clone(spec.Roles)
	slices.Sort(roles)
	a.rep.addDoc(info, categoryAccessRoles, "AccessRoleBinding grants roles to unauthenticated callers",
		"The binding names `mesh-system:unauthenticated` or `system:unauthenticated`, so anyone who reaches the API without a credential holds its roles. With the 2.x default `admin` binding that covers every write, token generation and reading stored Secrets and GlobalSecrets, the bootstrapped admin token included. "+
			"A 3.0 control plane no longer creates these subjects, but it keeps an existing binding unchanged, so the upgrade neither fixes nor breaks this. "+
			"Narrow the binding to authenticated groups (issue user tokens with `kumactl generate user-token` first, and on Kubernetes name every identity that applies mesh resources, such as a GitOps controller), then rotate the admin token if the API was reachable without one.",
		docRBAC, refNote(ref, "roles: "+strings.Join(roles, ", ")))
}

// checkRBACRules records each finding at most once per resource. With --mesh, a
// rule pinned to another mesh is skipped.
func (a *auditor) checkRBACRules(kind string, rules []rbacRule, removed map[string]bool, ref string) {
	flagged := map[string]bool{}
	add := func(sev severity, title, detail string) {
		if !flagged[title] {
			flagged[title] = true
			a.rep.addDoc(sev, categoryAccessRoles, title, detail, docRBAC, ref)
		}
	}
	const byName = "3.0 turns a qualifier `targetRef.name` into a `kuma.io/display-name` label match: the rule only covers policies whose targetRef carries `kuma.io/display-name: <name>`. Policies that select the same proxies or services by other labels (3.0 removes `name` from policy targetRefs) are no longer covered, so writes the role allowed are denied (the grant shrinks, it does not widen). The 2.14 qualifier has no `labels` field, so after upgrading rewrite it with `labels` matching how the policies select, and check who holds the role."
	var removedTypes []string
	for _, r := range rules {
		if a.meshFilter != "" && r.Mesh != "" && r.Mesh != a.meshFilter {
			continue
		}
		for _, t := range r.Types {
			if removed[t] && !slices.Contains(removedTypes, t) {
				removedTypes = append(removedTypes, t)
			}
		}
		for _, q := range r.When {
			if tr := q.TargetRef; tr != nil {
				switch {
				case tr.Kind != "" && !allowedTopLevelTargetRefKinds[tr.Kind]:
					add(blocker, kind+" when[].targetRef.kind="+tr.Kind,
						"3.0 matches a qualifier `targetRef` against a policy's top-level targetRef, which accepts only Mesh and Dataplane, and rejects any other kind on write (`value '<Kind>' is not supported`), so re-applying the role fails and the stored one matches no policy. "+
							"Either rewrite it as `kind: Dataplane` before upgrading, or remove the qualifier and recreate it with `labels` after upgrading (3.0 does not re-validate stored roles, it only rejects a re-apply). "+
							"A `kind: Dataplane` qualifier without `name` is not a catch-all: 3.0 requires the qualifier's name to equal the policy's `kuma.io/display-name` label, so it only covers policies without one (on 2.14: without `name`), and policies pinned by display-name are not covered. "+
							"On 2.14 the same rewrite widens the grant, from policies on this "+tr.Kind+" to every Dataplane-targeted policy without a name that the rule's types and mesh allow.")
				case tr.Name != "":
					add(info, kind+" qualifier matches a targetRef by name", byName)
				}
			}
			if q.From != nil {
				add(blocker, kind+" qualifier uses `from`",
					"3.0 rejects every `when[].from` qualifier on write, so re-applying the role fails. Remove the qualifier before upgrading, or scope the rule with a top-level `targetRef` qualifier instead.")
			}
			if q.To != nil && q.To.TargetRef != nil {
				switch tr := q.To.TargetRef; {
				case tr.Kind != "" && !allowedToTargetRefKinds[tr.Kind]:
					add(blocker, kind+" when[].to.targetRef.kind="+tr.Kind,
						"3.0 accepts only Mesh, MeshService, MeshExternalService, MeshMultiZoneService and MeshHTTPRoute in a `when[].to.targetRef` qualifier and rejects subset/selector kinds and MeshGateway on write, so re-applying the role fails. Retarget the qualifier at one of those kinds before upgrading.")
				case tr.Kind != "" && tr.Kind != "Mesh" && tr.Name == "":
					add(blocker, kind+" when[].to.targetRef.kind="+tr.Kind+" without name",
						"3.0 requires `labels` on a `when[].to.targetRef` of this kind and derives them only from `name`, so re-applying the role fails (`labels must be set when kind is "+tr.Kind+"`). 2.14 accepts it without `name` for MeshMultiZoneService, which has no 2.14 validator branch. "+
							"Set `name` to the target's display name before upgrading, or remove the qualifier and recreate it with `labels` after upgrading.")
				case tr.Name != "":
					add(info, kind+" qualifier matches a targetRef by name", byName)
				}
			}
			if jsonSet(q.Sources) || jsonSet(q.Destinations) || jsonSet(q.Selectors) {
				add(blocker, kind+" qualifier uses sources, destinations or selectors",
					"`when[].sources`, `destinations` and `selectors` scoped the classic tag-based policies, which 3.0 removes; 3.0 rejects them on write (`qualifier is no longer supported`), so re-applying the role fails. Remove them before upgrading and scope rules on targetRef policies with `targetRef`/`to` qualifiers.")
			}
		}
	}
	if len(removedTypes) > 0 {
		slices.Sort(removedTypes)
		a.rep.addDoc(blocker, categoryAccessRoles, kind+" rule types name a kind removed in 3.0",
			"3.0 no longer registers these resource types and rejects a rule whose `types` names one (`unknown types`), so re-applying the resource fails. Remove them from `rules[].types` before upgrading (and add the 3.0 replacements, such as MeshTrafficPermission or MeshOPA, if the rule should cover them).",
			docRBAC, refNote(ref, strings.Join(removedTypes, ", ")))
	}
}

// checkConfigAccess flags an AccessRole that reads `/config` on 2.14 but not on
// 3.0: 2.14 gates it on GENERATE_DATAPLANE_TOKEN, 3.0 on VIEW_CONTROL_PLANE_METADATA.
// Any rule grants access regardless of its types or mesh, so --mesh does not narrow it.
func (a *auditor) checkConfigAccess(rules []rbacRule, ref string) {
	has := func(access string) bool {
		return slices.ContainsFunc(rules, func(r rbacRule) bool { return slices.Contains(r.Access, access) })
	}
	if has("GENERATE_DATAPLANE_TOKEN") && !has("VIEW_CONTROL_PLANE_METADATA") {
		a.rep.addDoc(blocker, categoryAccessRoles, "AccessRole loses /config access in 3.0",
			"2.14 lets any role holding `GENERATE_DATAPLANE_TOKEN` read `GET /config`; 3.0 requires `VIEW_CONTROL_PLANE_METADATA` instead, so users bound to this role get 403 on `/config` after upgrading (the GUI and this tool's `--token` run read it). "+
				"The `admin` role of a control plane first started before 2.7.0 lacks it too. Add `VIEW_CONTROL_PLANE_METADATA` to the role's `access` if its users read `/config`.",
			docRBAC, ref)
	}
}

func (a *auditor) checkNewPolicies(ctx context.Context) error {
	for _, wsPath := range newPolicyPaths {
		for _, it := range a.listColl(ctx, a.scopedPath(wsPath)) {
			a.checkNewPolicy(it)
		}
	}
	for _, wsPath := range enterprisePolicyPaths {
		for _, it := range a.listIfServed(ctx, a.scopedPath(wsPath)) {
			a.checkNewPolicy(it)
		}
	}
	return nil
}

// checkNewPolicy runs the targetRef-policy checks on one policy.
func (a *auditor) checkNewPolicy(it resourceItem) {
	before := a.rep.total
	ref := a.ref(it)
	var spec policySpec
	if !a.unmarshalSpec(it, &spec, ref) {
		a.countSystem(it, before)
		return
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
		if pt := spec.TargetRef.ProxyTypes; len(pt) > 0 {
			gateway, sidecar := slices.Contains(pt, "Gateway"), slices.Contains(pt, "Sidecar")
			switch {
			case gateway && !sidecar:
				detail := "3.0 has no gateway concept (a gateway is a plain Dataplane whose listen ports skip inbound redirection) and drops `proxyTypes`, so this policy will apply to every proxy in the mesh, sidecars included. " +
					"Do not just remove the field. Delete the policy (which also clears its other findings), or retarget it to the gateway's Dataplane with `kind: Dataplane` and `labels`."
				if it.Type == "MeshTimeout" {
					detail += " The 2.x default `mesh-gateways-timeout-all-<mesh>` sets `streamIdleTimeout: 5s`, which left in place fails every sidecar HTTP response slower than 5s with 504. " +
						"Defaults are generated once per Mesh, so a deleted one stays deleted unless the Mesh is recreated; if yours is (e.g. GitOps replace), add `MeshTimeout` to its `skipCreatingInitialPolicies`."
				}
				a.rep.addDoc(blocker, "targetRef proxyTypes", it.Type+" scoped to gateways with targetRef.proxyTypes",
					detail, docUpgrade, ref)
			case sidecar && !gateway:
				a.rep.addDoc(blocker, "targetRef proxyTypes", it.Type+" scoped to sidecars with targetRef.proxyTypes",
					"3.0 drops `proxyTypes`, so this policy will also apply to gateways, which in 3.0 are plain Dataplanes with excluded inbound ports. "+
						"Remove the field if that is intended, otherwise retarget it with `kind: Dataplane` and `labels`.",
					docUpgrade, ref)
			default:
				a.rep.addDoc(blocker, "targetRef proxyTypes", it.Type+" uses targetRef.proxyTypes",
					"3.0 drops `proxyTypes`. It already covers every proxy here, so remove the field.",
					docUpgrade, ref)
			}
		}
	}
	// A resource is flagged once however many of its refs name a resource.
	byName := spec.TargetRef != nil && spec.TargetRef.selectsByName()
	for _, to := range spec.To {
		if k := to.TargetRef.Kind; k != "" && !allowedToTargetRefKinds[k] {
			a.rep.addDoc(blocker, "`to` targetRef kind", it.Type+" to[].targetRef.kind="+k,
				"`to` no longer accepts subset/selector or MeshGateway kinds; target Mesh, a Mesh*Service, or MeshHTTPRoute.", docPolicies, ref)
		}
		byName = byName || to.TargetRef.selectsByName()
	}
	if it.Type == "MeshHTTPRoute" || it.Type == "MeshTCPRoute" {
		byName = a.checkRouteBackendRefs(it.Type, it.specBytes(), ref) || byName
	}
	if byName {
		a.addSelectsByName(it.Type, ref)
	}
	a.checkPolicyFields(it, ref)
	a.checkReservedLabels(it, ref)
	if it.Labels[policyRoleLabel] == "producer" && !staysProducer(it, spec.To) {
		a.rep.addDoc(blocker, "Policy role", it.Type+" stops being a producer policy",
			"3.0 keeps a policy producer (applied to clients in every namespace and synced to the other zones) only when every `to[].targetRef` is a MeshService or MeshHTTPRoute selected by exactly three labels: `kuma.io/display-name`, `k8s.kuma.io/namespace` equal to the policy's own namespace and `kuma.io/zone` equal to its own zone. Anything else makes it a consumer policy that applies only inside its namespace, so clients elsewhere silently lose its rules; mixing both kinds of item is rejected on write. Rewrite each item as `labels: {kuma.io/display-name: <name>, k8s.kuma.io/namespace: <namespace>, kuma.io/zone: <zone>}`.",
			docPolicies, ref)
	}
	var sel selectorSpec
	if json.Unmarshal(it.specBytes(), &sel) == nil {
		a.addSelectorOnRemovedLabel(it.Type, ref, sel.labelSets()...)
	}
	a.countSystem(it, before)
}

func (a *auditor) addSelectsByName(typ string, ref string) {
	a.rep.addDoc(blocker, "Reference by name", typ+" references a resource by name",
		"3.0 drops `name`, `namespace` and `mesh` from `targetRef` and route `backendRefs` and selects by `labels` only. A stored ref that only names its resource loses the name: a top-level `kind: Dataplane` then selects every Dataplane in the mesh, and a `to[]` targetRef or backendRef resolves to nothing. Replace `name` with the `kuma.io/display-name` label, `namespace` with `k8s.kuma.io/namespace`, and drop `mesh`.",
		docPolicies, ref)
}

// routeBackendKinds are the only kinds 3.0 accepts in a route backendRef.
var routeBackendKinds = map[string]bool{"MeshService": true, "MeshExternalService": true, "MeshMultiZoneService": true}

// checkRouteBackendRefs flags MeshHTTPRoute/MeshTCPRoute backendRefs (and the
// RequestMirror filter's) whose kind 3.0 cannot resolve, once per kind, and
// reports whether any of them references its resource by name.
func (a *auditor) checkRouteBackendRefs(typ string, spec []byte, ref string) bool {
	var s struct {
		To []struct {
			Rules []struct {
				Default struct {
					BackendRefs []targetRef `json:"backendRefs"`
					Filters     []struct {
						RequestMirror *struct {
							BackendRef targetRef `json:"backendRef"`
						} `json:"requestMirror"`
					} `json:"filters"`
				} `json:"default"`
			} `json:"rules"`
		} `json:"to"`
	}
	if json.Unmarshal(spec, &s) != nil {
		return false
	}
	var refs []targetRef
	for _, t := range s.To {
		for _, r := range t.Rules {
			refs = append(refs, r.Default.BackendRefs...)
			for _, f := range r.Default.Filters {
				if f.RequestMirror != nil {
					refs = append(refs, f.RequestMirror.BackendRef)
				}
			}
		}
	}
	byName := false
	flagged := map[string]bool{}
	for _, br := range refs {
		switch {
		case br.Kind != "" && !routeBackendKinds[br.Kind]:
			if flagged[br.Kind] {
				continue
			}
			flagged[br.Kind] = true
			a.rep.addDoc(blocker, "Route backendRef", typ+" backendRef kind="+br.Kind,
				"3.0 routes accept only MeshService, MeshExternalService and MeshMultiZoneService backendRefs (the RequestMirror filter too). A stored ref of another kind is unresolved, so traffic matching the rule loses its destination (a MeshHTTPRoute rule with no resolvable backend answers 500). Selecting endpoints by tag has no equivalent: split the destination into separate MeshServices.",
				docMeshHTTPRoute, ref)
		case br.selectsByName():
			byName = true
		}
	}
	return byName
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
			Rules []struct {
				Default backendConf `json:"default"`
			} `json:"rules"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		confs := make([]backendConf, 0, len(s.To)+len(s.From)+len(s.Rules))
		for _, t := range s.To {
			confs = append(confs, t.Default)
		}
		for _, f := range s.From {
			confs = append(confs, f.Default)
		}
		for _, r := range s.Rules {
			confs = append(confs, r.Default)
		}
		if hasOtelEndpoint(confs...) {
			a.addOtelEndpoint(it.Type, ref)
		}
	case "MeshOPA":
		var s struct {
			Default struct {
				AgentConfig    map[string]json.RawMessage `json:"agentConfig"`
				AppendPolicies []struct {
					Rego map[string]json.RawMessage `json:"rego"`
				} `json:"appendPolicies"`
			} `json:"default"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		sources := []map[string]json.RawMessage{s.Default.AgentConfig}
		for _, p := range s.Default.AppendPolicies {
			sources = append(sources, p.Rego)
		}
		if slices.ContainsFunc(sources, untypedDataSource) {
			a.rep.addDoc(blocker, "MeshOPA data source", "MeshOPA uses the removed flat DataSource shape",
				"3.0 reads MeshOPA `agentConfig` and `appendPolicies[].rego` only as a typed `SecureDataSource` and has no converter for the flat `secret`/`inline`/`inlineString` shape, while 2.14 reads only the flat one. No stored shape works while a 3.0 global control plane syncs to 2.14 zones: the global drops the flat keys, the zone cannot load the data source, MeshOPA fails to apply and the proxies it selects stop getting configuration updates (new or restarted ones get none). Rewriting as part of the upgrade is too late, so do it before upgrading the global control plane: move every control plane (global and zones) to a 2.14 patch that accepts both shapes, rewrite each data source there, then upgrade the global. `inline` becomes `type: InsecureInline` with the base64-decoded value in `insecureInline.value`, `inlineString` becomes `type: InsecureInline` with the same text, and `secret: <name>` becomes `type: Secret` with `secretRef: {kind: Secret, name: <name>}`. Check the Kong Mesh 2.14 release notes for the patch that accepts the typed MeshOPA shape; until every control plane runs it, do not start the global upgrade while this MeshOPA is in use.",
				docMeshOPA, ref)
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
	case "MeshPassthrough":
		var s struct {
			Default struct {
				AppendMatch []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
					Port  int    `json:"port"`
				} `json:"appendMatch"`
			} `json:"default"`
		}
		if json.Unmarshal(spec, &s) != nil {
			return
		}
		for _, m := range s.Default.AppendMatch {
			if m.Type == "Domain" && m.Port == 0 && !strings.HasPrefix(m.Value, "*") {
				a.rep.addDoc(blocker, "MeshPassthrough", "MeshPassthrough Domain match has no port",
					"3.0 resolves a non-wildcard `Domain` match in the sidecar and connects to the resolved address, which needs a `port`. A stored match without one stops applying, and when it was the policy's only match the sidecar rejects all passthrough traffic. Add `port` to the match (duplicate it for each port the domain is used on) and make sure the sidecar can resolve the domain.",
					docMeshPassthrough, ref)
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
		var emptyMatches, noCatchAll, emptyBackendRefs bool
		for _, t := range s.To {
			if len(t.Rules) == 0 {
				continue
			}
			for _, r := range t.Rules {
				if len(r.Matches) == 0 {
					emptyMatches = true
				}
				if r.Default.BackendRefs != nil && len(*r.Default.BackendRefs) == 0 {
					emptyBackendRefs = true
				}
			}
			if !hasCatchAllRule(t.Rules) {
				noCatchAll = true
			}
		}
		if emptyBackendRefs {
			a.rep.addDoc(blocker, "MeshHTTPRoute routing", "MeshHTTPRoute rule has an empty backendRefs list",
				"2.x routes a rule with `backendRefs: []` to the destination itself, as if the field were absent. 3.0 reads an explicit empty list as \"every backend is unresolved\" and answers the matching requests with `500`. Remove the `backendRefs` key from the rule (keep `default: {}`) to keep sending the traffic to the destination.",
				docMeshHTTPRoute, ref)
		}
		switch {
		case emptyMatches:
			a.rep.addDoc(blocker, "MeshHTTPRoute routing", "MeshHTTPRoute rule has no matches",
				"A rule with an empty `matches` list generates no Envoy routes at all — the Universal API accepts it, but nothing is emitted for it. In 3.0 a request that matches no rule of an applicable MeshHTTPRoute gets a `404` instead of falling through to the destination, so every request to this destination fails after the upgrade. Give the rule at least one match (`path: {type: PathPrefix, value: /}` matches everything).",
				docMeshHTTPRoute, ref)
		case noCatchAll:
			a.rep.addDoc(blocker, "MeshHTTPRoute routing", "MeshHTTPRoute has no catch-all rule",
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

func (a *auditor) addOtelEndpoint(typ string, ref string) {
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
		// spec.probes is removed in 3.0. On Kubernetes the pod converter sets it
		// whenever the pod has virtual probes enabled, even when Application Probe
		// Proxy is also on and takes precedence, so the Dataplane alone cannot tell
		// whether the kubelet probes point at the virtual probes listener 3.0 no
		// longer builds.
		if hasJSON(spec.Probes) {
			if onK8s {
				a.rep.addDoc(blocker, "Dataplane probes", "Kubernetes pod has virtual probes enabled",
					"3.0 removes virtual probes along with the `kuma.io/virtual-probes*` annotations and the `virtualProbesEnabled` control plane setting. If this pod runs with Application Probe Proxy disabled (`kuma.io/application-probe-proxy-port: \"0\"`), its kubelet probes were rewritten to the virtual probes port, which a 3.0 control plane no longer serves, so they fail until the pod is re-injected; otherwise Application Probe Proxy already serves them and only the stale settings remain. Move it to Application Probe Proxy (the default) before upgrading: drop the `kuma.io/virtual-probes` annotation (and `virtualProbesEnabled` from the control plane config), keep `kuma.io/application-probe-proxy-port` unset or non-zero, and restart the pod.",
					docDataPlaneProxy, qualified(it))
			} else {
				a.rep.addDoc(blocker, "Dataplane probes", "Dataplane has a probes section",
					"Dataplane `spec.probes` is removed for Universal in 3.0 (app-probe-proxy supersedes it).", docDataPlaneProxy, qualified(it))
			}
		}
		// A per-proxy metrics backend (on k8s, translated from the deprecated
		// `prometheus.metrics.kuma.io/*` pod annotations) moves to MeshMetric.
		if hasJSON(spec.Metrics) {
			a.rep.addDoc(blocker, "Dataplane metrics", "Dataplane has a per-proxy metrics override",
				"`Dataplane.spec.metrics` (from `prometheus.metrics.kuma.io/*` annotations on k8s) is deprecated; move per-proxy metrics to the MeshMetric policy.", docMeshMetric, qualified(it))
		}
		a.checkDataplaneLabels(it, onK8s)
		var gw *gatewaySection
		if spec.Networking != nil {
			gw = spec.Networking.Gateway
		}
		a.checkGatewayMarking(it, gw, onK8s)
		// On Kubernetes the Dataplane is CP-written from the Pod, so only a
		// Universal one can carry a label an operator applied.
		if !onK8s {
			a.checkReservedLabels(it, qualified(it))
		}
		a.checkDataplaneNetworking(it, spec, onK8s)
	}
	return nil
}

// checkDataplaneLabels flags the Kubernetes ServiceAccount label, which 3.0
// treats as control-plane-owned.
func (a *auditor) checkDataplaneLabels(it resourceItem, onK8s bool) {
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

// gatewayReplacement is the 3.0 stand-in for a Kuma gateway: 3.0 drops the
// gateway concept (builtin and delegated), so a gateway is an ordinary proxy that
// keeps its listen ports out of inbound redirection.
const gatewayReplacement = "a Kong or third-party gateway running as a plain Dataplane whose listen ports are excluded from inbound redirection (`traffic.kuma.io/exclude-inbound-ports` on Kubernetes, `kuma-dp --exclude-inbound-ports` on Universal)"

// gatewayMarkingEffects lists what else 3.0 drops with the kuma.io/gateway marking.
const gatewayMarkingEffects = " 3.0 also stops reporting `gateway` as the MeshMetric `kuma.proxy_role` (a former gateway reports `sidecar`) and ignores the `?gateway=` filter on `/dataplanes/_overview`; update dashboards and scripts that rely on either."

// checkGatewayMarking flags gateways relying on the kuma.io/gateway marking (Pod
// annotation, Dataplane label, networking.gateway), all removed in 3.0 with the
// delegated gateway concept itself: a marked proxy becomes an ordinary workload
// whose inbound traffic goes through Envoy, so MeshTrafficPermission rejects
// clients outside the mesh. A stray Pod label on Kubernetes is not flagged: 3.0
// no longer copies reserved Pod labels.
func (a *auditor) checkGatewayMarking(it resourceItem, g *gatewaySection, onK8s bool) {
	switch _, labeled := it.Labels[gatewayLabel]; {
	case g != nil && strings.EqualFold(g.Type, "BUILTIN"):
		if !onK8s {
			a.rep.addDoc(blocker, "Gateway in Dataplane", "Dataplane is a builtin gateway",
				"`networking.gateway.type: BUILTIN` is removed in 3.0 together with the MeshGateway resources that configured it, and 3.0 has no gateway proxy type at all. Replace it before upgrading with "+gatewayReplacement+".",
				docUpgrade, qualified(it))
		}
	case onK8s && g != nil:
		a.rep.addDoc(blocker, "Gateway in Dataplane", "Kubernetes gateway relies on the kuma.io/gateway annotation",
			"3.0 ignores the `kuma.io/gateway` Pod annotation: the Pod is injected as an ordinary workload and its inbound traffic is redirected through Envoy, so MeshTrafficPermission rejects clients outside the mesh instead of letting them reach the gateway. 3.0 has no gateway concept; a gateway is a plain Dataplane whose listen ports skip inbound redirection. Replace the annotation with `traffic.kuma.io/exclude-inbound-ports` listing every port the gateway listens on (there is no all-ports value) and restart the Pods; annotate the fronting Service with `kuma.io/ignore: \"true\"` so it does not become a MeshService with no endpoints."+gatewayMarkingEffects,
			docUpgrade, qualified(it))
	case !onK8s && (g != nil || labeled):
		a.rep.addDoc(blocker, "Gateway in Dataplane", "Universal Dataplane uses the removed kuma.io/gateway marking",
			"3.0 removes `networking.gateway` and the `kuma.io/gateway` label, and with them the gateway concept: a gateway marked either way becomes an ordinary proxy. The control plane deletes the label the next time it writes the Dataplane (kuma-dp registration included), but re-applying a manifest that still carries it through the REST API or `kumactl apply` fails, because `kuma.io/gateway` is now an unknown reserved label. Drop both from the Dataplane and, if it runs with a transparent proxy, start `kuma-dp` with `--exclude-inbound-ports` (or `redirect.inbound.excludePorts`) covering every port the gateway listens on. Move any `targetRef` or MeshLoadBalancingStrategy affinity key that selects on the label or on `networking.gateway.tags` to a label you own."+gatewayMarkingEffects,
			docUpgrade, qualified(it))
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
	for _, in := range net.Inbound {
		if !supportedInboundProtocol(inboundProtocol(in.Protocol, in.Tags)) {
			a.rep.addDoc(blocker, "Dataplane networking", "Dataplane inbound uses a protocol 3.0 rejects",
				"3.0 accepts only `tcp`, `tls`, `http`, `http2`, `grpc` and `mysql` as `networking.inbound[].protocol` (Kafka support is removed) and rejects any other value on write. On Kubernetes the protocol comes from the Service port's `appProtocol` or its `<port>.service.kuma.io/protocol` annotation, so change it there; on Universal set a supported protocol (`tcp` for opaque traffic).",
				docDataPlaneProxy, qualified(it))
			break
		}
	}
	if !onK8s {
		if net.AdvertisedAddress != "" {
			a.rep.addDoc(blocker, "Dataplane networking", "Dataplane uses networking.advertisedAddress",
				"`networking.advertisedAddress` is removed in 3.0 (the proto field is reserved); drop it and advertise the address through the zone proxy configuration instead.",
				docDataPlaneProxy, qualified(it))
		}
		var tagged, protocolTagOnly bool
		for _, in := range net.Inbound {
			tagged = tagged || len(in.Tags) > 0
			// A tcp tag keeps the default and an unsupported one is flagged above.
			tag := in.Tags[protocolTag]
			protocolTagOnly = protocolTagOnly || (in.Protocol == "" && tag != "" && !strings.EqualFold(tag, "tcp") && supportedInboundProtocol(tag))
		}
		if tagged {
			a.rep.addDoc(blocker, "Dataplane networking", "Dataplane uses networking.inbound[].tags",
				"`networking.inbound[].tags` is removed in 3.0 (the proto field is reserved); move the tags to Dataplane labels and select proxies through MeshService, except `kuma.io/protocol`, which belongs in `networking.inbound[].protocol`. This pairs with `experimental.inboundTagsDisabled: true` on the control plane.",
				docMeshService, qualified(it))
		}
		// 2.x fell back to the kuma.io/protocol tag when the protocol field was
		// unset; 3.0 reads only the field.
		if protocolTagOnly {
			a.rep.addDoc(blocker, "Dataplane networking", "Dataplane inbound sets its protocol only through kuma.io/protocol",
				"3.0 reads an inbound's protocol only from `networking.inbound[].protocol` and no longer falls back to the `kuma.io/protocol` tag. An inbound without the field is served as plain TCP and silently loses its L7 behavior: HTTP access log fields, MeshTimeout HTTP timeouts, MeshFaultInjection, MeshRateLimit HTTP limits and HTTP routing. Set `protocol` on each such inbound before upgrading.",
				docDataPlaneProxy, qualified(it))
		}
		for _, out := range net.Outbound {
			if !hasJSON(out.BackendRef) {
				a.rep.addDoc(blocker, "Dataplane networking", "Dataplane outbound has no backendRef",
					"3.0 rejects `networking.outbound[]` entries without a `backendRef` on write and NACKs them over KDS; replace tag-based outbounds with a `backendRef` pointing at a MeshService, MeshExternalService or MeshMultiZoneService.",
					docMeshService, qualified(it))
				break
			}
		}
		// 3.0 still redirects a proxy that reports no transparent-proxy config
		// through the deprecated ports; 3.1 removes them.
		if tp := net.transparentProxying(); tp.RedirectPortInbound != 0 || tp.RedirectPortOutbound != 0 || (tp.IPFamilyMode != "" && tp.IPFamilyMode != "UnSpecified") {
			a.rep.addDoc(info, "Dataplane networking", "Dataplane configures transparent proxying through deprecated fields",
				"3.0 removes `networking.transparentProxying.ipFamilyMode` (the IP family now comes from what kuma-dp reports) and deprecates `redirectPortInbound`/`redirectPortOutbound`, which keep working on 3.0 and are removed in 3.1. Nothing breaks on the upgrade. To be ready for 3.1, drop the three fields and start kuma-dp with `--transparent-proxy`, or with `--transparent-proxy-config` pointing at a file carrying the non-default IP family mode and redirect ports; kuma-dp 2.14 already supports both flags.",
				docTransparentProxy, qualified(it))
		}
		for _, out := range net.Outbound {
			var br targetRef
			// MeshExternalService and MeshMultiZoneService names already resolve
			// across zones on 2.x, so only a MeshService changes.
			if json.Unmarshal(out.BackendRef, &br) == nil && br.Kind == "MeshService" && br.Name != "" && len(br.Labels) == 0 {
				a.rep.addDoc(blocker, "Dataplane networking", "Dataplane outbound backendRef selects by name",
					"2.x resolves an outbound `backendRef.name` to the resource of that name in the proxy's own zone. 3.0 turns the name into a `kuma.io/display-name` label and binds the outbound to the oldest matching resource in any zone, so a same-named MeshService in another zone can silently take the traffic cross-zone. Select by `labels` instead, including `kuma.io/zone` with the proxy's zone.",
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
	// 2.x accepts a ref by name/namespace or by labels, never both, so a ref
	// without labels is a name ref; 3.0 requires labels and drops name/namespace.
	if rb := tp.ReachableBackends; rb != nil {
		for _, ref := range rb.Refs {
			if len(ref.Labels) == 0 {
				a.rep.addDoc(blocker, "Dataplane networking", "Dataplane reachableBackends ref selects by name",
					"3.0 removes `name`/`namespace` from `reachableBackends.refs[]` (and the `kuma.io/reachable-backends` annotation) and requires `labels`. Existing refs resolve to nothing, so the proxy gets no outbounds even with `defaults.restrictOutbound: false`, and on Kubernetes the pod converter rejects the annotation. Rewrite each ref with labels: `name` becomes `kuma.io/display-name`, `namespace` becomes `k8s.kuma.io/namespace`. `kuma.io/display-name` alone selects more than before: a `MeshService` name ref resolved only in the proxy's own zone and namespace (when `namespace` was omitted), so also add `k8s.kuma.io/namespace` (the proxy's namespace if it was omitted) and, in multi-zone, `kuma.io/zone` (the proxy's zone) to keep the same scope.",
					docReachableBackends, qualified(it))
				break
			}
		}
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
// With neither, a Kubernetes sidecar still counts: the injector refuses to
// disable transparent proxying, and when its config comes from the injector
// ConfigMap the pod converter leaves transparentProxying nil, so an offline or
// older kuma-dp that reports no metadata would otherwise be missed. A zone proxy
// is not an injected sidecar; neither is a builtin gateway, which
// checkOutboundDefaults skips on its own.
func (o dpOverview) transparentProxy(labels map[string]string) bool {
	if tp := o.DataplaneInsight.Metadata.TransparentProxy; tp != nil {
		return tp.Redirect.Inbound.Enabled || tp.Redirect.Outbound.Enabled
	}
	net := o.Dataplane.Networking
	if net == nil || net.TransparentProxying == nil {
		return labels[envLabel] == "kubernetes" && labels[listenerZoneIngressLabel] == ""
	}
	tp := net.transparentProxying()
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
		if !ov.transparentProxy(it.Labels) {
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
			"Add `networking.transparentProxying.reachableBackends.refs` to each Dataplane, selecting by `labels` (not `name`/`namespace`, which 3.0 drops) the MeshServices the workload actually calls",
			mode, denied[0][mode], total[0], refs[0][mode])
		a.addOutboundDenyFinding("Kubernetes dataplanes", "Kubernetes",
			"Add the `kuma.io/reachable-backends` annotation to each Pod (the control plane copies it onto the Dataplane), selecting by `labels` (not `name`/`namespace`, which 3.0 drops) the MeshServices the workload actually calls",
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
		sev := info
		var impact string
		switch mode {
		case outboundUnset:
			sev = blocker
			impact = "In 2.x a proxy matched by no MeshPassthrough still gets a passthrough cluster, so anything the application dials that the mesh does not know about still leaves the proxy; 3.0 makes the no-policy case behave like `passthroughMode: None` and drops that traffic. " +
				fix + " " + restrictOutboundRemediation
		case outboundAllowed:
			impact = "`defaults.restrictOutbound` is explicitly `false` here, which 3.0 honors, so these proxies keep their passthrough cluster after the upgrade as long as the 3.0 control plane keeps that setting. " +
				"Selecting them with a MeshPassthrough is required before switching to `true`. " + fix
		case outboundRestricted:
			// The CP already drops this egress, so the upgrade changes nothing.
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
			// A Universal ZoneIngress registered by kuma-dp carries no kuma.io/env
			// (only one applied through the API gets `universal`), so anything not
			// labeled `kubernetes` is Universal.
			if wsPath == "zoneingresses" && it.Labels[envLabel] != "kubernetes" {
				a.noteZoneProxy(zoneOf(it))
			}
			a.rep.addDoc(blocker, "Zone proxies", wsPath+" present",
				"Separate ZoneIngress/ZoneEgress resources are replaced by the unified Zone Proxy (Listener types embedded in the Dataplane), which functions only in `meshServices.mode: Exclusive`; plan the migration before upgrading to 3.0.", docZoneProxies, qualified(it))
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
		a.addZoneNameFinding(displayName(it), qualified(it))
	}
	return nil
}

// addZoneNameFinding records the non-RFC-1035 zone-name blocker for one zone. ref
// names the zone as the report should show it (the resource name on a global, the
// configured name on a directly audited zone CP).
func (a *auditor) addZoneNameFinding(name string, ref string) {
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

// checkServiceResources flags MeshService, MeshExternalService and
// MeshMultiZoneService names that are not valid RFC-1035 DNS labels (deprecated
// in 3.0) and the spec fields 3.0 no longer reads. These resource types are newer
// than the legacy set; a 404 means the CP version does not serve them, which is
// not a coverage gap.
func (a *auditor) checkServiceResources(ctx context.Context) error {
	for _, rc := range []struct {
		wsPath, kind string
		checkSpec    func(resourceItem)
	}{
		{"meshservices", "MeshService", a.checkMeshServiceSpec},
		{"meshexternalservices", "MeshExternalService", a.checkExternalServiceTLS},
		{"meshmultizoneservices", "MeshMultiZoneService", a.checkMultiZoneServiceSpec},
	} {
		items := a.listIfServed(ctx, a.scopedPath(rc.wsPath))
		for _, it := range items {
			a.checkName(it, rc.kind)
			if it.Labels["kuma.io/managed-by"] == "" {
				a.checkReservedLabels(it, qualified(it))
			}
			rc.checkSpec(it)
			if rc.kind == "MeshExternalService" {
				if a.externalServiceMeshes == nil {
					a.externalServiceMeshes = map[string]bool{}
				}
				a.externalServiceMeshes[it.Mesh] = true
				if it.Labels["kuma.io/origin"] == "zone" {
					a.rep.addDoc(blocker, "MeshExternalService routing", "Zone-origin MeshExternalService is reached through its own zone",
						"2.x reaches a MeshExternalService created in a zone only through that zone's ingress and egress, so clients elsewhere depend on that zone's network path to the endpoint. 3.0 drops per-zone routing: every zone's local egress dials the endpoint directly. Make sure each zone's egress can reach it (or recreate the resource on the global) before upgrading.",
						docMeshExternalService, qualified(it))
				}
			}
		}
	}
	return nil
}

type servicePort struct {
	AppProtocol string `json:"appProtocol"`
}

// supportedAppProtocol mirrors 3.0's core_meta.SupportedProtocols; an empty value
// defaults to tcp.
func supportedAppProtocol(p string) bool {
	switch strings.ToLower(p) {
	case "", "tcp", "http", "http2", "grpc":
		return true
	}
	return false
}

func (a *auditor) addUnsupportedAppProtocol(kind string, ports []servicePort, ref string) {
	for _, p := range ports {
		if !supportedAppProtocol(p.AppProtocol) {
			a.rep.addDoc(blocker, "Service ports", kind+" port uses an appProtocol 3.0 rejects",
				"3.0 accepts only `tcp`, `http`, `http2` and `grpc` as `ports[].appProtocol` (Kafka support is removed) and rejects any other value on write, so re-applying this resource fails. Set a supported protocol (`tcp` for opaque traffic); for a MeshService generated from a Kubernetes Service, change the Service port's `appProtocol`.",
				docMeshService, ref)
			return
		}
	}
}

// checkMeshServiceSpec flags MeshService fields 3.0 removes. Generated
// MeshServices (kuma.io/managed-by) are regenerated by the 3.0 control plane, so
// only a Universal one still keyed on kuma.io/service needs attention: 3.0
// generates per kuma.io/workload instead, which changes its name.
func (a *auditor) checkMeshServiceSpec(it resourceItem) {
	ref := qualified(it)
	var s struct {
		Selector struct {
			DataplaneTags   map[string]string `json:"dataplaneTags"`
			DataplaneLabels *struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"dataplaneLabels"`
		} `json:"selector"`
		Identities []struct {
			Type string `json:"type"`
		} `json:"identities"`
		Ports []servicePort `json:"ports"`
	}
	if !a.unmarshalSpec(it, &s, ref) {
		return
	}
	managedBy := it.Labels["kuma.io/managed-by"]
	if len(s.Selector.DataplaneTags) > 0 {
		switch managedBy {
		case "":
			a.rep.addDoc(blocker, "MeshService selector", "MeshService selects proxies by dataplaneTags",
				"3.0 removes `spec.selector.dataplaneTags` and drops it on read, so this MeshService matches no proxies, produces no endpoints and goes `Unavailable`. Move the selector to `spec.selector.dataplaneLabels.matchLabels` using labels that exist on the Dataplanes themselves (Pod labels on Kubernetes, Dataplane `labels` on Universal).",
				docMeshService, ref)
		case "k8s-controller":
		default:
			a.rep.addDoc(blocker, "MeshService selector", "Generated MeshService is keyed on kuma.io/service",
				"3.0 generates Universal MeshServices per `kuma.io/workload` label instead of per `kuma.io/service` tag, so this one is replaced by a MeshService named after the proxies' workload unless the two names already match. Update every targetRef, backendRef and `reachableBackends` entry that selects it by `kuma.io/display-name`.",
				docMeshService, ref)
		}
	}
	// A hand-written MeshService needs the rewrite. A generated one is rewritten by
	// its zone CP, which on 2.14 keeps a ServiceTag entry while the mesh has mTLS
	// and, before kumahq/kuma#18920, even without it.
	for _, id := range s.Identities {
		if id.Type != "ServiceTag" {
			continue
		}
		if managedBy == "" {
			a.rep.addDoc(blocker, "MeshService identities", "MeshService declares a ServiceTag identity",
				"3.0 accepts only `SpiffeID` entries in `spec.identities` and rejects a `ServiceTag` one on write. Replace it with the SPIFFE ID of the workload before upgrading.",
				docMeshService, ref)
		} else if withMTLS, seen := a.meshMTLS[it.Mesh]; seen && !withMTLS {
			a.rep.addDoc(blocker, "MeshService identities", "Generated MeshService keeps a ServiceTag identity without Mesh mTLS",
				"The zone control plane that owns this MeshService still writes a `ServiceTag` identity although the mesh no longer has `mtls`, which no proxy presents any more. 3.0 accepts only `SpiffeID` identities: while zones are upgraded one by one, a 3.0 Kubernetes zone refuses this MeshService when it syncs it (a new one is skipped, so that zone cannot reach the service; an identity change fails the zone's MeshService sync). Upgrade the owning zone control plane to the 2.14 patch that drops the entry without Mesh mTLS (kumahq/kuma#18920) before upgrading the global control plane; it rewrites the identities within one status update interval.",
				docMeshService, ref)
		}
		break
	}
	a.addUnsupportedAppProtocol("MeshService", s.Ports, ref)
	if dl := s.Selector.DataplaneLabels; dl != nil {
		a.addSelectorOnRemovedLabel("MeshService", ref, dl.MatchLabels)
	}
}

func (a *auditor) checkMultiZoneServiceSpec(it resourceItem) {
	ref := qualified(it)
	var s struct {
		Selector struct {
			MeshService struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"meshService"`
		} `json:"selector"`
		Ports []servicePort `json:"ports"`
	}
	if a.unmarshalSpec(it, &s, ref) {
		a.addUnsupportedAppProtocol("MeshMultiZoneService", s.Ports, ref)
		a.addSelectorOnRemovedLabel("MeshMultiZoneService", ref, s.Selector.MeshService.MatchLabels)
	}
}

// checkExternalServiceTLS flags TLS material in the 2.x DataSource shape (a flat
// secret/inline/inlineString with no `type`), which 3.0 cannot read. 2.14.6+ also
// accepts the typed shape (kumahq/kuma#18867), so it can be rewritten before upgrading.
func (a *auditor) checkExternalServiceTLS(it resourceItem) {
	ref := qualified(it)
	var s struct {
		TLS *struct {
			Verification *struct {
				CaCert     map[string]json.RawMessage `json:"caCert"`
				ClientCert map[string]json.RawMessage `json:"clientCert"`
				ClientKey  map[string]json.RawMessage `json:"clientKey"`
			} `json:"verification"`
		} `json:"tls"`
	}
	if !a.unmarshalSpec(it, &s, ref) || s.TLS == nil || s.TLS.Verification == nil {
		return
	}
	v := s.TLS.Verification
	if slices.ContainsFunc([]map[string]json.RawMessage{v.CaCert, v.ClientCert, v.ClientKey}, untypedDataSource) {
		a.rep.addDoc(blocker, "MeshExternalService TLS", "MeshExternalService TLS uses the removed DataSource shape",
			"3.0 reads `tls.verification.caCert`, `clientCert` and `clientKey` only as a typed `SecureDataSource`. A stored MeshExternalService in the old shape is not rejected, but the control plane cannot read its TLS material and drops the destination from every proxy's config. Rewrite it before upgrading: `inline` becomes `type: InsecureInline` with the base64-decoded value in `insecureInline.value`, `inlineString` becomes `type: InsecureInline` with the same text, and `secret: <name>` becomes `type: Secret` with `secretRef: {kind: Secret, name: <name>}`.",
			docMeshExternalService, ref)
	}
}

// untypedDataSource reports a data source in the 2.x flat DataSource shape
// (`secret`/`inline`/`inlineString`, no `type` discriminator), which 3.0's typed
// SecureDataSource cannot read.
func untypedDataSource(ds map[string]json.RawMessage) bool {
	_, typed := ds["type"]
	return len(ds) > 0 && !typed
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
	// ApiServer carries the admin API authentication settings: 3.0 drops the
	// adminClientCerts authn plugin (the CP refuses to start with it) and the
	// auth.clientCertsDir field (silently ignored, so its client certs stop
	// being trusted). Both are served on every mode, global included.
	ApiServer struct {
		Authn struct {
			Type string `json:"type"`
		} `json:"authn"`
		Auth struct {
			ClientCertsDir string `json:"clientCertsDir"`
		} `json:"auth"`
	} `json:"apiServer"`
	// BootstrapServer.Params.ReadinessPort is a pointer so a control plane that
	// does not serve the field is not mistaken for one pinning it to 0, which
	// 3.0 rejects at startup.
	BootstrapServer struct {
		Params struct {
			ReadinessPort *uint32 `json:"readinessPort"`
		} `json:"params"`
	} `json:"bootstrapServer"`
	// MonitoringAssignmentServer.Enabled is nil when not served; 2.14 always
	// serves it and defaults it to true, so nil reads as true.
	MonitoringAssignmentServer struct {
		Enabled *bool `json:"enabled"`
	} `json:"monitoringAssignmentServer"`
	// Store.Cache.Enabled is nil when not served, so only an explicit false
	// (3.0 always caches) is flagged.
	Store struct {
		Cache struct {
			Enabled *bool `json:"enabled"`
		} `json:"cache"`
	} `json:"store"`
	// DNSServer holds the legacy kuma.io/service VIP allocator settings 3.0
	// removes together with the allocator.
	DNSServer struct {
		CIDR              string `json:"CIDR"`
		ServiceVipEnabled *bool  `json:"serviceVipEnabled"`
	} `json:"dnsServer"`
	// Metrics.Mesh carries the deprecated resync timeouts, which 2.14 prefers
	// over the resync intervals when set and 3.0 ignores. Durations are served
	// as Go duration strings ("0s" when unset).
	Metrics struct {
		Mesh struct {
			MinResyncTimeout string `json:"minResyncTimeout"`
			MaxResyncTimeout string `json:"maxResyncTimeout"`
		} `json:"mesh"`
	} `json:"metrics"`
	// DpServer.Authn.ZoneProxy authenticates the standalone ZoneIngress and
	// ZoneEgress proxies 3.0 removes; 3.0 authenticates every proxy with
	// dpProxy and moves the zone token issuer switch under multizone.global.
	DpServer struct {
		Authn struct {
			DpProxy struct {
				Type string `json:"type"`
			} `json:"dpProxy"`
			ZoneProxy struct {
				Type      string `json:"type"`
				ZoneToken struct {
					EnableIssuer *bool `json:"enableIssuer"`
				} `json:"zoneToken"`
			} `json:"zoneProxy"`
		} `json:"authn"`
	} `json:"dpServer"`
	Experimental struct {
		AutoReachableServices bool `json:"autoReachableServices"`
		// ExposeZoneProxyMetrics (2.14 only) serves unauthenticated
		// /stats/prometheus on zone proxies; 3.0 drops it.
		ExposeZoneProxyMetrics bool `json:"exposeZoneProxyMetrics"`
		DeltaXds               bool `json:"deltaXds"`
		SidecarContainers      bool `json:"sidecarContainers"`
		InboundTagsDisabled    bool `json:"inboundTagsDisabled"`
		// KubeOutboundsAsVIPs is nil when not served; 3.0 always stores
		// Kubernetes outbounds next to the VIPs.
		KubeOutboundsAsVIPs             *bool `json:"kubeOutboundsAsVIPs"`
		UseTagFirstVirtualOutboundModel bool  `json:"useTagFirstVirtualOutboundModel"`
		KdsEventBasedWatchdog           struct {
			Enabled            bool   `json:"enabled"`
			FlushInterval      string `json:"flushInterval"`
			FullResyncInterval string `json:"fullResyncInterval"`
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
				UnifiedResourceNamingEnabled bool   `json:"unifiedResourceNamingEnabled"`
				CNIEnabled                   bool   `json:"cniEnabled"`
				TransparentProxyConfigMap    string `json:"transparentProxyConfigMap"`
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
		a.rep.addGap("/config", "requires authentication — pass --token to audit this control plane's own settings (NOT audited)")
		// Zone configs come from ZoneInsight, which RBAC does not gate the same
		// way. Only a global serves it: a 404 means a zone or standalone CP (nothing
		// more to audit), while an unreadable one is its own gap.
		if _, served, zerr := a.zoneInsights(ctx); zerr == nil && !served {
			return nil
		}
		return a.checkZoneControlPlaneConfigs(ctx)
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
		// The API server does run on a global, so its startup-breaking settings
		// are audited here too.
		a.addAPIServerFindings(cfg, zoneRef(""))
		a.addDroppedSettingFindings(cfg, zoneRef(""))
		a.addZoneTokenIssuerFinding(cfg)
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
			cpConfigDetail("environment", "kubernetes", "universal"),
			docUniversal, "mode=global")
	}
}

// zoneRef qualifies a config example with the zone it came from; zone is ""
// for the control plane the tool connected to.
func zoneRef(zone string) func(string) string {
	return func(s string) string {
		if zone != "" {
			return "zone " + zone + ": " + s
		}
		return s
	}
}

// addAPIServerFindings flags admin API authentication settings 3.0 does not
// carry over. The adminClientCerts authn plugin is removed (kumahq/kuma#17906),
// so a CP configured with it fails to start. apiServer.auth.clientCertsDir is
// removed with it and, since the CP loads its config non-strictly, silently
// ignored: certificates trusted only through that directory stop authenticating
// to the HTTPS API server. Both apply to every mode, a global included.
func (a *auditor) addAPIServerFindings(cfg cpConfig, ref func(string) string) {
	if cfg.ApiServer.Authn.Type == "adminClientCerts" {
		a.rep.addDoc(blocker, cpConfigCategory, "API server adminClientCerts authn removed",
			cpConfigDetail("apiServer.authn.type", "adminClientCerts", "tokens"),
			docKumaCPReference, ref("apiServer.authn.type=adminClientCerts"))
	}
	if dir := cfg.ApiServer.Auth.ClientCertsDir; dir != "" {
		a.rep.addDoc(blocker, cpConfigCategory, "API server clientCertsDir ignored in 3.0",
			cpConfigDetail("apiServer.auth.clientCertsDir", dir, "unset"),
			docKumaCPReference, ref("apiServer.auth.clientCertsDir="+dir))
	}
}

// addDroppedSettingFindings flags settings 3.0 removes on every mode, a global
// included. The 3.0 CP loads its config non-strictly, so each is silently
// ignored and the behavior it selected reverts to the 3.0 default.
func (a *auditor) addDroppedSettingFindings(cfg cpConfig, ref func(string) string) {
	if e := cfg.Store.Cache.Enabled; e != nil && !*e {
		a.rep.addDoc(blocker, cpConfigCategory, "Store cache can no longer be disabled",
			cpConfigDetail("store.cache.enabled", "false", "true"),
			docKumaCPReference, ref("store.cache.enabled=false"))
	}
	if wd := cfg.Experimental.KdsEventBasedWatchdog; wd.Enabled {
		for _, s := range []struct {
			field, value string
			def          time.Duration
		}{
			{"flushInterval", wd.FlushInterval, 5 * time.Second},
			{"fullResyncInterval", wd.FullResyncInterval, time.Minute},
		} {
			if d, ok := setDuration(s.value); ok && d != s.def {
				field := "experimental.kdsEventBasedWatchdog." + s.field
				a.rep.addDoc(blocker, cpConfigCategory, "KDS watchdog timing moved to multizone.{global,zone}.kds.eventBasedWatchdog",
					cpConfigDetail(field, s.value, "unset"),
					docKumaCPReference, ref(field+"="+s.value))
			}
		}
	}
	for _, s := range []struct{ field, value string }{
		{"metrics.mesh.minResyncTimeout", cfg.Metrics.Mesh.MinResyncTimeout},
		{"metrics.mesh.maxResyncTimeout", cfg.Metrics.Mesh.MaxResyncTimeout},
	} {
		if _, ok := setDuration(s.value); ok {
			a.rep.addDoc(blocker, cpConfigCategory, s.field+" ignored in 3.0",
				cpConfigDetail(s.field, s.value, "unset"),
				docKumaCPReference, ref(s.field+"="+s.value))
		}
	}

	var legacyVIP []string
	if c := cfg.DNSServer.CIDR; c != "" && c != "240.0.0.0/4" {
		legacyVIP = append(legacyVIP, "dnsServer.CIDR="+c)
	}
	if e := cfg.DNSServer.ServiceVipEnabled; e != nil && !*e {
		legacyVIP = append(legacyVIP, "dnsServer.serviceVipEnabled=false")
	}
	if cfg.Experimental.UseTagFirstVirtualOutboundModel {
		legacyVIP = append(legacyVIP, "experimental.useTagFirstVirtualOutboundModel=true")
	}
	for _, s := range legacyVIP {
		a.rep.addDoc(info, cpConfigCategory, "Legacy DNS VIP settings have no effect in 3.0",
			"3.0 removes the `kuma.io/service` VIP allocator these settings configured, together with the `<service>.mesh` names it served. DNS names come only from MeshService, MeshExternalService and MeshMultiZoneService VIPs, allocated from the `ipam.*` CIDRs. The settings are ignored, so drop them from the control plane configuration.",
			docDNS, ref(s))
	}
}

// addZoneTokenIssuerFinding flags a global that turned the zone token issuer
// off. 3.0 validates zone tokens on the global only, so a zone's value is inert.
func (a *auditor) addZoneTokenIssuerFinding(cfg cpConfig) {
	if e := cfg.DpServer.Authn.ZoneProxy.ZoneToken.EnableIssuer; e != nil && !*e {
		a.rep.addDoc(blocker, cpConfigCategory, "Zone token issuer switch moved to multizone.global.kds.auth.zoneToken.enableIssuer",
			"3.0 ignores dpServer.authn.zoneProxy.zoneToken.enableIssuer, so the issuer turns back on. Set multizone.global.kds.auth.zoneToken.enableIssuer to false on the global to keep it off.",
			docKumaCPReference, "dpServer.authn.zoneProxy.zoneToken.enableIssuer=false")
	}
}

// setDuration parses a Go duration string served by /config, reporting false
// for an unset ("", "0s") or unparseable value.
func setDuration(s string) (time.Duration, bool) {
	d, err := time.ParseDuration(s)
	return d, err == nil && d != 0
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
	ref := zoneRef(zone)

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
	if onK8s && cfg.Runtime.Kubernetes.Injector.CNIEnabled {
		if a.cniEnabled == nil {
			a.cniEnabled = map[string]bool{}
		}
		a.cniEnabled[zone] = true
		// The 3.0 CNI plugin configures a pod only from the
		// traffic.kuma.io/transparent-proxy-config annotation, which the 2.x
		// injector writes only on the ConfigMap path.
		if cfg.Runtime.Kubernetes.Injector.TransparentProxyConfigMap == "" {
			a.rep.addDoc(blocker, cpConfigCategory, "CNI configures pods from legacy transparent proxy annotations",
				cpConfigDetail("runtime.kubernetes.injector.transparentProxyConfigMap", "unset", "kuma-transparent-proxy-config"),
				docTransparentProxy, ref("runtime.kubernetes.injector.transparentProxyConfigMap="))
		}
	}

	// Settings the 3.0 control plane refuses to start with, or silently drops.
	a.addAPIServerFindings(cfg, ref)
	a.addDroppedSettingFindings(cfg, ref)
	// zoneProxy.type authenticated only the standalone zone proxies; 3.0 zone
	// proxies are Dataplanes and authenticate like any other proxy. On Kubernetes
	// that is the pod service-account token, issued without operator action.
	if authn := cfg.DpServer.Authn; !onK8s && authn.ZoneProxy.Type == "none" && authn.DpProxy.Type != "none" {
		a.rep.addDoc(blocker, cpConfigCategory, "Zone proxies need a dataplane token in 3.0",
			cpConfigDetail("dpServer.authn.zoneProxy.type", "none", "unset"),
			docZoneProxies, ref("dpServer.authn.zoneProxy.type=none"))
	}
	if p := cfg.BootstrapServer.Params.ReadinessPort; p != nil && *p == 0 {
		a.rep.addDoc(blocker, cpConfigCategory, "Readiness port 0 fails 3.0 startup",
			cpConfigDetail("bootstrapServer.params.readinessPort", "0", "9902"),
			docKumaCPReference, ref("bootstrapServer.params.readinessPort=0"))
	}
	if cfg.Experimental.ExposeZoneProxyMetrics {
		a.rep.addDoc(blocker, cpConfigCategory, "Zone proxy metrics exposure removed",
			cpConfigDetail("experimental.exposeZoneProxyMetrics", "true", "false"),
			docMeshMetric, ref("experimental.exposeZoneProxyMetrics=true"))
	}
	if onK8s && (cfg.MonitoringAssignmentServer.Enabled == nil || *cfg.MonitoringAssignmentServer.Enabled) {
		a.rep.addDoc(blocker, cpConfigCategory, "MADS not served on Kubernetes in 3.0",
			cpConfigDetail("monitoringAssignmentServer.enabled", "true", "false"),
			docMeshMetric, ref("monitoringAssignmentServer.enabled=true"))
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
	if v := cfg.Experimental.KubeOutboundsAsVIPs; onK8s && v != nil && !*v {
		a.rep.addDoc(blocker, cpConfigCategory, "Kubernetes outbounds as VIPs not enabled",
			cpConfigDetail("experimental.kubeOutboundsAsVIPs", "false", "true"),
			docKumaCPReference, ref("experimental.kubeOutboundsAsVIPs=false"))
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
		a.flagIfBehind(a.rep.cp.Version, "", latestMin, latestPatch, detail)
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
// proven current), not a silent pass. zone labels the source in the example
// ("" for the control plane the tool connected to).
func (a *auditor) flagIfBehind(version, zone string, latestMin, latestPatch int, detail string) {
	maj, minor, patch, ok := ParseSemver(version)
	if !ok {
		origin := "control plane"
		if zone != "" {
			origin = "zone " + zone
		}
		a.rep.addGap("version ("+origin+")",
			"reported version "+version+" is not valid semver — version currency NOT audited")
		return
	}
	if behind(maj, minor, patch, latestMin, latestPatch) {
		origin := "control plane"
		if zone != "" {
			origin = "zone " + zone
		}
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
		a.flagIfBehind(v, it.Name, latestMin, latestPatch, detail)
	}
	return nil
}

// dpInsight captures just the per-subscription version data exposed by
// /dataplanes+insights — enough to read the control plane's own compatibility
// verdict for each connected proxy, plus the dependency versions kuma-dp reports
// (e.g. a bundled `coredns`, which signals the legacy embedded-DNS path).
type dpInsight struct {
	Dataplane        dataplaneSpec `json:"dataplane"`
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

// 2.14 never persists the `coredns` dependency, so this feature is the only CoreDNS signal there.
const featureEmbeddedDNS = "feature-embedded-dns"

// featureReadinessUnixSocket is advertised by kuma-dp older than 2.14, which
// serves readiness on a Unix socket. 3.0 always points the readiness cluster at
// the TCP readiness port, so such a proxy never reports ready.
const featureReadinessUnixSocket = "feature-readiness-unix-socket"

// checkDataplaneVersions flags data planes the control plane itself reports as
// version-incompatible (`kumaCpCompatible` false or absent): they are already outside the
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
		// The insight is proto3 JSON, which omits a false bool: a CP that judged the
		// proxy incompatible sends its version with no kumaCpCompatible key at all.
		if kd.Version != "" && (kd.KumaCpCompatible == nil || !*kd.KumaCpCompatible) {
			a.rep.addDoc(blocker, "Dataplane version", "Dataplane is version-incompatible with the control plane",
				"The control plane reports this proxy's kuma-dp version as incompatible; bring it into the supported skew window before upgrading to 3.0.",
				docUpgrade, qualifiedNote(it, "kuma-dp "+kd.Version))
		}
		// 3.0 upgrades only from 2.14, and older kuma-dp does not advertise the
		// features checkDataplaneFeatures reads, so this comes before every other
		// data plane finding.
		if maj, minor, _, ok := ParseSemver(kd.Version); ok && maj == 2 && minor < UpgradeTargetMinor {
			a.rep.addDoc(blocker, "Dataplane version", fmt.Sprintf("Dataplane runs kuma-dp older than 2.%d", UpgradeTargetMinor),
				fmt.Sprintf("Upgrade kuma-dp to the latest 2.%d patch first, before acting on any other data plane finding for this proxy. 3.0 supports upgrading only from 2.%d, and older kuma-dp does not advertise the features the other data plane checks read (`feature-otel-via-kuma-dp`, and before 2.13 `feature-reuse-port` and `feature-strict-inbound-ports`), so re-run the audit once it runs 2.%d.", UpgradeTargetMinor, UpgradeTargetMinor, UpgradeTargetMinor),
				docUpgrade, qualifiedNote(it, "kuma-dp "+kd.Version))
		}
		if ref, ok := legacyCoreDNSRef(it, ins, last.Dependencies["coredns"]); ok {
			a.rep.addDoc(blocker, "Dataplane DNS", "Dataplane uses the legacy embedded CoreDNS",
				"This proxy resolves mesh names through the bundled CoreDNS (a transparent proxy not advertising `feature-embedded-dns`, or one reporting a `coredns` dependency). 3.0 removes the CoreDNS + Envoy DNS-filter path, so this proxy loses mesh DNS as soon as its control plane runs 3.0. Before upgrading, switch it to the embedded DNS proxy: on Universal set `KUMA_DNS_PROXY_PORT=15053` (or `--dns-proxy-port` / `dns.proxyPort`) on kuma-dp and restart it; on Kubernetes set `runtime.kubernetes.injector.builtinDNS.experimentalProxy: true` on the control plane and restart the pods. A proxy running with DNS disabled (`KUMA_DNS_ENABLED=false`) does not advertise the feature either and can be ignored.",
				docDNS, ref)
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
		if slices.Contains(ins.DataplaneInsight.Metadata.Features, featureReadinessUnixSocket) {
			a.rep.addDoc(blocker, "Dataplane features", "Dataplane reports readiness over a Unix socket",
				"This proxy advertises `feature-readiness-unix-socket`, which kuma-dp stopped sending in 2.14. A 3.0 control plane always points the readiness cluster at the TCP readiness port, so this proxy never reports ready. Upgrade its kuma-dp to 2.14 before upgrading the control plane.",
				docUpgrade, qualifiedNote(it, "kuma-dp "+kd.Version))
		}
		if feats := ins.DataplaneInsight.Metadata.Features; len(feats) > 0 {
			a.checkDataplaneFeatures(it, ins, feats)
		}
	}
	return nil
}

// kuma-dp 2.14 advertises these only when the matching runtime setting is on;
// 3.0 assumes all of them and stops reading the features.
const (
	featureDeltaGRPC                = "feature-delta-grpc"
	featureReusePort                = "feature-reuse-port"
	featureStrictInboundPorts       = "feature-strict-inbound-ports"
	featureOtelViaKumaDp            = "feature-otel-via-kuma-dp"
	featureTransparentProxyInDPMeta = "feature-transparent-proxy-in-dataplane-metadata"
)

// checkDataplaneFeatures flags proxies whose advertised features show a runtime
// setting 3.0 no longer supports. An empty feature list is inconclusive and is
// not passed in.
func (a *auditor) checkDataplaneFeatures(it resourceItem, ins dpInsight, feats []string) {
	if !slices.Contains(feats, featureDeltaGRPC) {
		a.rep.addDoc(blocker, "Dataplane features", "Dataplane uses state-of-the-world xDS",
			"This proxy does not advertise `feature-delta-grpc`, so it talks SotW xDS. 3.0 serves only delta xDS: once its control plane runs 3.0 the proxy keeps its last config, stays Ready and stops receiving updates until kuma-dp restarts. `experimental.deltaXds` on the control plane only reaches pods through the Kubernetes injector; on Universal (and for ZoneIngress/ZoneEgress started outside the injector) set `KUMA_DATAPLANE_RUNTIME_ENVOY_XDS_TRANSPORT_PROTOCOL_VARIANT=DELTA_GRPC` on kuma-dp. Restart the proxy before upgrading.",
			docKumaCPReference, qualified(it))
	}
	if !slices.Contains(feats, featureReusePort) || !slices.Contains(feats, featureStrictInboundPorts) {
		a.rep.addDoc(blocker, "Dataplane features", "Dataplane opts out of SO_REUSEPORT or strict inbound ports",
			"This proxy runs with `KUMA_DATAPLANE_RUNTIME_REUSE_PORT_ENABLED=false` or `KUMA_DATAPLANE_RUNTIME_STRICT_INBOUND_PORTS_ENABLED=false`. 3.0 always generates listeners with SO_REUSEPORT and strict inbound ports: Envoy cannot change `enable_reuse_port` on a live listener, so it rejects the inbound listener updates until the proxy restarts, and inbound traffic to undeclared ports is refused. Remove the override and restart the proxy on 2.x, declaring any extra inbound port it serves.",
			docDataPlaneProxy, qualified(it))
	}
	if !slices.Contains(feats, featureOtelViaKumaDp) {
		a.rep.addDoc(blocker, "Dataplane features", "Dataplane exports OpenTelemetry directly",
			"This proxy runs with `KUMA_DATAPLANE_RUNTIME_OTEL_PIPE_ENABLED=false`. 3.0 always sends OpenTelemetry traces, logs and metrics through kuma-dp, so this proxy exports to a socket nothing listens on and its telemetry stops. Remove the override and restart the proxy.",
			docOtelCollector, qualified(it))
	}
	// Only a transparent-proxied Kubernetes sidecar: zone proxies and gateways
	// have no inbound redirection to configure.
	if it.Labels[envLabel] == "kubernetes" && a.cniFor(it) &&
		it.Labels[listenerZoneIngressLabel] == "" && it.Labels[listenerZoneEgressLabel] == "" &&
		ins.Dataplane.Networking.gateway() == "" && !slices.Contains(feats, featureTransparentProxyInDPMeta) {
		a.rep.addDoc(blocker, "Dataplane features", "Pod is configured through legacy transparent proxy annotations",
			"This pod was injected without the transparent proxy ConfigMap, so it carries only the per-setting `traffic.kuma.io/*` annotations. The 3.0 CNI plugin configures a pod only from `traffic.kuma.io/transparent-proxy-config` and fails sandbox setup without it, so once the CNI DaemonSet runs 3.0 this pod cannot start again after a node reboot or sandbox restart. Enable `transparentProxy.configMap.enabled` on the control plane and restart the pod before upgrading.",
			docTransparentProxy, qualified(it))
	}
}

// cniFor reports whether the control plane governing it runs the CNI, keyed the
// same way as outboundModeFor.
func (a *auditor) cniFor(it resourceItem) bool {
	if _, ok := a.outboundModes[""]; ok {
		return a.cniEnabled[""]
	}
	return a.cniEnabled[zoneOf(it)]
}

func legacyCoreDNSRef(it resourceItem, ins dpInsight, corednsVersion string) (string, bool) {
	if corednsVersion != "" {
		return qualified(it) + " (coredns " + corednsVersion + ")", true
	}
	feats := ins.DataplaneInsight.Metadata.Features
	net := ins.Dataplane.Networking
	// empty features: an older CP that reports no metadata, inconclusive
	if len(feats) > 0 && !slices.Contains(feats, featureEmbeddedDNS) && net != nil && net.TransparentProxying != nil {
		return qualified(it), true
	}
	return "", false
}

// dnsFilterMarker is the Envoy UDP DNS filter name; its presence in a proxy's
// listeners means that proxy still uses the built-in DNS path 3.0 removes.
var dnsFilterMarker = []byte("envoy.filters.udp.dns_filter")

// usesDNSFilter reports whether a config dump's listeners use the Envoy DNS
// filter. Only the ListenersConfigDump counts: the bootstrap's
// `node.extensions` lists every filter compiled into Envoy, this one included,
// so the whole dump always contains the name.
func usesDNSFilter(dump []byte) bool {
	var d struct {
		Configs []json.RawMessage `json:"configs"`
	}
	if json.Unmarshal(dump, &d) != nil {
		return false
	}
	for _, c := range d.Configs {
		var t struct {
			Type string `json:"@type"`
		}
		if json.Unmarshal(c, &t) == nil && strings.HasSuffix(t.Type, ".ListenersConfigDump") && bytes.Contains(c, dnsFilterMarker) {
			return true
		}
	}
	return false
}

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
		if usesDNSFilter(dump) {
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

// displayName returns the logical resource name, which is what 3.0 validates.
// A KDS-synced copy is stored as "<name>-<hash>[.<system-ns>]", so its
// kuma.io/display-name label is the only place the original name survives.
func displayName(it resourceItem) string {
	if dn := it.Labels["kuma.io/display-name"]; dn != "" {
		return dn
	}
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

// qualified is the example string of a flagged resource: its KRI (the
// identifier Kuma 3.0 addresses it by) when the type has a 3.0 short name,
// otherwise the legacy "mesh/name" display form — types removed in 3.0 are
// not addressable by KRI, and neither are names containing "_" (Kuma decodes
// a KRI by splitting on it). The zone comes from zoneOf: the kuma.io/zone
// label a global CP stamps on KDS-synced resources, falling back to the
// ZoneIngress/ZoneEgress spec field a zone CP serves without the label.
func qualified(it resourceItem) string {
	if kri := kriOf(it); kri != "" {
		return kri
	}
	name := it.Name
	if it.Mesh != "" {
		name = it.Mesh + "/" + it.Name
	}
	if z := zoneOf(it); z != "" {
		name += " [zone:" + z + "]"
	}
	return name
}

// qualifiedNote is qualified with an annotation (the kuma-dp or CoreDNS
// version, the field a Mesh setting lives in).
func qualifiedNote(it resourceItem, note string) string {
	return qualified(it) + " (" + note + ")"
}

// refNote annotates a resource example (the roles a binding grants, the
// types a rule names).
func refNote(ref, note string) string {
	return ref + " (" + note + ")"
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
	// SkipCreatingInitialPolicies is present-but-nil when the key is absent and
	// non-nil (empty or populated) when the Mesh carries it: 3.0 removes the
	// field, so any presence is flagged.
	SkipCreatingInitialPolicies []string `json:"skipCreatingInitialPolicies"`
}

type policySpec struct {
	TargetRef *targetRef  `json:"targetRef"`
	From      []ruleEntry `json:"from"`
	To        []ruleEntry `json:"to"`
}

type targetRef struct {
	Kind       string            `json:"kind"`
	ProxyTypes []string          `json:"proxyTypes"`
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Mesh       string            `json:"mesh"`
	Labels     map[string]string `json:"labels"`
}

// labelSelectedKinds are the targetRef/backendRef kinds 3.0 resolves by labels only.
var labelSelectedKinds = map[string]bool{
	"Dataplane": true, "MeshService": true, "MeshExternalService": true,
	"MeshMultiZoneService": true, "MeshHTTPRoute": true,
}

// selectsByName reports a ref to a real resource that names it instead of
// selecting it by labels. 3.0 drops name/namespace/mesh, which leaves it empty.
func (t targetRef) selectsByName() bool {
	return labelSelectedKinds[t.Kind] && len(t.Labels) == 0 && (t.Name != "" || t.Namespace != "" || t.Mesh != "")
}

type ruleEntry struct {
	TargetRef targetRef `json:"targetRef"`
}

// gatewaySection is the Dataplane's 2.x networking.gateway block, which 3.0
// removes with the rest of the kuma.io/gateway marking. Type defaults to the 2.x
// DELEGATED.
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
		Tags     map[string]string `json:"tags"`
		Protocol string            `json:"protocol"`
	} `json:"inbound"`
	Outbound []struct {
		BackendRef json.RawMessage `json:"backendRef"`
	} `json:"outbound"`
	TransparentProxying *transparentProxying `json:"transparentProxying"`
}

// transparentProxying is the Dataplane's transparentProxying block. The redirect
// ports are the pre-3.0 way to declare transparent proxying. A non-nil
// ReachableBackends, even an empty `{"refs":[]}`, is a deliberate selection, not
// an absence.
type transparentProxying struct {
	ReachableServices    []string           `json:"reachableServices"`
	DirectAccessServices []string           `json:"directAccessServices"`
	ReachableBackends    *reachableBackends `json:"reachableBackends"`
	RedirectPortInbound  uint32             `json:"redirectPortInbound"`
	RedirectPortOutbound uint32             `json:"redirectPortOutbound"`
	IPFamilyMode         string             `json:"ipFamilyMode"`
}

// reachableBackends keeps only each ref's labels: 2.x accepts a ref by
// name/namespace or by labels, never both, so a ref without labels is a name ref.
type reachableBackends struct {
	Refs []struct {
		Labels map[string]string `json:"labels"`
	} `json:"refs"`
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
	if n.transparentProxying().ReachableBackends != nil {
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
	// A pointer tells an explicit empty list, which 3.0 answers with 500, from an
	// absent one, which routes to the destination.
	Default struct {
		BackendRefs *[]json.RawMessage `json:"backendRefs"`
	} `json:"default"`
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
// checkDataplaneVersions plus the
// --inspect-dataplanes deep check, so none is repeated here.
var manualChecks = []ManualCheck{
	{
		Title: "Migrate clients of removed inspect and overview endpoints",
		Detail: "Kuma 3.0 removes several legacy REST endpoints, which then answer 404: the " +
			"dataplane `rules` inspect endpoint, the per-policy `{policy}/{name}/dataplanes` " +
			"inspect paths, the MeshService `_resources/dataplanes` path, the `dataplanes+insights` " +
			"and `zones+insights` overview aliases, the ZoneIngress/ZoneEgress overview and Envoy " +
			"admin endpoints, and `service-insights`, which the control plane stops computing. " +
			"The `_rules` endpoint stays but no longer returns `toRules`/`fromRules`, and the " +
			"`?gateway=` overview filter is ignored. The control-plane API cannot tell you which " +
			"clients still call these paths, whether that's kumactl, the GUI, dashboards, scripts, " +
			"or monitoring, so find and migrate those consumers yourself using the mapping below, " +
			"and upgrade kumactl and the GUI together with the control plane.",
		Command: `# Removed in 3.0 (404)                                   -> replacement
GET /meshes/{mesh}/dataplanes/{name}/rules                  -> /meshes/{mesh}/dataplanes/{name}/_policies
GET /meshes/{mesh}/{policyType}/{name}/dataplanes           -> /meshes/{mesh}/{policyType}/{name}/_resources/dataplanes
GET /meshes/{mesh}/meshservices/{name}/_resources/dataplanes -> /meshes/{mesh}/meshservices/{name}/_dataplanes
GET /meshes/{mesh}/dataplanes+insights[/{name}]             -> /meshes/{mesh}/dataplanes/_overview (/{name}/_overview)
GET /zones+insights[/{name}]                                -> /zones/_overview (/zones/{name}/_overview)
GET /meshes/{mesh}/service-insights[/{name}]                -> MeshService / MeshExternalService status
GET /zoneingresses+insights, /zoneegressoverviews           -> none (ZoneIngress/ZoneEgress are removed)
GET /zoneingresses/{name}/{xds,stats,clusters}              -> none
GET /zoneegresses/{name}/{xds,stats,clusters}               -> none

# Changed
GET /meshes/{mesh}/dataplanes/{name}/_rules                 -> no toRules/fromRules; read toResourceRules/inboundRules
GET /meshes/{mesh}/dataplanes/_overview?gateway=            -> filter ignored

# Deprecated, still served
GET /meshes/{mesh}/dataplanes/{name}/policies               -> /meshes/{mesh}/dataplanes/{name}/_policies

# KRI-based inspect API
GET /meshes/{mesh}/dataplanes/{name}/_layout
GET /meshes/{mesh}/dataplanes/{name}/_policies
GET /meshes/{mesh}/dataplanes/{name}/_inbounds/{inbound_kri}/_policies
GET /meshes/{mesh}/dataplanes/{name}/_outbounds/{outbound_kri}/_policies
GET /meshes/{mesh}/dataplanes/{name}/_outbounds/{outbound_kri}/_routes
GET /meshes/{mesh}/dataplanes/{name}/_outbounds/{outbound_kri}/_routes/{route_kri}/_policies`,
	},
	{
		Title: "Clear every resource and Mesh blocker before upgrading the global control plane",
		Detail: "The global control plane is upgraded first, and the moment it runs 3.0 it " +
			"changes what every 2.x zone receives over KDS, before any zone is upgraded. " +
			"It answers the zones with an empty list for every resource type 3.0 removed, so " +
			"each zone deletes its copies of the legacy policies, MeshGateway, " +
			"MeshGatewayRoute, ExternalService and the other zones' ZoneIngress. It reads " +
			"stored resources with the removed fields dropped and syncs them that way: the " +
			"Mesh arrives without `mtls`, `routing`, `networking`, `logging`, `tracing`, " +
			"`metrics` and `constraints`, and policies arrive without `from`, `proxyTypes` " +
			"and name refs, which a 2.x zone still accepts and applies with a wider scope. " +
			"So the Mesh settings, removed kinds, zone proxies and policy field findings in " +
			"this report are deadlines for the global upgrade, not for the zone upgrades. " +
			"If that is not possible, keep the zones disconnected from the global " +
			"(stop the global or block KDS) until each zone runs 3.0.",
		Command: `# On the 2.x global, before upgrading it: every command must print nothing.
kumactl get meshes -o json | jq -r '.items[] | select(.mtls or .routing or .networking or .logging or .tracing or .metrics or .constraints) | .name'
for m in $(kumactl get meshes -o json | jq -r '.items[].name'); do
  for t in traffic-permissions traffic-routes traffic-logs traffic-traces fault-injections healthchecks circuit-breakers retries timeouts rate-limits proxytemplates virtual-outbounds external-services meshgateways meshgatewayroutes; do
    kumactl get "$t" --mesh "$m" -o json | jq -r --arg t "$t" '.items[]? | "\($t) \(.mesh)/\(.name)"'
  done
done
kumactl get zoneingresses -o json | jq -r '.items[].name'

# After upgrading the global, on each 2.x zone: the zone must not delete what it synced.
kubectl -n kuma-system logs deploy/kuma-control-plane | grep "no longer available in the upstream"`,
	},
	{
		Title: "Reissue Universal dataplane tokens bound to tags",
		Detail: "A dataplane token issued with `--tag` is checked against the Dataplane's " +
			"inbound tags on 2.x, but against its labels on 3.0. A token bound to " +
			"`kuma.io/service` can never match on 3.0, because `kuma.io/service` is a " +
			"reserved label 3.0 does not allow on a Dataplane, so the proxy is rejected the " +
			"next time it connects to a 3.0 zone control plane (every zone upgrade forces a " +
			"reconnect). The same token already fails on 2.x once " +
			"`experimental.inboundTagsDisabled` removes the inbound tags. Tokens are not " +
			"stored by the control plane, so the tool cannot find them. Reissue every " +
			"tag-bound token as a name-bound (`--name`) or workload-bound (`--workload`) " +
			"token and restart kuma-dp with it before upgrading. A proxy selected by a " +
			"MeshIdentity whose SPIFFE ID uses the workload (the Universal default) needs a " +
			"`--workload` token matching its `kuma.io/workload` label.",
		Command: `# Decode the claims of each token kuma-dp runs with; "Tags" must be empty.
# The payload is unpadded base64url, so restore the padding before decoding.
p=$(cut -d. -f2 /path/to/dataplane-token | tr '_-' '/+')
while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done
printf '%s' "$p" | base64 -d | jq '{Name, Mesh, Tags, Workload}'

# Reissue, bound to the workload (or --name <dataplane>)
kumactl generate dataplane-token --mesh <mesh> --workload <kuma.io/workload value> --valid-for 8760h > /path/to/dataplane-token`,
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
	{
		Title: "Rename the `standalone` control plane mode to `zone`",
		Detail: "Kuma 3.0 removes the deprecated `standalone` mode: `kuma-cp` fails config " +
			"validation at startup and the Helm chart fails at template time. 2.x already runs " +
			"`standalone` as `zone` and serves `mode: zone` from `/config`, so the tool cannot " +
			"tell which one you configured. Set `zone` in `KUMA_MODE`, the `mode` key of the " +
			"kuma-cp config file or the Helm value `controlPlane.mode` before upgrading; the two " +
			"modes behave the same, so nothing else changes. Empty output means there is " +
			"nothing left to fix.",
		Command: `# Kubernetes: Helm values and the running control plane
helm get values -n <namespace> <release> -o json | jq -r '.. | .mode? // empty | select(. == "standalone")'
kubectl get deploy -A -o json | jq -r '.items[] | select(any(.spec.template.spec.containers[].env[]?; .name == "KUMA_MODE" and .value == "standalone")) | [.metadata.namespace, .metadata.name] | @tsv'

# Universal: kuma-cp units, environment files and config files
grep -rnE 'KUMA_MODE=.?standalone|^\s*mode:\s*standalone' /etc/systemd/system /etc/kuma* 2>/dev/null`,
	},
	{
		Title: "Review defaults that change in 3.0",
		Detail: "Some 3.0 defaults differ from 2.x, so a control plane or proxy relying on the " +
			"old default changes behavior although no setting changed. The API cannot tell a " +
			"default from an explicit value, so review each. " +
			"(1) `xdsServer.dataplaneConfigurationRefreshInterval` goes from `1s` to `10s`: " +
			"mesh, policy and service changes take up to 10s to reach proxies, and a CA rotation " +
			"must keep the old CA for at least one interval. Set it explicitly if you need faster " +
			"propagation. (2) Workload certificates last 5 days instead of 1 day and renew about " +
			"every 4 days. Set `certificateParameters.expiry` on the MeshIdentity (or " +
			"`dpCert.rotation.expiration` on the Mesh) if you need a shorter lifetime. (3) On " +
			"Kubernetes a sidecar without a CPU limit runs 2 Envoy worker threads instead of one " +
			"per node core. Set a sidecar CPU limit or the `kuma.io/sidecar-proxy-concurrency` " +
			"annotation on workloads that need more. (4) A new Mesh gets no default policies: 2.x " +
			"created `mesh-timeout-*`, `mesh-circuit-breaker-all-*` and `mesh-retry-all-*`. " +
			"Existing meshes keep theirs, and timeouts and circuit breakers keep the same values " +
			"without them, but a mesh with no MeshRetry does not retry. Apply your own MeshRetry " +
			"to meshes created after the upgrade (meshes still carrying " +
			"`skipCreatingInitialPolicies` are flagged by the audit).",
		Command: `# Add -H "Authorization: Bearer $TOKEN" when the API needs a token.
# (1) "1s" means the CP follows the 2.x default
curl -s http://<cp-address>:5681/config | jq -r '.xdsServer.dataplaneConfigurationRefreshInterval'

# (3) Kubernetes: 0 or empty means no limit, so every sidecar without the annotation drops to 2 workers
curl -s http://<cp-address>:5681/config | jq -r '.runtime.kubernetes.injector.sidecarContainer.resources.limits.cpu'`,
	},
	{
		Title: "Drop removed kuma-dp flags and settings",
		Detail: "Kuma 3.0 `kuma-dp` removes the `--config-dir` flag, so a proxy still started " +
			"with it fails with `unknown flag`. It also ignores the `dataplaneRuntime.configDir` " +
			"and `socketDir` config fields and their `KUMA_DATAPLANE_RUNTIME_CONFIG_DIR` / " +
			"`KUMA_DATAPLANE_RUNTIME_SOCKET_DIR` env vars without an error, falling back to a " +
			"generated temporary directory. Data plane flags and env vars are not visible " +
			"through the control-plane API, so the tool cannot detect this. Switch to " +
			"`--work-dir` (`KUMA_DATAPLANE_RUNTIME_WORK_DIR`), which kuma-dp 2.14 already " +
			"supports, before upgrading kuma-dp. Empty output means there is nothing left to fix.",
		Command: `# Kubernetes: sidecar env vars set through kuma.io/sidecar-env-vars or container patches
kubectl get pods -A -o yaml | grep -nE 'config-dir|KUMA_DATAPLANE_RUNTIME_(CONFIG|SOCKET)_DIR'

# Universal: kuma-dp units, launch scripts and config files
grep -rnE -- '--config-dir|KUMA_DATAPLANE_RUNTIME_(CONFIG|SOCKET)_DIR|^\s*(configDir|socketDir):' /etc/systemd/system /etc/kuma* 2>/dev/null`,
	},
	{
		Title: "Update scripts using removed kumactl commands and flags",
		Detail: "Kuma 3.0 `kumactl` removes commands and flags that scripts, CI jobs and " +
			"runbooks may still call, and fails on them: `install observability` (run your own " +
			"observability stack; the Grafana dashboards ship in the release tarball under " +
			"`dashboards/grafana/`), the `install control-plane` flags `--ingress-*` and " +
			"`--egress-*`, `generate zone-token --scope ingress|egress`, `generate " +
			"dataplane-token --proxy-type ingress|egress` (a zone proxy takes an ordinary " +
			"dataplane token), the `transparent-proxy --ebpf-*` flags and `uninstall ebpf`, " +
			"`inspect dataplanes --gateway`, `inspect services` (use `get meshservices`) and the " +
			"`inspect zoneingress`/`zoneegress` commands. The tool cannot see how kumactl is " +
			"called, so search your repositories, and upgrade kumactl together with the control " +
			"plane. Empty output means there is nothing left to fix.",
		Command: `grep -rnE 'kumactl +(install +observability|install +control-plane.*--(ingress|egress)-|generate +zone-token.*--scope[= ](ingress|egress)|generate +dataplane-token.*--proxy-type[= ](ingress|egress)|(un)?install +transparent-proxy.*--ebpf|uninstall +ebpf|inspect +dataplanes.*--gateway|inspect +(services|zone-?ingress(es)?|zone-?egress(es)?)\b)' <path-to-scripts-and-ci>`,
	},
	{
		Title: "Validate user-supplied MeshIdentity CAs",
		Detail: "Kuma 3.0 validates a CA supplied through a Bundled MeshIdentity's " +
			"`provider.bundled.ca` like the legacy `provided` mTLS backend did: the " +
			"certificate must be a CA (`CA:TRUE`) with the `keyCertSign` key usage and without " +
			"`keyAgreement`. 2.x accepts any certificate there, so a MeshIdentity whose CA fails " +
			"these checks works today, and after the upgrade it never becomes Ready and the " +
			"proxies it selects get no workload certificates, which breaks mTLS. The certificate " +
			"usually lives in a Secret, which the tool does not read, so check each one. The " +
			"first command lists every MeshIdentity with a user-supplied CA and where its " +
			"certificate comes from; check each certificate with the second.",
		Command: `# MeshIdentities with a user-supplied CA, and the source of each certificate
for m in $(kumactl get meshes -o json | jq -r '.items[].name'); do
  kumactl get meshidentities --mesh "$m" -o json | jq -r '.items[] | select(.spec.provider.bundled.ca.certificate) | [.mesh, .name, (.spec.provider.bundled.ca.certificate | tostring)] | @tsv'
done

# For each certificate: needs "CA:TRUE" and "Certificate Sign", must not show "Key Agreement"
openssl x509 -in ca.crt -noout -ext basicConstraints,keyUsage`,
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
	{
		Title: "Drop the top-level Helm `ingress` and `egress` values",
		Detail: "Kuma 3.0 removes the chart's standalone ZoneIngress/ZoneEgress Deployments " +
			"along with the top-level `ingress` and `egress` value blocks (`kuma.ingress` / " +
			"`kuma.egress` in the Kong Mesh chart). Helm does not reject unknown values, so " +
			"`helm upgrade` with `ingress.enabled=true` still succeeds, and then deletes the " +
			"legacy zone proxy Deployment, Service, HorizontalPodAutoscaler, " +
			"PodDisruptionBudget and RBAC objects the previous release owned, which drops all " +
			"cross-zone traffic still flowing through them. The control plane does not see " +
			"Helm values, so the tool cannot detect this. Migrate to mesh-scoped zone proxies " +
			"(`meshes[].ingress.enabled` / `meshes[].egress.enabled`) first, then remove both " +
			"blocks from your values files. `controlPlane.ingress.*` is unrelated and stays. " +
			"Empty output means there is nothing left to fix.",
		Command: `helm get values -n <namespace> <release> -o json | jq -r '(. // {}) | (., .kuma // {}) | to_entries[] | select(.key == "ingress" or .key == "egress") | select(.value.enabled == true) | "\(.key).enabled=true"'`,
	},
	{
		Title: "Replace the `kuma.io/builtin-dns` Pod annotations",
		Detail: "Kuma 3.0 no longer reads the `kuma.io/builtin-dns`, `kuma.io/builtin-dns-port` " +
			"and `kuma.io/builtin-dns-logging` Pod annotations, so a Pod that turned the DNS " +
			"proxy off or moved its port with them gets the control plane's DNS settings once " +
			"it is re-injected. The control-plane API does not expose Pod annotations, so the " +
			"tool cannot detect this. Put the per-Pod value in a ConfigMap in the Pod's " +
			"namespace (key `config.yaml`, `redirect.dns.enabled` / `redirect.dns.port`), point " +
			"the Pod at it with `traffic.kuma.io/transparent-proxy-configmap-name`, which 2.14 " +
			"already supports, and drop the old annotations. DNS query logging has no " +
			"replacement. Empty output means there is nothing left to fix.",
		Command: `kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.annotations // {} | keys | any(startswith("kuma.io/builtin-dns"))) | [.metadata.namespace, .metadata.name] | @tsv'`,
	},
}

// kongMeshManualChecks are appended only when the CP reports the Kong Mesh
// product: they concern enterprise-only data plane features.
var kongMeshManualChecks = []ManualCheck{
	{
		Title: "Move static kuma-dp OPA config into MeshOPA `agentConfig`",
		Detail: "Kong Mesh 3.0 removes the `kuma-dp` flag `--opa-config-path` and the env vars " +
			"`KMESH_OPA_CONFIG_PATH` and `KMESH_OPA_EXPERIMENTAL_USE_DYNAMIC_CONFIG` (dynamic " +
			"config is always used). `kuma-dp` fails to start while `--opa-config-path` is still " +
			"set. Data plane flags and env vars are not visible through the control-plane API, so " +
			"the tool cannot detect this for you. Before upgrading, move the file's contents into " +
			"`spec.default.agentConfig` of a `MeshOPA` policy, then drop the flag and both env vars " +
			"from every data plane deployment. `--opa-set` (`KMESH_OPA_CONFIG_OVERRIDES`) stays and " +
			"now applies on top of the config generated from `MeshOPA`.",
		Command: `# Kubernetes: find pods still passing the removed flag or env vars
kubectl get pods -A -o yaml | grep -nE 'opa-config-path|KMESH_OPA_CONFIG_PATH|KMESH_OPA_EXPERIMENTAL_USE_DYNAMIC_CONFIG'

# Universal: check each kuma-dp unit / launch script
grep -rnE 'opa-config-path|KMESH_OPA_CONFIG_PATH|KMESH_OPA_EXPERIMENTAL_USE_DYNAMIC_CONFIG' /etc/systemd/system /etc/kuma* 2>/dev/null`,
	},
}

// buildManualChecks returns the manual checklist for a run, appending the
// Kubernetes-only items when the audit positively observed Kubernetes and the
// Kong Mesh-only items when the CP reports that product.
func buildManualChecks(k8sObserved, kongMesh bool) []ManualCheck {
	checks := append([]ManualCheck{}, manualChecks...)
	if k8sObserved {
		checks = append(checks, kubernetesManualChecks...)
	}
	if kongMesh {
		checks = append(checks, kongMeshManualChecks...)
	}
	return checks
}

// inboundProtocol is the protocol 2.x serves an inbound with: the protocol
// field, falling back to the kuma.io/protocol tag when the field is unset.
func inboundProtocol(field string, tags map[string]string) string {
	if field != "" {
		return field
	}
	return tags[protocolTag]
}

// supportedInboundProtocol mirrors the 3.0 Dataplane validator, which accepts any
// protocol core_meta.ParseProtocol knows; an empty value defaults to tcp.
func supportedInboundProtocol(p string) bool {
	switch strings.ToLower(p) {
	case "", "tcp", "tls", "http", "http2", "grpc", "mysql":
		return true
	}
	return false
}

// knownReservedLabels mirrors the 3.0 label registry
// (pkg/core/resources/labels/registry.go). 3.0 rejects a user write carrying any
// other kuma.io/ or k8s.kuma.io/ label, and no longer sets one on Dataplanes or
// services, so a selector keyed on it matches nothing.
var knownReservedLabels = map[string]bool{
	"kuma.io/origin": true, "kuma.io/zone": true, "kuma.io/mesh": true,
	"kuma.io/policy-role": true, "kuma.io/display-name": true, "kuma.io/env": true,
	"k8s.kuma.io/namespace": true, "k8s.kuma.io/service-account": true,
	"kuma.io/listener-zoneingress": true, "kuma.io/listener-zoneegress": true,
	"kuma.io/workload": true, "kuma.io/managed-by": true,
	"kuma.io/deletion-grace-period-started-at": true, "k8s.kuma.io/service-name": true,
	"k8s.kuma.io/is-headless-service": true, "kuma.io/kds-sync": true, "kuma.io/effect": true,
}

// cpStampedLabels are reserved labels the 2.14 control plane writes itself; 3.0
// drops them on its next write, so their presence is not an operator's doing.
// kuma.io/gateway is left to checkGatewayMarking.
var cpStampedLabels = map[string]bool{"kuma.io/proxy-type": true, "kuma.io/proxy-ready": true, gatewayLabel: true}

func unknownReservedLabel(k string) bool {
	return (strings.HasPrefix(k, "kuma.io/") || strings.HasPrefix(k, "k8s.kuma.io/")) && !knownReservedLabels[k]
}

// unknownReservedKeys returns the sorted keys of labels that are reserved but
// unknown to 3.0, skipping the ones in skip.
func unknownReservedKeys(labels map[string]string, skip map[string]bool) []string {
	var keys []string
	for k := range labels {
		if unknownReservedLabel(k) && !skip[k] {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// checkReservedLabels flags a user-authored resource carrying reserved labels 3.0
// does not know: the resource keeps working, but re-applying it fails.
func (a *auditor) checkReservedLabels(it resourceItem, ref string) {
	if keys := unknownReservedKeys(it.Labels, cpStampedLabels); len(keys) > 0 {
		a.rep.addDoc(blocker, "Reserved labels", it.Type+" carries a reserved label 3.0 rejects",
			"3.0 rejects creating or updating a resource with a `kuma.io/` or `k8s.kuma.io/` label it does not know (for example `kuma.io/service`, `kuma.io/protocol`, `kuma.io/instance`, `k8s.kuma.io/service-port`), through the API and the Kubernetes webhook alike. The stored resource keeps working, but re-applying it (GitOps, `kumactl apply`) fails. Remove the label, or move it outside the reserved prefixes.",
			docPolicies, refNote(ref, strings.Join(keys, ", ")))
	}
}

// selectorSpec gathers every label selector a policy can carry: targetRefs,
// route backendRefs (RequestMirror included) and MeshLoadBalancingStrategy
// affinity tag keys.
type selectorSpec struct {
	TargetRef *struct {
		Labels map[string]string `json:"labels"`
	} `json:"targetRef"`
	To []struct {
		TargetRef struct {
			Labels map[string]string `json:"labels"`
		} `json:"targetRef"`
		Default struct {
			LocalityAwareness *struct {
				LocalZone *struct {
					AffinityTags []struct {
						Key string `json:"key"`
					} `json:"affinityTags"`
				} `json:"localZone"`
			} `json:"localityAwareness"`
		} `json:"default"`
		Rules []struct {
			Default struct {
				BackendRefs []struct {
					Labels map[string]string `json:"labels"`
				} `json:"backendRefs"`
				Filters []struct {
					RequestMirror *struct {
						BackendRef struct {
							Labels map[string]string `json:"labels"`
						} `json:"backendRef"`
					} `json:"requestMirror"`
				} `json:"filters"`
			} `json:"default"`
		} `json:"rules"`
	} `json:"to"`
}

func (s selectorSpec) labelSets() []map[string]string {
	var sets []map[string]string
	if s.TargetRef != nil {
		sets = append(sets, s.TargetRef.Labels)
	}
	for _, t := range s.To {
		sets = append(sets, t.TargetRef.Labels)
		if la := t.Default.LocalityAwareness; la != nil && la.LocalZone != nil {
			keys := map[string]string{}
			for _, at := range la.LocalZone.AffinityTags {
				keys[at.Key] = ""
			}
			sets = append(sets, keys)
		}
		for _, r := range t.Rules {
			for _, br := range r.Default.BackendRefs {
				sets = append(sets, br.Labels)
			}
			for _, f := range r.Default.Filters {
				if f.RequestMirror != nil {
					sets = append(sets, f.RequestMirror.BackendRef.Labels)
				}
			}
		}
	}
	return sets
}

// addSelectorOnRemovedLabel flags a resource whose selectors key on a reserved
// label 3.0 no longer sets, which then matches nothing.
func (a *auditor) addSelectorOnRemovedLabel(typ string, ref string, sets ...map[string]string) {
	merged := map[string]string{}
	for _, s := range sets {
		maps.Copy(merged, s)
	}
	if keys := unknownReservedKeys(merged, nil); len(keys) > 0 {
		a.rep.addDoc(blocker, "Reserved labels", typ+" selects on a label 3.0 no longer sets",
			"3.0 no longer puts `kuma.io/service`, `kuma.io/proxy-type`, `kuma.io/gateway` or any other reserved label outside its registry on Dataplanes and services, so a selector keyed on one (targetRef or backendRef `labels`, MeshService `dataplaneLabels`, MeshMultiZoneService `meshService` labels, MeshLoadBalancingStrategy `affinityTags`) matches nothing after the upgrade. Select on your own labels, `kuma.io/workload` or `kuma.io/display-name` instead.",
			docPolicies, refNote(ref, strings.Join(keys, ", ")))
	}
}

// staysProducer mirrors 3.0's ComputePolicyRole: a policy is producer only when
// every to[] item is a MeshService or MeshHTTPRoute pinned to one resource of the
// policy's own namespace and zone by exactly display-name, namespace and zone.
func staysProducer(it resourceItem, to []ruleEntry) bool {
	ns, zone := it.Labels["k8s.kuma.io/namespace"], it.Labels[zoneLabel]
	if len(to) == 0 || zone == "" {
		return false
	}
	for _, t := range to {
		tr := t.TargetRef
		if tr.Kind != "MeshService" && tr.Kind != "MeshHTTPRoute" {
			return false
		}
		if len(tr.Labels) != 3 || tr.Labels["kuma.io/display-name"] == "" ||
			tr.Labels["k8s.kuma.io/namespace"] != ns || tr.Labels[zoneLabel] != zone {
			return false
		}
	}
	return true
}

// checkExternalServiceIdentity flags meshes with MeshExternalServices but no
// MeshIdentity: 3.0 gives a client proxy without a workload identity no cluster
// for a MeshExternalService. An unreadable MeshIdentity list is a coverage gap,
// never read as "none".
func (a *auditor) checkExternalServiceIdentity(ctx context.Context) error {
	if len(a.externalServiceMeshes) == 0 {
		return nil
	}
	ids, complete := a.listServed(ctx, a.scopedPath("meshidentities"))
	if !complete {
		return nil
	}
	withIdentity := map[string]bool{}
	for _, id := range ids {
		withIdentity[id.Mesh] = true
	}
	for _, m := range slices.Sorted(maps.Keys(a.externalServiceMeshes)) {
		if !withIdentity[m] {
			// EXC:FILE011:a synthetic Mesh must obey the same zone stamping/suppression the listed ones get
			meshItem := []resourceItem{{Type: "Mesh", Name: m}}
			a.stampZone(meshItem)
			a.rep.addDoc(blocker, "MeshIdentity coverage", "Mesh has MeshExternalServices but no MeshIdentity",
				"3.0 gives a client proxy without a workload identity no cluster for a MeshExternalService, so its requests fail locally with a 503 (`cluster_not_found`). Create a MeshIdentity in this mesh that selects every proxy calling a MeshExternalService before upgrading.",
				docMeshIdentity, qualified(meshItem[0]))
		}
	}
	return nil
}
