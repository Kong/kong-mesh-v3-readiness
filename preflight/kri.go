package preflight

import (
	"fmt"
	"strings"
)

// shortNames maps a Kuma resource type to its 3.0 KRI short name, the first
// segment of a Kuma Resource Identifier (KRI, Kuma MADR 070 —
// kri_<short>_<mesh>_<zone>_<namespace>_<name>_<section>). Ported from the
// Kuma 3.0 resource descriptors (OSS) and the Kong Mesh 3.0 ones (RBAC,
// MeshOPA); MeshGlobalRateLimit/OPAPolicy and every legacy kind the audit
// flags are absent because 3.0 no longer registers them. A type missing here
// is not addressable by KRI and gets no `kri` string — the structured
// example fields still identify it on the 2.x CP.
var shortNames = map[string]string{
	"Mesh":                      "m",
	"Dataplane":                 "dp",
	"Zone":                      "z",
	"MeshService":               "msvc",
	"MeshExternalService":       "extsvc",
	"MeshMultiZoneService":      "mzsvc",
	"MeshTrust":                 "mtrust",
	"MeshIdentity":              "mid",
	"MeshZoneAddress":           "mza",
	"MeshAccessLog":             "mal",
	"MeshCircuitBreaker":        "mcb",
	"MeshFaultInjection":        "mfi",
	"MeshHealthCheck":           "mhc",
	"MeshHTTPRoute":             "mhttpr",
	"MeshLoadBalancingStrategy": "mlbs",
	"MeshMetric":                "mm",
	"MeshPassthrough":           "mp",
	"MeshProxyPatch":            "mpp",
	"MeshRateLimit":             "mrl",
	"MeshRetry":                 "mr",
	"MeshTCPRoute":              "mtcpr",
	"MeshTimeout":               "mt",
	"MeshTLS":                   "mtls",
	"MeshTrace":                 "mtr",
	"MeshTrafficPermission":     "mtp",
	"MeshOPA":                   "mopa",
	"AccessRole":                "ar",
	"AccessAudit":               "aa",
	"AccessRoleBinding":         "arb",
}

// kriOf builds the canonical KRI of an audited resource: the identifier Kuma
// 3.0 addresses it by. Zone comes from kuma.io/zone and namespace from
// k8s.kuma.io/namespace (both empty on Universal / for global-origin
// resources); the name is the display name, the one that survives a KDS
// hash-suffix. Section is always empty (the audit flags whole resources).
// A Mesh is stored under NoMesh, so its mesh segment is empty — anything
// else makes the KRI unresolvable on a 3.0 CP. Returns "" when the type
// has no 3.0 short name, or any segment contains "_" (Kuma decodes a KRI
// by splitting on it, so such an identifier would resolve elsewhere).
func kriOf(it resourceItem) string {
	if it.zoneUnknown {
		return ""
	}
	typ := it.Type
	// EXC:FILE011:Kuma's KRI treats an overview as its base resource (DataplaneOverview -> Dataplane)
	typ, _ = strings.CutSuffix(typ, "Overview")
	short, ok := shortNames[typ]
	if !ok {
		return ""
	}
	name := displayName(it)
	if name == "" {
		return ""
	}
	// EXC:FILE011:Kuma splits a KRI on "_", so a segment containing one would resolve to a different resource
	for _, seg := range []string{it.Mesh, it.Labels[zoneLabel], it.Labels[kubeNamespaceLabel], name} {
		if strings.Contains(seg, "_") {
			return ""
		}
	}
	return fmt.Sprintf("kri_%s_%s_%s_%s_%s_", short, it.Mesh,
		it.Labels[zoneLabel], it.Labels[kubeNamespaceLabel], name)
}
