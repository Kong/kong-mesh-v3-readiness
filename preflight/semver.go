package preflight

import (
	"strconv"
	"strings"
)

// UpgradeTargetMinor is the 2.x minor line a CP must be on (at its latest patch)
// before upgrading to 3.0: 2.14 is the final 2.x release, so it is the only
// supported upgrade source. Bump this when a newer final 2.x line ships.
const UpgradeTargetMinor = 14

// ParseSemver extracts major.minor.patch from a version/tag string, tolerating a
// leading "v" and any pre-release/build suffix (e.g. "v2.14.1-rc1" -> 2,14,1). It
// returns ok=false when the first three dot-separated components are not numeric.
func ParseSemver(s string) (int, int, int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, false
	}
	return maj, minor, patch, true
}

// behind reports whether a running version is older than the latest target patch
// and therefore not a supported 3.0 upgrade source. Anything below 2.x (a 1.x or
// 0.x build) must reach 2.x first, so it is "behind"; 3.0+ is beyond the 2.x
// upgrade source and is not flagged.
func behind(maj, minor, patch, latestMin, latestPatch int) bool {
	if maj < 2 {
		return true
	}
	if maj > 2 {
		return false
	}
	if minor != latestMin {
		return minor < latestMin
	}
	return patch < latestPatch
}
