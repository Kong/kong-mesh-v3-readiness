package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// upgradeTargetMinor is the 2.x minor line a CP must be on (at its latest patch)
// before upgrading to 3.0: 2.14 is the final 2.x release, so it is the only
// supported upgrade source. Bump this when a newer final 2.x line ships.
const upgradeTargetMinor = 14

// githubReleasesURL is the source for the latest 2.x patch. Kong Mesh tracks Kuma
// patch numbers, so the same source serves both products. It is a var so tests can
// point it at a mock instead of the live API.
var githubReleasesURL = "https://api.github.com/repos/kumahq/kuma/releases?per_page=100"

// maxReleasePages backstops the GitHub pagination loop. GitHub orders releases by
// creation date, not version, so a maintenance line's latest patch can sit beyond
// the first page once newer major lines churn; following the Link header avoids
// returning a stale patch (or missing the line entirely).
const maxReleasePages = 20

// fetchLatestPatch returns the highest published 2.<targetMinor>.x patch from the
// GitHub releases API (e.g. "2.14.7"), following pagination so the result is not
// truncated to the newest page. Drafts and pre-releases are ignored. Response
// bodies are never echoed into errors (consistent with the CP client) and are
// size-capped. A best-effort call: the caller treats any error as "unknown latest"
// (a coverage gap), never a hard failure.
func fetchLatestPatch(ctx context.Context, hc *http.Client, targetMinor int) (string, error) {
	best := -1
	next := githubReleasesURL
	for page := 0; page < maxReleasePages && next != ""; page++ {
		patch, link, err := fetchReleasePage(ctx, hc, next, targetMinor)
		if err != nil {
			return "", err
		}
		if patch > best {
			best = patch
		}
		next = link
	}
	if best < 0 {
		return "", fmt.Errorf("no 2.%d.x release found", targetMinor)
	}
	return fmt.Sprintf("2.%d.%d", targetMinor, best), nil
}

// fetchReleasePage fetches one releases page and returns the highest matching
// 2.<targetMinor>.x patch on it (-1 if none) and the rel="next" URL ("" if last).
func fetchReleasePage(ctx context.Context, hc *http.Client, url string, targetMinor int) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// GitHub rejects requests without a User-Agent.
	req.Header.Set("User-Agent", toolName)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("fetching GitHub releases: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("GitHub releases: status %d", resp.StatusCode)
	}
	var rels []struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&rels); err != nil {
		return 0, "", fmt.Errorf("decoding GitHub releases: %w", err)
	}
	best := -1
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		maj, min, patch, ok := parseSemver(r.TagName)
		if !ok || maj != 2 || min != targetMinor {
			continue
		}
		if patch > best {
			best = patch
		}
	}
	return best, nextReleaseLink(resp.Header.Get("Link")), nil
}

// nextReleaseLink extracts the rel="next" URL from a GitHub Link header, or "" if
// there is no next page.
func nextReleaseLink(link string) string {
	for _, part := range strings.Split(link, ",") {
		seg := strings.Split(part, ";")
		if len(seg) < 2 {
			continue
		}
		rel := false
		for _, p := range seg[1:] {
			if strings.TrimSpace(p) == `rel="next"` {
				rel = true
				break
			}
		}
		if !rel {
			continue
		}
		u := strings.TrimSpace(seg[0])
		u = strings.TrimPrefix(u, "<")
		u = strings.TrimSuffix(u, ">")
		// Only follow http(s) targets, never a surprise scheme from a bad header.
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return u
		}
	}
	return ""
}

// parseSemver extracts major.minor.patch from a version/tag string, tolerating a
// leading "v" and any pre-release/build suffix (e.g. "v2.14.1-rc1" -> 2,14,1). It
// returns ok=false when the first three dot-separated components are not numeric.
func parseSemver(s string) (maj, min, patch int, ok bool) {
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
	min, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, false
	}
	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, false
	}
	return maj, min, patch, true
}

// behind reports whether a running version is older than the latest target patch
// and therefore not a supported 3.0 upgrade source. Anything below 2.x (a 1.x or
// 0.x build) must reach 2.x first, so it is "behind"; 3.0+ is beyond the 2.x
// upgrade source and is not flagged.
func behind(maj, min, patch, latestMin, latestPatch int) bool {
	if maj < 2 {
		return true
	}
	if maj > 2 {
		return false
	}
	if min != latestMin {
		return min < latestMin
	}
	return patch < latestPatch
}
