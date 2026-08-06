package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Kong/kong-mesh-v3-readiness/preflight"
)

// githubReleasesURL is the source for the latest 2.x patch. Kong Mesh tracks Kuma
// patch numbers, so the same source serves both products. It is a var so tests can
// point it at a mock instead of the live API.
var githubReleasesURL = "https://api.github.com/repos/kumahq/kuma/releases?per_page=100"

// maxReleasePages backstops the GitHub pagination loop. GitHub orders releases by
// creation date, not version, so a maintenance line's latest patch can sit beyond
// the first page once newer major lines churn; following the Link header avoids
// returning a stale patch (or missing the line entirely).
const maxReleasePages = 20

// fetchLatestPatch returns the highest published patch on the preflight.UpgradeTargetMinor
// line from the GitHub releases API (e.g. "2.14.7"), following pagination so the
// result is not truncated to the newest page. Drafts and pre-releases are ignored.
// Response bodies are never echoed into errors (consistent with the CP client) and
// are size-capped. A best-effort call: the caller treats any error as "unknown
// latest" (a coverage gap), never a hard failure. This is a CLI-only concern (checking
// the latest upstream release) — it must not become a network call inside the
// preflight library, so it stays in cmd/kuma3-preflight.
func fetchLatestPatch(ctx context.Context, hc *http.Client) (string, error) {
	best := -1
	next := githubReleasesURL
	for page := 0; page < maxReleasePages && next != ""; page++ {
		patch, link, err := fetchReleasePage(ctx, hc, next)
		if err != nil {
			return "", err
		}
		if patch > best {
			best = patch
		}
		next = link
	}
	// Hitting the cap with pages still unread means we may not have seen the true
	// latest patch — return an error (the caller degrades to a coverage gap) rather
	// than a possibly-stale best that would read as authoritative.
	if next != "" {
		return "", fmt.Errorf("release list exceeded %d pages; latest 2.%d.x not determined", maxReleasePages, preflight.UpgradeTargetMinor)
	}
	if best < 0 {
		return "", fmt.Errorf("no 2.%d.x release found", preflight.UpgradeTargetMinor)
	}
	return fmt.Sprintf("2.%d.%d", preflight.UpgradeTargetMinor, best), nil
}

// fetchReleasePage fetches one releases page and returns the highest matching
// patch on the preflight.UpgradeTargetMinor line (-1 if none) and the rel="next" URL
// ("" if last).
func fetchReleasePage(ctx context.Context, hc *http.Client, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// GitHub rejects requests without a User-Agent.
	req.Header.Set("User-Agent", preflight.ToolName)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("fetching GitHub releases: %w", err)
	}
	if resp == nil { // unreachable per net/http (resp non-nil when err == nil); guards the deref for static analysis
		return 0, "", fmt.Errorf("fetching GitHub releases: nil response")
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReportBytes)).Decode(&rels); err != nil {
		return 0, "", fmt.Errorf("decoding GitHub releases: %w", err)
	}
	best := -1
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		maj, minor, patch, ok := preflight.ParseSemver(r.TagName)
		if !ok || maj != 2 || minor != preflight.UpgradeTargetMinor {
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
