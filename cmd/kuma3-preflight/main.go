// Command kuma3-preflight audits a running Kuma zone (or global) control plane
// over its REST API and reports which resources and settings must change before
// upgrading to Kuma 3.0. See docs/deprecated-features.md for the source
// of truth behind every check. The audit engine itself lives in the importable
// preflight package (github.com/Kong/kong-mesh-v3-readiness/preflight); this
// command wires its flags into preflight.Audit and renders the result.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kong/kong-mesh-v3-readiness/preflight"
)

// maxReportBytes caps a single response/file body read by the CLI itself (a
// --from-json file/stdin read, or a GitHub releases response in release.go) so a
// hostile/huge input cannot OOM the process. The preflight library enforces its
// own equivalent cap on control-plane responses.
const maxReportBytes = 64 << 20 // 64 MiB

func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("address", "http://localhost:5681", "Control plane REST API base URL")
	token := flag.String("token", "", "Bearer token for the CP API (needed to read /config on access-controlled Kong Mesh CPs; otherwise /config is a coverage gap)")
	mesh := flag.String("mesh", "", "Limit the audit to a single mesh (default: all meshes)")
	out := flag.String("output", "", "Write the report to this file (default: stdout)")
	format := flag.String("format", "", "Output format. CP audit: json or html (default html). With --classify: markdown, json, or html (default markdown).")
	fromJSON := flag.String("from-json", "", "Render a previously captured JSON report (path, or - for stdin) instead of auditing")
	timeout := flag.Duration("timeout", 60*time.Second, "Overall timeout for the audit")
	inspect := flag.Int("inspect-dataplanes", 0, "Fetch up to N dataplanes' Envoy config dumps to detect removed features (0 = skip; expensive)")
	latestVersion := flag.String("latest-version", "", fmt.Sprintf("Latest 2.%d patch to check control plane(s) against (e.g. 2.%d.7); skips the GitHub lookup when set", preflight.UpgradeTargetMinor, preflight.UpgradeTargetMinor))
	classify := flag.Bool("classify", false, "Classify e2e tests by Kuma-3.0 deprecated-feature usage (uses --source-dir / --reports-dir) instead of auditing a CP")
	sourceDir := flag.String("source-dir", "", "With --classify: root of the e2e test sources to scan statically")
	reportsDir := flag.String("reports-dir", "", "With --classify: directory of per-spec preflight JSON snapshots to fold in")
	flag.Parse()

	now := time.Now().UTC().Format(time.RFC3339)

	// --classify is a separate mode: it inspects e2e test sources / captured
	// snapshots rather than auditing a live control plane. It is the only mode that
	// renders Markdown (its default); a CP audit renders JSON or a self-contained HTML page.
	if *classify {
		fmtName, err := classifyFormat(*format)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		return runClassify(*sourceDir, *reportsDir, fmtName, *out, now)
	}

	fmtName, err := auditFormat(*format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// --from-json renders an existing JSON report in any format without touching
	// the control plane (capture once in CI, regenerate the HTML site offline).
	if *fromJSON != "" {
		model, err := loadModel(*fromJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading --from-json: %v\n", err)
			return 2
		}
		content, err := renderFormat(fmtName, model)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		if err := emit(*out, content); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *out, err)
			return 2
		}
		return exitForStatus(model.Status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Validate --address up front (before the GitHub lookup below), so a bad
	// address fails fast rather than waiting on a network round-trip first.
	if err := validAddress(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// Resolve the latest 2.x patch to check against: an explicit --latest-version
	// wins (and keeps the run offline/deterministic); otherwise look it up from
	// GitHub. A failed lookup is non-fatal — the check degrades to a coverage gap
	// (inconclusive) rather than aborting or faking a clean pass. The lookup gets
	// its OWN short, separate deadline so a slow/hung GitHub can never eat the audit
	// budget and turn a healthy CP audit into an operational error.
	latest := *latestVersion
	if latest == "" {
		fetchTimeout := min(*timeout, 15*time.Second)
		fctx, fcancel := context.WithTimeout(context.Background(), fetchTimeout)
		v, ferr := fetchLatestPatch(fctx, &http.Client{Timeout: fetchTimeout})
		fcancel()
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "warning: could not determine the latest 2.%d patch from GitHub (%v); version currency will be inconclusive — pass --latest-version to set it\n", preflight.UpgradeTargetMinor, ferr)
		} else {
			latest = v
		}
	}

	rep, auditErr := preflight.Audit(ctx, preflight.Options{
		Address: *addr, Token: *token, Mesh: *mesh,
		InspectDataplanes: *inspect, LatestPatch: latest,
		HTTPClient: &http.Client{Timeout: *timeout},
	})

	// Always make the output reflect this run: on failure, stamp the destination
	// so a stale clean report is never mistaken for an up-to-date one.
	var content string
	if auditErr != nil {
		content, err = renderFormat(fmtName, preflight.FailureReport(*addr, auditErr, now))
	} else {
		rep.GeneratedAt = now
		content, err = renderFormat(fmtName, rep)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if err := emit(*out, content); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *out, err)
		return 2
	}

	// Exit codes (so CI can gate on $?):
	//   0 clean · 1 blockers found · 2 operational error · 3 audit inconclusive
	if auditErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", auditErr)
		return 2
	}
	return exitForStatus(rep.Status)
}

// validAddress mirrors the preflight library's own --address validation so a bad
// address is rejected before the GitHub latest-patch lookup runs.
func validAddress(addr string) error {
	u, err := url.Parse(strings.TrimRight(addr, "/"))
	if err != nil {
		return fmt.Errorf("invalid --address %q: %w", addr, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid --address %q: need scheme and host, e.g. http://localhost:5681", addr)
	}
	return nil
}

// classifyFormat canonicalizes --format for --classify, which renders Markdown
// (its default), JSON, or HTML.
func classifyFormat(f string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "", "markdown", "md":
		return "markdown", nil
	case "json":
		return "json", nil
	case "html", "htm":
		return "html", nil
	default:
		return "", fmt.Errorf("invalid --format %q: want markdown, json, or html", f)
	}
}

// auditFormat canonicalizes --format for a live CP audit / --from-json render.
// Markdown is produced only by --classify; a CP audit emits JSON or a
// self-contained HTML page (the default).
func auditFormat(f string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "", "html", "htm":
		return "html", nil
	case "json":
		return "json", nil
	case "markdown", "md":
		return "", fmt.Errorf("--format markdown is only available with --classify; use --format json or html for a CP audit")
	default:
		return "", fmt.Errorf("invalid --format %q: want json or html", f)
	}
}

func renderFormat(format string, m preflight.Report) (string, error) {
	if format == "json" {
		return m.RenderJSON()
	}
	return m.RenderHTML()
}

func exitForStatus(status string) int {
	switch status {
	case preflight.StatusFailed:
		return 2
	case preflight.StatusBlockers:
		return 1
	case preflight.StatusInconclusive:
		return 3
	default:
		return 0
	}
}

// loadModel reads a JSON report from a file (or stdin when path is "-") and
// delegates parsing/validation/normalization to preflight.ParseReport.
func loadModel(path string) (preflight.Report, error) {
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, maxReportBytes))
	} else {
		var f *os.File
		if f, err = os.Open(path); err != nil {
			return preflight.Report{}, err
		}
		defer f.Close()
		data, err = io.ReadAll(io.LimitReader(f, maxReportBytes))
	}
	if err != nil {
		return preflight.Report{}, err
	}
	return preflight.ParseReport(data)
}

// emit writes content to stdout, or to a file when out is set.
func emit(out, content string) error {
	if out == "" {
		fmt.Print(content)
		return nil
	}
	if err := writeReport(out, content); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "report written to %s\n", out)
	return nil
}

// writeReport writes content atomically (temp file + rename) and refuses to
// follow a symlink at the destination, so it never clobbers an unrelated file
// nor leaves a half-written report behind.
func writeReport(path, content string) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write %s: destination is a symlink", path)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kuma3-preflight-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
