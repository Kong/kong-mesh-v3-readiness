// Command kuma3-preflight audits a running Kuma zone (or global) control plane
// over its REST API and reports which resources and settings must change before
// upgrading to Kuma 3.0. See docs/deprecated-features.md for the source
// of truth behind every check.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("address", "http://localhost:5681", "Control plane REST API base URL")
	token := flag.String("token", "", "Bearer token for the CP API (needed to read /config on access-controlled Kong Mesh CPs; otherwise /config is a coverage gap)")
	mesh := flag.String("mesh", "", "Limit the audit to a single mesh (default: all meshes)")
	out := flag.String("output", "", "Write the report to this file (default: stdout)")
	format := flag.String("format", "markdown", "Output format: markdown, json, or html")
	fromJSON := flag.String("from-json", "", "Render a previously captured JSON report (path, or - for stdin) instead of auditing")
	timeout := flag.Duration("timeout", 60*time.Second, "Overall timeout for the audit")
	inspect := flag.Int("inspect-dataplanes", 0, "Fetch up to N dataplanes' Envoy config dumps to detect removed features (0 = skip; expensive)")
	classify := flag.Bool("classify", false, "Classify e2e tests by Kuma-3.0 deprecated-feature usage (uses --source-dir / --reports-dir) instead of auditing a CP")
	sourceDir := flag.String("source-dir", "", "With --classify: root of the e2e test sources to scan statically")
	reportsDir := flag.String("reports-dir", "", "With --classify: directory of per-spec preflight JSON snapshots to fold in")
	flag.Parse()

	fmtName, err := normalizeFormat(*format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// --classify is a separate mode: it inspects e2e test sources / captured
	// snapshots rather than auditing a live control plane.
	if *classify {
		return runClassify(*sourceDir, *reportsDir, fmtName, *out, now)
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

	c, err := newClient(*addr, *token, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	report, auditErr := audit(ctx, c, auditOptions{meshFilter: *mesh, inspectDataplanes: *inspect})

	// Always make the output reflect this run: on failure, stamp the destination
	// so a stale clean report is never mistaken for an up-to-date one.
	var content string
	if auditErr != nil {
		content, err = failureContent(fmtName, *addr, auditErr, now)
	} else {
		content, err = renderFormat(fmtName, report.toModel(now))
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
	switch {
	case auditErr != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", auditErr)
		return 2
	case report.count(blocker) > 0:
		return 1
	case report.incomplete():
		// Coverage gaps / unparseable resources mean the audit could not prove a
		// clean result — don't let $? read as success.
		return 3
	default:
		return 0
	}
}

// normalizeFormat canonicalizes the --format value, accepting common aliases.
func normalizeFormat(f string) (string, error) {
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

func renderFormat(format string, m reportModel) (string, error) {
	switch format {
	case "json":
		return renderJSON(m)
	case "html":
		return renderHTML(m)
	default:
		return renderMarkdown(m), nil
	}
}

// failureContent renders the "audit did not complete" payload in the requested
// format. Markdown keeps the original plain stamp; json/html carry a structured
// failed-status model so they round-trip and render a red banner.
func failureContent(format, addr string, auditErr error, generatedAt string) (string, error) {
	if format == "markdown" {
		return failureStamp(addr, auditErr), nil
	}
	return renderFormat(format, failureModel(addr, auditErr, generatedAt))
}

func exitForStatus(status string) int {
	switch status {
	case statusFailed:
		return 2
	case statusBlockers:
		return 1
	case statusInconclusive:
		return 3
	default:
		return 0
	}
}

// loadModel reads a JSON report from a file (or stdin when path is "-") and
// validates it is a kuma3-preflight payload.
func loadModel(path string) (reportModel, error) {
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, maxBodyBytes))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return reportModel{}, err
	}
	var m reportModel
	if err := json.Unmarshal(data, &m); err != nil {
		return reportModel{}, fmt.Errorf("parsing JSON report: %w", err)
	}
	// Validate the schema value, not merely its presence: a non-empty but foreign
	// `schema` (e.g. an unrelated JSON document, or a classification report fed where a
	// report is expected) must be rejected, not silently mis-decoded.
	if !strings.HasPrefix(m.Schema, toolName+"/") {
		return reportModel{}, fmt.Errorf("does not look like a %s JSON report (schema %q)", toolName, m.Schema)
	}
	return m, nil
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

func failureStamp(addr string, err error) string {
	return fmt.Sprintf("# Kuma 3.0 Upgrade Pre-flight Report — FAILED\n\n"+
		"The audit of %s did not complete:\n\n    %v\n\n"+
		"Do NOT treat this as upgrade-safe; re-run after fixing the cause.\n", addr, err)
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
