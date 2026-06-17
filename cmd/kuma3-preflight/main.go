// Command kuma3-preflight audits a running Kuma zone (or global) control plane
// over its REST API and reports which resources and settings must change before
// upgrading to Kuma 3.0. See docs/deprecated-features.md for the source
// of truth behind every check.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("address", "http://localhost:5681", "Control plane REST API base URL")
	token := flag.String("token", "", "Bearer token for the CP API (optional)")
	mesh := flag.String("mesh", "", "Limit the audit to a single mesh (default: all meshes)")
	out := flag.String("output", "", "Write the markdown report to this file (default: stdout)")
	timeout := flag.Duration("timeout", 60*time.Second, "Overall timeout for the audit")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	c, err := newClient(*addr, *token, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	report, auditErr := audit(ctx, c, *mesh)

	// Always make the output reflect this run: on failure, stamp the destination
	// so a stale clean report is never mistaken for an up-to-date one.
	content := failureStamp(*addr, auditErr)
	if auditErr == nil {
		content = report.render()
	}

	if *out == "" {
		fmt.Print(content)
	} else if err := writeReport(*out, content); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *out, err)
		return 2
	} else {
		fmt.Fprintf(os.Stderr, "report written to %s\n", *out)
	}

	// Exit codes (so CI can gate on $?):
	//   0 clean · 1 blockers found · 2 operational error · 3 audit inconclusive
	switch {
	case auditErr != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", auditErr)
		return 2
	case report.countBlockers() > 0:
		return 1
	case report.incomplete():
		// Coverage gaps / unparseable resources mean the audit could not prove a
		// clean result — don't let $? read as success.
		return 3
	default:
		return 0
	}
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
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
