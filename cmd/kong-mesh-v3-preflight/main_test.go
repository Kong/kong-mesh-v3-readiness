package main

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kong/kong-mesh-v3-readiness/preflight"
)

const cleanConfigJSON = `{
  "mode": "zone",
  "environment": "kubernetes",
  "defaults": {"restrictOutbound": true},
  "monitoringAssignmentServer": {"enabled": false},
  "experimental": {
    "autoReachableServices": false,
    "deltaXds": true,
    "sidecarContainers": true,
    "inboundTagsDisabled": true,
    "kdsEventBasedWatchdog": {"enabled": true}
  },
  "runtime": {"kubernetes": {
    "injector": {
      "unifiedResourceNamingEnabled": true,
      "ebpf": {"enabled": false}
    }
  }}
}`

func TestClassifyFormat(t *testing.T) {
	// --classify keeps Markdown as its default and supported format.
	cases := map[string]string{"": "markdown", "md": "markdown", "MARKDOWN": "markdown", "json": "json", "HTML": "html", "htm": "html"}
	for in, want := range cases {
		got, err := classifyFormat(in)
		if err != nil || got != want {
			t.Errorf("classifyFormat(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	if _, err := classifyFormat("pdf"); err == nil {
		t.Error("classifyFormat(pdf) should error")
	}
}

func TestAuditFormat(t *testing.T) {
	// A CP audit defaults to HTML and does not produce Markdown.
	cases := map[string]string{"": "html", "HTML": "html", "htm": "html", "json": "json"}
	for in, want := range cases {
		got, err := auditFormat(in)
		if err != nil || got != want {
			t.Errorf("auditFormat(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"markdown", "md", "pdf"} {
		if _, err := auditFormat(bad); err == nil {
			t.Errorf("auditFormat(%q) should error (markdown is classify-only)", bad)
		}
	}
}

func TestExitForStatus(t *testing.T) {
	cases := map[string]int{
		preflight.StatusClean:        0,
		preflight.StatusBlockers:     0,
		preflight.StatusInconclusive: 0,
		preflight.StatusFailed:       2,
		"unknown":                    0,
	}
	for status, want := range cases {
		if got := exitForStatus(status); got != want {
			t.Errorf("exitForStatus(%q) = %d, want %d", status, got, want)
		}
	}
}

func TestRunCollectionReadFailureExitsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0"}`))
		case "/meshes":
			writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","mesh":"default","meshServices":{"mode":"Disabled"}}],"next":null}`))
		case "/traffic-permissions":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":403}`))
		default:
			writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
		}
	}))
	t.Cleanup(srv.Close)

	oldArgs := os.Args
	oldFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	})

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	out := filepath.Join(t.TempDir(), "report.json")
	os.Args = []string{
		"kong-mesh-v3-preflight",
		"--address", srv.URL,
		"--format", "json",
		"--output", out,
		"--latest-version", "2.14.0",
	}

	if got := run(); got != 0 {
		t.Fatalf("run() exit = %d, want 0", got)
	}
}

func TestRunMaxResourceReadsValidation(t *testing.T) {
	oldArgs := os.Args
	oldFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	})

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	os.Args = []string{"kong-mesh-v3-preflight", "--max-resource-reads", "-1"}

	if got := run(); got != 2 {
		t.Fatalf("run() exit = %d, want 2", got)
	}
}

func TestRunMaxResourceReadsWiring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0"}`))
		case "/meshes":
			writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}}],"next":null}`))
		default:
			writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
		}
	}))
	t.Cleanup(srv.Close)

	oldArgs := os.Args
	oldFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	})

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	out := filepath.Join(t.TempDir(), "report.json")
	os.Args = []string{
		"kong-mesh-v3-preflight",
		"--address", srv.URL,
		"--format", "json",
		"--output", out,
		"--latest-version", "2.14.0",
		"--max-resource-reads", "1",
	}

	if got := run(); got != 0 {
		t.Fatalf("run() exit = %d, want 0", got)
	}
}

func TestRunDefaultResourceReadLimitKeepsSmallAuditClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0"}`))
		case "/config":
			writeJSON(w, []byte(cleanConfigJSON))
		case "/meshes":
			writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Exclusive"}}],"next":null}`))
		default:
			writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
		}
	}))
	t.Cleanup(srv.Close)

	oldArgs := os.Args
	oldFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	})

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	out := filepath.Join(t.TempDir(), "report.json")
	os.Args = []string{
		"kong-mesh-v3-preflight",
		"--address", srv.URL,
		"--format", "json",
		"--output", out,
		"--latest-version", "2.14.0",
	}

	if got := run(); got != 0 {
		t.Fatalf("run() exit = %d, want 0", got)
	}
}

func TestRunBlockersReportExitsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			writeJSON(w, []byte(`{"product":"Kuma","version":"2.14.0"}`))
		case "/config":
			writeJSON(w, []byte(cleanConfigJSON))
		case "/meshes":
			writeJSON(w, []byte(`{"total":1,"items":[{"type":"Mesh","name":"default","meshServices":{"mode":"Disabled"}}],"next":null}`))
		default:
			writeJSON(w, []byte(`{"total":0,"items":[],"next":null}`))
		}
	}))
	t.Cleanup(srv.Close)

	oldArgs := os.Args
	oldFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	})

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	out := filepath.Join(t.TempDir(), "report.json")
	os.Args = []string{
		"kong-mesh-v3-preflight",
		"--address", srv.URL,
		"--format", "json",
		"--output", out,
		"--latest-version", "2.14.0",
	}

	if got := run(); got != 0 {
		t.Fatalf("run() exit = %d, want 0", got)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	if !strings.Contains(string(data), `"status": "blockers"`) {
		t.Errorf("report status is not blockers: %.200s", data)
	}
}

func TestRunFromJSONFailedReportExitsTwo(t *testing.T) {
	failed := `{
	  "tool_schema": "kong-mesh-v3-preflight/v6",
	  "tool": "kong-mesh-v3-preflight",
	  "status": "failed",
	  "control_plane": {"address": "http://localhost:5681"},
	  "summary": {"findings": 0, "coverage_gaps": 0, "manual_checks": 0},
	  "findings": [],
	  "coverage_gaps": [],
	  "manual_checks": []
	}`
	path := filepath.Join(t.TempDir(), "failed.json")
	if err := os.WriteFile(path, []byte(failed), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	oldArgs := os.Args
	oldFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	})

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	out := filepath.Join(t.TempDir(), "report.html")
	os.Args = []string{"kong-mesh-v3-preflight", "--from-json", path, "--format", "html", "--output", out}

	if got := run(); got != 2 {
		t.Fatalf("run() exit = %d, want 2", got)
	}
}

func TestValidAddress(t *testing.T) {
	if err := validAddress("http://localhost:5681"); err != nil {
		t.Errorf("valid address rejected: %v", err)
	}
	for _, bad := range []string{"", "not-a-url", "localhost:5681", "://bad"} {
		if err := validAddress(bad); err == nil {
			t.Errorf("validAddress(%q) should error", bad)
		}
	}
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func TestRunVersion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantExit int
		wantOut  string
	}{
		{name: "subcommand", args: []string{"version"}, wantExit: 0, wantOut: "kong-mesh-v3-preflight dev\n"},
		{name: "flag", args: []string{"--version"}, wantExit: 0, wantOut: "kong-mesh-v3-preflight dev\n"},
		{name: "unknown positional", args: []string{"report"}, wantExit: 2, wantOut: ""},
		{name: "extra positional", args: []string{"version", "now"}, wantExit: 2, wantOut: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldArgs, oldFlags, oldStdout := os.Args, flag.CommandLine, os.Stdout
			t.Cleanup(func() {
				os.Args, flag.CommandLine, os.Stdout = oldArgs, oldFlags, oldStdout
			})

			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("os.Pipe: %v", err)
			}
			os.Stdout = w
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
			flag.CommandLine.SetOutput(os.Stderr)
			os.Args = append([]string{"kong-mesh-v3-preflight"}, tc.args...)

			got := run()
			_ = w.Close()
			out, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("reading stdout: %v", err)
			}

			if got != tc.wantExit {
				t.Errorf("run() exit = %d, want %d", got, tc.wantExit)
			}
			if string(out) != tc.wantOut {
				t.Errorf("stdout = %q, want %q", out, tc.wantOut)
			}
		})
	}
}

func TestToolVersionPrefersReleaseStamp(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "1.2.3"
	if got := toolVersion(); got != "1.2.3" {
		t.Errorf("toolVersion() = %q, want %q", got, "1.2.3")
	}
}
