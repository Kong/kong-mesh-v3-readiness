package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kong/kong-mesh-v3-readiness/preflight"
)

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
		preflight.StatusBlockers:     1,
		preflight.StatusFailed:       2,
		preflight.StatusInconclusive: 3,
		"unknown":                    0,
	}
	for status, want := range cases {
		if got := exitForStatus(status); got != want {
			t.Errorf("exitForStatus(%q) = %d, want %d", status, got, want)
		}
	}
}

func TestRunCollectionReadFailureExitsInconclusive(t *testing.T) {
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
		"kuma3-preflight",
		"--address", srv.URL,
		"--format", "json",
		"--output", out,
		"--latest-version", "2.14.0",
	}

	if got := run(); got != 3 {
		t.Fatalf("run() exit = %d, want 3", got)
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
