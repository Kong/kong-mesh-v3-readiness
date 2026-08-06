package main

import (
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
