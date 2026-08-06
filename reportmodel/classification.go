package reportmodel

// Classification is the canonical, serializable form of a --classify run.
// JSON, HTML, and Markdown all render from this structure.
type Classification struct {
	Schema      string       `json:"schema" jsonschema:"enum=kuma3-preflight-classification/v1"`
	Tool        string       `json:"tool" jsonschema:"enum=kuma3-preflight"`
	GeneratedAt string       `json:"generatedAt,omitempty" jsonschema:"format=date-time"`
	SourceDir   string       `json:"sourceDir,omitempty"`
	ReportsDir  string       `json:"reportsDir,omitempty"`
	Summary     ClassSummary `json:"summary"`
	// Global lifts non-removable deprecations recurring across enough suites into
	// one cross-cutting fix, out of each Feature's Usages.
	Global   []GlobalMigration `json:"global"`
	Features []Feature         `json:"features"`
}

// ClassSummary is the headline counts shown above a classification report.
type ClassSummary struct {
	Features         int `json:"features" jsonschema:"minimum=0"`
	Remove           int `json:"remove" jsonschema:"minimum=0"`
	Rewrite          int `json:"rewrite" jsonschema:"minimum=0"`
	DeprecatedUsages int `json:"deprecatedUsages" jsonschema:"minimum=0"`
	GlobalMigrations int `json:"globalMigrations" jsonschema:"minimum=0"`
}

// GlobalMigration is a cross-cutting deprecation: a non-removable field/policy/
// mesh setting recurring across many suites, fixed once centrally rather than per suite.
type GlobalMigration struct {
	Kind        string `json:"kind"`
	Category    string `json:"category"`
	Replacement string `json:"replacement"`
	// Removable is always false here — removed resources stay per-suite removal work.
	Removable bool `json:"removable"`
	Suites    int  `json:"suites" jsonschema:"minimum=3"`
	Count     int  `json:"count" jsonschema:"minimum=0"`
}

// Feature is one e2e suite's deprecation classification.
type Feature struct {
	Name           string  `json:"name"`
	Recommendation string  `json:"recommendation" jsonschema:"enum=REMOVE/REPLACE,enum=REWRITE"`
	Usages         []Usage `json:"usages"`
}

// Usage is one deprecated-feature usage within a Feature.
type Usage struct {
	Kind        string   `json:"kind"`
	Category    string   `json:"category"`
	Replacement string   `json:"replacement"`
	Removable   bool     `json:"removable"`
	Count       int      `json:"count" jsonschema:"minimum=0"`
	Sources     []string `json:"sources"`
	Examples    []string `json:"examples"`
	// Global marks a usage whose Kind was lifted into Classification.Global; the
	// per-suite view omits these to avoid repeating the same fix in every suite.
	Global bool `json:"global,omitempty"`
}
