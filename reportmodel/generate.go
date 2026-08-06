package reportmodel

// openapigen lives in its own module (tools/openapigen/go.mod) so its
// dependencies never touch this module's dependency graph; `go generate`
// therefore has to cd into it before running.
//go:generate sh -c "cd ../tools/openapigen && go run ."
