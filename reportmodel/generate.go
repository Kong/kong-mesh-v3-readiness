package reportmodel

// openapigen lives in its own module (tools/openapigen/go.mod) so its
// dependencies never touch this module's dependency graph; `go generate`
// therefore has to run it from there.
//go:generate go -C ../tools/openapigen run .
