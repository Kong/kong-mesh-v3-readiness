// Command openapigen regenerates docs/openapi.yaml from the reportmodel
// package: it reflects reportmodel.Report and reportmodel.Classification into
// JSON Schema (via invopop/jsonschema, picking up field doc comments and
// jsonschema struct tags), merges the results into one components.schemas
// map, and writes it under the hand-authored info/externalDocs/paths preamble
// below. Run via `go generate ./...` from the repo root after changing a
// reportmodel type.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/invopop/jsonschema"
	"sigs.k8s.io/yaml"

	"github.com/Kong/kong-mesh-v3-readiness/reportmodel"
)

const repoModulePath = "github.com/Kong/kong-mesh-v3-readiness"

const header = `openapi: 3.1.0
info:
  title: kuma3-preflight report schema
  version: "1.0.0"
  description: |
    Schema for the JSON documents emitted by the ` + "`kuma3-preflight`" + ` CLI
    (` + "`github.com/Kong/kong-mesh-v3-readiness`" + `, ` + "`cmd/kuma3-preflight`" + `).

    ` + "`kuma3-preflight`" + ` is a CLI, not an HTTP service — this document has no ` + "`paths`" + `.
    It exists only so the two JSON contracts below can be browsed/validated with
    standard OpenAPI/JSON-Schema tooling (Redoc, openapi-generator, ajv). Point such
    tooling at a real file — ` + "`--output report.json`" + `, or ` + "`--classify ... --format json" + `
    --output classification.json` + "`" + ` — and validate it against the matching schema.

    Two independent, versioned contracts are shipped:
    - ` + "`Report`" + ` — the CP-audit report (default command; ` + "`schema` = `kuma3-preflight/vN`" + `).
    - ` + "`Classification`" + ` — the ` + "`--classify`" + ` output (` + "`schema` = `kuma3-preflight-classification/v1`" + `).
    Each is a stable contract: ` + "`--from-json`" + ` reloads ` + "`Report`" + ` verbatim, so JSON,
    HTML (and, for classification, Markdown) render from the exact same object.

    Generated from the ` + "`reportmodel`" + ` Go package by ` + "`tools/openapigen`" + ` — do not edit by
    hand; run ` + "`go generate ./...`" + ` from the repo root after changing a reportmodel type.
  license:
    name: Apache-2.0
externalDocs:
  description: Repository README and architecture notes
  url: https://github.com/Kong/kong-mesh-v3-readiness
paths: {}
`

// repoRoot locates the main module's root on disk relative to this source
// file, so the generator works regardless of the caller's cwd.
func repoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func reflectAll(r *jsonschema.Reflector) jsonschema.Definitions {
	merged := jsonschema.Definitions{}
	for _, v := range []any{&reportmodel.Report{}, &reportmodel.Classification{}} {
		s := r.Reflect(v)
		for name, def := range s.Definitions {
			merged[name] = def
		}
	}
	return merged
}

// componentsYAML renders defs as an indented `components:\n  schemas:\n` YAML
// block, with every "#/$defs/X" ref rewritten to the OpenAPI-conventional
// "#/components/schemas/X".
func componentsYAML(defs jsonschema.Definitions) (string, error) {
	raw, err := json.Marshal(defs)
	if err != nil {
		return "", fmt.Errorf("marshal schemas: %w", err)
	}
	raw = bytes.ReplaceAll(raw, []byte(`"#/$defs/`), []byte(`"#/components/schemas/`))

	y, err := yaml.JSONToYAML(raw)
	if err != nil {
		return "", fmt.Errorf("convert schemas to yaml: %w", err)
	}

	var b bytes.Buffer
	b.WriteString("components:\n  schemas:\n")
	for _, line := range bytes.Split(bytes.TrimRight(y, "\n"), []byte("\n")) {
		b.WriteString("    ")
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// run must execute with cwd == the main module's root: AddGoComments derives
// a type's fully-qualified package path by joining its base argument to the
// path argument's directory components, so path has to be the module-root-
// relative package dir ("reportmodel"), not an absolute one.
func run() error {
	if err := os.Chdir(repoRoot()); err != nil {
		return fmt.Errorf("chdir to repo root: %w", err)
	}

	r := &jsonschema.Reflector{}
	if err := r.AddGoComments(repoModulePath, "reportmodel"); err != nil {
		return fmt.Errorf("read reportmodel doc comments: %w", err)
	}

	defs := reflectAll(r)
	components, err := componentsYAML(defs)
	if err != nil {
		return err
	}

	const outPath = "docs/openapi.yaml"
	if err := os.WriteFile(outPath, []byte(header+"\n"+components), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", outPath)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "openapigen: %v\n", err)
		os.Exit(1)
	}
}
