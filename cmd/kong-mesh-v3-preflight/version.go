package main

import "runtime/debug"

// version is stamped at release time by GoReleaser (-X main.version=...).
var version = ""

// toolVersion reports the CLI version: the release stamp when present, else the
// module version recorded by `go install ...@vX`, else "dev" for local builds.
func toolVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
