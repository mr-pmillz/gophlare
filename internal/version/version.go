// Package version provides the build version shared by the CLI and SDK.
package version

import "runtime/debug"

const (
	modulePath         = "github.com/mr-pmillz/gophlare"
	developmentVersion = "dev"
)

// Set by Make and GoReleaser with -ldflags -X. An empty value uses Go's
// embedded module version, including for go install module@version.
var version string

// String returns the build version, or dev when no version metadata is available.
func String() string {
	if version != "" {
		return version
	}
	info, _ := debug.ReadBuildInfo()
	return fromBuildInfo(info)
}

func fromBuildInfo(info *debug.BuildInfo) string {
	if info != nil {
		if info.Main.Path == modulePath {
			return moduleVersion(&info.Main)
		}
		// When used as an SDK, report gophlare's version, not the host application's.
		for _, dep := range info.Deps {
			if dep.Path == modulePath {
				return moduleVersion(dep)
			}
		}
	}
	return developmentVersion
}

func moduleVersion(module *debug.Module) string {
	if module.Replace != nil {
		module = module.Replace
	}
	if module.Version == "" || module.Version == "(devel)" {
		return developmentVersion
	}
	return module.Version
}
