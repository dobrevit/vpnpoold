package buildinfo

import (
	"runtime"
	"runtime/debug"
	"sync"
)

// Version, Commit and Date are stamped by the release build through -ldflags.
// A build that omits them — for example the plain `go build ./cmd/vpnpoold`
// documented in the README — falls back to the VCS metadata the Go toolchain
// embeds, so an unstamped binary still reports the revision it was built from
// instead of "unknown". Requires the default -buildvcs=auto.
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

const (
	developmentVersion = "dev"
	unknownValue       = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	// Modified reports that the working tree held uncommitted changes at build
	// time. An operator comparing a deployed binary against a tag needs this.
	Modified bool `json:"modified"`
}

var (
	once     sync.Once
	resolved Info
)

func Current() Info {
	once.Do(func() { resolved = resolve(debug.ReadBuildInfo) })
	return resolved
}

func resolve(readBuildInfo func() (*debug.BuildInfo, bool)) Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: Date,
		GoVersion: runtime.Version(),
	}

	if build, ok := readBuildInfo(); ok && build != nil {
		settings := make(map[string]string, len(build.Settings))
		for _, setting := range build.Settings {
			settings[setting.Key] = setting.Value
		}
		if info.Commit == "" {
			info.Commit = settings["vcs.revision"]
		}
		if info.BuildDate == "" {
			info.BuildDate = settings["vcs.time"]
		}
		info.Modified = settings["vcs.modified"] == "true"
		// A `go install <module>@<version>` build carries its version here
		// even though no ldflags were applied.
		if info.Version == "" &&
			build.Main.Version != "" &&
			build.Main.Version != "(devel)" {
			info.Version = build.Main.Version
		}
	}

	if info.Version == "" {
		info.Version = developmentVersion
	}
	if info.Commit == "" {
		info.Commit = unknownValue
	}
	if info.BuildDate == "" {
		info.BuildDate = unknownValue
	}
	return info
}
