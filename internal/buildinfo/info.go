package buildinfo

import "runtime"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
}

func Current() Info {
	return Info{
		Version: Version, Commit: Commit, BuildDate: Date,
		GoVersion: runtime.Version(),
	}
}
