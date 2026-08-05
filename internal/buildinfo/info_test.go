package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestCurrentAlwaysIncludesRuntimeVersion(t *testing.T) {
	info := Current()
	if info.Version == "" || info.Commit == "" ||
		info.BuildDate == "" || info.GoVersion == "" {
		t.Fatalf("Current() = %+v", info)
	}
}

func TestResolvePrefersLdflagsOverVCSMetadata(t *testing.T) {
	vcsBuild := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: "v1.2.3"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abcdef123456"},
				{Key: "vcs.time", Value: "2026-01-02T03:04:05Z"},
				{Key: "vcs.modified", Value: "true"},
			},
		}, true
	}
	noBuild := func() (*debug.BuildInfo, bool) { return nil, false }

	tests := []struct {
		name          string
		version       string
		commit        string
		date          string
		readBuildInfo func() (*debug.BuildInfo, bool)
		want          Info
	}{
		{
			name:          "ldflags win over embedded VCS metadata",
			version:       "0.1.0",
			commit:        "stamped00cafe",
			date:          "2026-08-05T00:00:00Z",
			readBuildInfo: vcsBuild,
			want: Info{
				Version: "0.1.0", Commit: "stamped00cafe",
				BuildDate: "2026-08-05T00:00:00Z", Modified: true,
			},
		},
		{
			name:          "unstamped build falls back to VCS metadata",
			readBuildInfo: vcsBuild,
			want: Info{
				Version: "v1.2.3", Commit: "abcdef123456",
				BuildDate: "2026-01-02T03:04:05Z", Modified: true,
			},
		},
		{
			name:          "no ldflags and no build info degrades to placeholders",
			readBuildInfo: noBuild,
			want: Info{
				Version: developmentVersion, Commit: unknownValue,
				BuildDate: unknownValue, Modified: false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			Version, Commit, Date = test.version, test.commit, test.date
			t.Cleanup(func() { Version, Commit, Date = "", "", "" })

			got := resolve(test.readBuildInfo)
			if got.Version != test.want.Version ||
				got.Commit != test.want.Commit ||
				got.BuildDate != test.want.BuildDate ||
				got.Modified != test.want.Modified {
				t.Fatalf("resolve() = %+v, want %+v", got, test.want)
			}
			if got.GoVersion == "" {
				t.Fatal("resolve() did not record the Go version")
			}
		})
	}
}
