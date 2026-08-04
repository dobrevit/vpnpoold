package buildinfo

import "testing"

func TestCurrentAlwaysIncludesRuntimeVersion(t *testing.T) {
	info := Current()
	if info.Version == "" || info.Commit == "" ||
		info.BuildDate == "" || info.GoVersion == "" {
		t.Fatalf("Current() = %+v", info)
	}
}
