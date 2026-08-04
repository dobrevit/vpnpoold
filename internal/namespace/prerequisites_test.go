package namespace

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckHostPrerequisites(t *testing.T) {
	tests := []struct {
		name        string
		values      map[string]string
		wantError   string
		wantWarning bool
	}{
		{
			name: "ready",
			values: map[string]string{
				ipForwardPath:   "1\n",
				allRPFilterPath: "0\n",
			},
		},
		{
			name: "forwarding disabled",
			values: map[string]string{
				ipForwardPath:   "0\n",
				allRPFilterPath: "0\n",
			},
			wantError: "ip_forward",
		},
		{
			name: "strict rp filter warning",
			values: map[string]string{
				ipForwardPath:   "1\n",
				allRPFilterPath: "1\n",
			},
			wantWarning: true,
		},
		{
			name: "invalid rp filter",
			values: map[string]string{
				ipForwardPath:   "1\n",
				allRPFilterPath: "9\n",
			},
			wantError: "unexpected",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := CheckHostPrerequisites(mapReader(test.values))
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if (len(result.Warnings) != 0) != test.wantWarning {
				t.Fatalf("warnings = %#v", result.Warnings)
			}
		})
	}
}

type mapReader map[string]string

func (r mapReader) ReadFile(path string) ([]byte, error) {
	value, exists := r[path]
	if !exists {
		return nil, errors.New("not found")
	}
	return []byte(value), nil
}
