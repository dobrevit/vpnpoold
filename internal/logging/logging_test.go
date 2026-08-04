package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewFiltersLevelsAndRedactsSensitiveAttributes(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, "json", "info")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	logger.Debug("hidden")
	logger.Info("started",
		slog.String("worker", "france-1"),
		slog.String("password", "do-not-log"),
		slog.Group("openvpn", slog.String("private_key_path", "/secret/key")),
	)
	logged := output.String()
	if strings.Contains(logged, "hidden") {
		t.Fatalf("debug message was not filtered: %s", logged)
	}
	if strings.Contains(logged, "do-not-log") || strings.Contains(logged, "/secret/key") {
		t.Fatalf("sensitive value was not redacted: %s", logged)
	}
	if !strings.Contains(logged, `"password":"[REDACTED]"`) {
		t.Fatalf("redaction marker missing: %s", logged)
	}
	if !strings.Contains(logged, `"worker":"france-1"`) {
		t.Fatalf("ordinary attribute missing: %s", logged)
	}
}

func TestNewRejectsUnknownOptions(t *testing.T) {
	for _, test := range []struct {
		format string
		level  string
	}{
		{format: "xml", level: "info"},
		{format: "json", level: "verbose"},
	} {
		if _, err := New(&bytes.Buffer{}, test.format, test.level); err == nil {
			t.Fatalf("New(%q, %q) unexpectedly succeeded", test.format, test.level)
		}
	}
}
