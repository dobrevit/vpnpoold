package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

func New(output io.Writer, format, levelName string) (*slog.Logger, error) {
	level, err := parseLevel(levelName)
	if err != nil {
		return nil, err
	}
	options := &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redactAttribute,
	}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(output, options)
	case "text":
		handler = slog.NewTextHandler(output, options)
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}
	return slog.New(handler), nil
}

func parseLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", value)
	}
}

func redactAttribute(_ []string, attr slog.Attr) slog.Attr {
	if isSensitiveKey(attr.Key) {
		return slog.String(attr.Key, "[REDACTED]")
	}
	if attr.Value.Kind() == slog.KindGroup {
		attributes := attr.Value.Group()
		for index := range attributes {
			attributes[index] = redactAttribute(nil, attributes[index])
		}
		return slog.Group(attr.Key, attrsToAny(attributes)...)
	}
	return attr
}

func attrsToAny(attributes []slog.Attr) []any {
	values := make([]any, len(attributes))
	for index := range attributes {
		values[index] = attributes[index]
	}
	return values
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, fragment := range []string{"password", "credential", "private_key", "auth_token", "secret"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
