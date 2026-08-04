package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

func ParseObservedIP(format, jsonField string, body []byte) (netip.Addr, error) {
	switch format {
	case "plain_text":
		return parsePlainText(body)
	case "json":
		return parseJSON(body, jsonField)
	default:
		return netip.Addr{}, fmt.Errorf("unsupported public-IP response format %q", format)
	}
}

func parseJSON(body []byte, fieldPath string) (netip.Addr, error) {
	if fieldPath == "" {
		return netip.Addr{}, errors.New("JSON field path is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return netip.Addr{}, errors.New("public-IP response is invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return netip.Addr{}, errors.New("public-IP response contains trailing JSON data")
	}
	current := value
	for _, field := range strings.Split(fieldPath, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return netip.Addr{}, fmt.Errorf("public-IP JSON field %q is not an object path", fieldPath)
		}
		current, ok = object[field]
		if !ok {
			return netip.Addr{}, fmt.Errorf("public-IP JSON field %q is missing", fieldPath)
		}
	}
	text, ok := current.(string)
	if !ok {
		return netip.Addr{}, fmt.Errorf("public-IP JSON field %q must be a string", fieldPath)
	}
	return parsePlainText([]byte(text))
}
