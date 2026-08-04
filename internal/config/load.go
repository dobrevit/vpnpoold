package config

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()

	cfg, err := Decode(file)
	if err != nil {
		return nil, fmt.Errorf("decode configuration %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration %q: %w", path, err)
	}
	return cfg, nil
}

func Decode(r io.Reader) (*Config, error) {
	cfg := Defaults()
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("configuration is empty")
		}
		return nil, err
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("decode trailing YAML document: %w", err)
		}
		return nil, errors.New("multiple YAML documents are not allowed")
	}
	return &cfg, nil
}
