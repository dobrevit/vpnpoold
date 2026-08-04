package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecodeAppliesDefaultsAndRejectsUnknownFields(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := Decode(strings.NewReader("version: 1\n"))
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if cfg.Proxy.Listen != "127.0.0.1:1080" {
			t.Fatalf("Proxy.Listen = %q", cfg.Proxy.Listen)
		}
		if cfg.OpenVPN.ConnectTimeout.Duration != 45*time.Second {
			t.Fatalf("ConnectTimeout = %v", cfg.OpenVPN.ConnectTimeout.Duration)
		}
		if cfg.Metrics.Enabled || cfg.Metrics.Listen != "127.0.0.1:9090" {
			t.Fatalf("Metrics = %+v", cfg.Metrics)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		_, err := Decode(strings.NewReader("version: 1\nsurprise: true\n"))
		if err == nil || !strings.Contains(err.Error(), "field surprise not found") {
			t.Fatalf("Decode() error = %v", err)
		}
	})

	t.Run("numeric duration", func(t *testing.T) {
		_, err := Decode(strings.NewReader("version: 1\nhealth:\n  interval: 10\n"))
		if err == nil || !strings.Contains(err.Error(), "duration must be") {
			t.Fatalf("Decode() error = %v", err)
		}
	})

	t.Run("multiple documents", func(t *testing.T) {
		_, err := Decode(strings.NewReader("version: 1\n---\nversion: 1\n"))
		if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
			t.Fatalf("Decode() error = %v", err)
		}
	})

	t.Run("worker enabled defaults true", func(t *testing.T) {
		cfg, err := Decode(strings.NewReader("version: 1\nworkers:\n  - id: worker-1\n"))
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if len(cfg.Workers) != 1 || !cfg.Workers[0].Enabled {
			t.Fatalf("workers = %+v", cfg.Workers)
		}
	})

	t.Run("worker can be explicitly disabled", func(t *testing.T) {
		cfg, err := Decode(strings.NewReader(
			"version: 1\nworkers:\n  - id: worker-1\n    enabled: false\n",
		))
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if cfg.Workers[0].Enabled {
			t.Fatalf("workers = %+v", cfg.Workers)
		}
	})

	t.Run("unknown worker field", func(t *testing.T) {
		_, err := Decode(strings.NewReader("version: 1\nworkers:\n  - id: worker-1\n    surprise: true\n"))
		if err == nil || !strings.Contains(err.Error(), "field surprise not found") {
			t.Fatalf("Decode() error = %v", err)
		}
	})
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config, *testFiles)
		wantError string
	}{
		{
			name: "valid",
		},
		{
			name: "duplicate worker ID",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers = append(cfg.Workers, cfg.Workers[0])
			},
			wantError: "duplicated",
		},
		{
			name: "profile traversal",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].Config = "../secret.ovpn"
			},
			wantError: "base filename",
		},
		{
			name: "missing profile",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].Config = "missing.ovpn"
			},
			wantError: "no such file",
		},
		{
			name: "profile permissions",
			mutate: func(_ *Config, files *testFiles) {
				if err := os.Chmod(
					filepath.Join(files.profiles, files.profile),
					0o644,
				); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "config must not be accessible",
		},
		{
			name: "profile symlink",
			mutate: func(cfg *Config, files *testFiles) {
				link := filepath.Join(files.profiles, "worker-link.ovpn")
				if err := os.Symlink(
					filepath.Join(files.profiles, files.profile),
					link,
				); err != nil {
					t.Fatal(err)
				}
				cfg.Workers[0].Config = "worker-link.ovpn"
			},
			wantError: "config must name a regular file",
		},
		{
			name: "writable profiles directory",
			mutate: func(_ *Config, files *testFiles) {
				if err := os.Chmod(files.profiles, 0o770); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "profiles_dir must not be writable",
		},
		{
			name: "relative credentials file",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].CredentialsFile = "credentials"
			},
			wantError: "credentials_file must be an absolute path",
		},
		{
			name: "credentials file permissions",
			mutate: func(cfg *Config, files *testFiles) {
				cfg.Workers[0].CredentialsFile = files.credentials
				if err := os.Chmod(files.credentials, 0o640); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "credentials_file must not be accessible",
		},
		{
			name: "credentials file symlink",
			mutate: func(cfg *Config, files *testFiles) {
				link := filepath.Join(files.root, "credentials-link")
				if err := os.Symlink(files.credentials, link); err != nil {
					t.Fatal(err)
				}
				cfg.Workers[0].CredentialsFile = link
			},
			wantError: "credentials_file must name a regular file",
		},
		{
			name: "credentials file writable parent",
			mutate: func(cfg *Config, files *testFiles) {
				directory := filepath.Join(files.root, "shared")
				if err := os.Mkdir(directory, 0o770); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(directory, 0o770); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(directory, "credentials")
				if err := os.WriteFile(path, []byte("username\npassword\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.Workers[0].CredentialsFile = path
			},
			wantError: "parent directory must not be writable",
		},
		{
			name: "management username password requires credentials",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].Management.UsernamePassword = true
			},
			wantError: "requires credentials_file",
		},
		{
			name: "management username password",
			mutate: func(cfg *Config, files *testFiles) {
				cfg.Workers[0].CredentialsFile = files.credentials
				cfg.Workers[0].Management.UsernamePassword = true
			},
		},
		{
			name: "management private key password permissions",
			mutate: func(cfg *Config, files *testFiles) {
				cfg.Workers[0].Management.PrivateKeyPasswordFile = files.credentials
				if err := os.Chmod(files.credentials, 0o640); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "private_key_password_file must not be accessible",
		},
		{
			name: "relative management challenge helper",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].Management.ChallengeResponseCommand = "otp-helper"
			},
			wantError: "challenge_response_command must be an absolute path",
		},
		{
			name: "writable management challenge helper",
			mutate: func(cfg *Config, files *testFiles) {
				helper := filepath.Join(files.root, "otp-helper")
				if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o777); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(helper, 0o777); err != nil {
					t.Fatal(err)
				}
				cfg.Workers[0].Management.ChallengeResponseCommand = helper
			},
			wantError: "must not be writable by group or other",
		},
		{
			name: "management challenge timeout without helper",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].Management.ChallengeTimeout = Duration{
					Duration: 10 * time.Second,
				}
			},
			wantError: "challenge_timeout requires",
		},
		{
			name: "upstream proxy hostname",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].UpstreamHTTPProxy = "proxy.example:3128"
			},
			wantError: "upstream_http_proxy",
		},
		{
			name: "upstream proxy missing port",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].UpstreamHTTPProxy = "192.168.1.1"
			},
			wantError: "upstream_http_proxy",
		},
		{
			name: "public listener without auth",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Proxy.Listen = "0.0.0.0:1080"
			},
			wantError: "non-loopback",
		},
		{
			name: "public listener with auth",
			mutate: func(cfg *Config, files *testFiles) {
				cfg.Proxy.Listen = "0.0.0.0:1080"
				cfg.Proxy.Authentication.Enabled = true
				cfg.Proxy.Authentication.UsersFile = files.users
			},
		},
		{
			name: "explicit insecure listener",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Proxy.Listen = "0.0.0.0:1080"
				cfg.Proxy.AllowInsecurePublicListener = true
			},
		},
		{
			name: "loopback metrics listener",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Metrics.Enabled = true
				cfg.Metrics.Listen = "127.0.0.1:9090"
			},
		},
		{
			name: "public metrics listener",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Metrics.Enabled = true
				cfg.Metrics.Listen = "0.0.0.0:9090"
			},
			wantError: "metrics.listen must use a loopback",
		},
		{
			name: "metrics listener hostname",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Metrics.Enabled = true
				cfg.Metrics.Listen = "localhost:9090"
			},
			wantError: "metrics.listen must use a loopback",
		},
		{
			name: "unsupported balance mode",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Proxy.Balancing.Mode = "random"
			},
			wantError: "unsupported",
		},
		{
			name: "username hash without authentication",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Proxy.Balancing.Mode = "username_hash"
			},
			wantError: "requires authentication",
		},
		{
			name: "users file permissions",
			mutate: func(cfg *Config, files *testFiles) {
				cfg.Proxy.Authentication.Enabled = true
				cfg.Proxy.Authentication.UsersFile = files.users
				if err := os.Chmod(files.users, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "group or other",
		},
		{
			name: "users file symlink",
			mutate: func(cfg *Config, files *testFiles) {
				link := filepath.Join(files.root, "users-link.yaml")
				if err := os.Symlink(files.users, link); err != nil {
					t.Fatal(err)
				}
				cfg.Proxy.Authentication.Enabled = true
				cfg.Proxy.Authentication.UsersFile = link
			},
			wantError: "must name a regular file",
		},
		{
			name: "private expected IP",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Workers[0].ExpectedPublicIP = "10.0.0.1"
			},
			wantError: "public unicast",
		},
		{
			name: "private host public IP",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Health.HostPublicIPs = []string{"10.0.0.1"}
			},
			wantError: "host_public_ips",
		},
		{
			name: "noncanonical subnet",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Network.Subnet = "10.231.1.1/16"
			},
			wantError: "canonical",
		},
		{
			name: "loopback DNS server",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Network.DNSServers = []string{"127.0.0.53"}
			},
			wantError: "dns_servers",
		},
		{
			name: "duplicate DNS server",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Network.DNSServers = []string{"1.1.1.1", "1.1.1.1"}
			},
			wantError: "duplicated",
		},
		{
			name: "placeholder health endpoint",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Health.IPCheckURL = "https://example.invalid/ip"
			},
			wantError: ".invalid",
		},
		{
			name: "example health endpoint",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.Health.IPCheckURL = "https://ip.example.com/ip"
			},
			wantError: "reserved example",
		},
		{
			name: "backoff order",
			mutate: func(cfg *Config, _ *testFiles) {
				cfg.OpenVPN.RestartMinBackoff.Duration = 2 * time.Minute
			},
			wantError: "restart_max_backoff",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, files := validTestConfig(t)
			if test.mutate != nil {
				test.mutate(cfg, files)
			}
			err := cfg.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantError)
			}
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("Validate() error type = %T", err)
			}
		})
	}
}

func TestLoadValidatesReferencedFiles(t *testing.T) {
	cfg, files := validTestConfig(t)
	data := strings.NewReader(renderTestConfig(cfg, files))
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

type testFiles struct {
	root        string
	binary      string
	profiles    string
	profile     string
	users       string
	credentials string
}

func validTestConfig(t *testing.T) (*Config, *testFiles) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	files := &testFiles{
		root:        root,
		binary:      filepath.Join(root, "openvpn"),
		profiles:    filepath.Join(root, "profiles"),
		profile:     "worker.ovpn",
		users:       filepath.Join(root, "users.yaml"),
		credentials: filepath.Join(root, "credentials"),
	}
	if err := os.Mkdir(files.profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.binary, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(files.profiles, files.profile), []byte("client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.users, []byte("users: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.credentials, []byte("username\npassword\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Defaults()
	cfg.OpenVPN.Binary = files.binary
	cfg.OpenVPN.ProfilesDir = files.profiles
	cfg.Network.HostUplinkInterface = "eth0"
	cfg.Health.IPCheckURL = "https://ip-check.test-domain.dev/ip"
	cfg.Workers = []Worker{{
		ID:      "worker-1",
		Config:  files.profile,
		Enabled: true,
		Weight:  1,
	}}
	return &cfg, files
}

func renderTestConfig(cfg *Config, files *testFiles) string {
	return "version: 1\n" +
		"openvpn:\n" +
		"  binary: " + files.binary + "\n" +
		"  profiles_dir: " + files.profiles + "\n" +
		"network:\n" +
		"  host_uplink_interface: eth0\n" +
		"health:\n" +
		"  ip_check_url: https://ip-check.test-domain.dev/ip\n" +
		"workers:\n" +
		"  - id: " + cfg.Workers[0].ID + "\n" +
		"    config: " + cfg.Workers[0].Config + "\n" +
		"    enabled: true\n" +
		"    weight: 1\n"
}
