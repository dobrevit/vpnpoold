package config

import (
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	CurrentVersion       = 1
	DefaultConfigPath    = "/etc/vpnpoold/vpnpoold.yaml"
	DefaultOpenVPNBinary = "/usr/sbin/openvpn"
)

type Config struct {
	Version int      `yaml:"version"`
	Runtime Runtime  `yaml:"runtime"`
	OpenVPN OpenVPN  `yaml:"openvpn"`
	Network Network  `yaml:"network"`
	Proxy   Proxy    `yaml:"proxy"`
	Metrics Metrics  `yaml:"metrics"`
	Health  Health   `yaml:"health"`
	Workers []Worker `yaml:"workers"`
}

type Runtime struct {
	StateDir              string `yaml:"state_dir"`
	RunDir                string `yaml:"run_dir"`
	LogLevel              string `yaml:"log_level"`
	LogFormat             string `yaml:"log_format"`
	CleanupStaleResources bool   `yaml:"cleanup_stale_resources"`
}

type OpenVPN struct {
	Binary            string   `yaml:"binary"`
	ProfilesDir       string   `yaml:"profiles_dir"`
	ConnectTimeout    Duration `yaml:"connect_timeout"`
	RestartMinBackoff Duration `yaml:"restart_min_backoff"`
	RestartMaxBackoff Duration `yaml:"restart_max_backoff"`
	CrashLoopWindow   Duration `yaml:"crash_loop_window"`
	CrashLoopLimit    int      `yaml:"crash_loop_limit"`
}

type Network struct {
	NamespacePrefix            string   `yaml:"namespace_prefix"`
	Subnet                     string   `yaml:"subnet"`
	WorkerPrefixLength         int      `yaml:"worker_prefix_length"`
	HostUplinkInterface        string   `yaml:"host_uplink_interface"`
	TunnelInterface            string   `yaml:"tunnel_interface"`
	DNSServers                 []string `yaml:"dns_servers"`
	DisableIPv6WhenUnavailable bool     `yaml:"disable_ipv6_when_unavailable"`
}

type Proxy struct {
	Listen                      string         `yaml:"listen"`
	WorkerPort                  int            `yaml:"worker_port"`
	HandshakeTimeout            Duration       `yaml:"handshake_timeout"`
	ConnectTimeout              Duration       `yaml:"connect_timeout"`
	IdleTimeout                 Duration       `yaml:"idle_timeout"`
	MaxConnectAttempts          int            `yaml:"max_connect_attempts"`
	Authentication              Authentication `yaml:"authentication"`
	AllowInsecurePublicListener bool           `yaml:"allow_insecure_public_listener"`
	Balancing                   Balancing      `yaml:"balancing"`
}

type Authentication struct {
	Enabled   bool   `yaml:"enabled"`
	UsersFile string `yaml:"users_file"`
}

type Balancing struct {
	Mode               string `yaml:"mode"`
	UniquenessEnforced bool   `yaml:"uniqueness_enforced"`
	SessionSeparator   string `yaml:"session_separator"`
}

type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type Health struct {
	Interval               Duration `yaml:"interval"`
	Timeout                Duration `yaml:"timeout"`
	FailureThreshold       int      `yaml:"failure_threshold"`
	SuccessThreshold       int      `yaml:"success_threshold"`
	IPCheckURL             string   `yaml:"ip_check_url"`
	ExpectedResponseFormat string   `yaml:"expected_response_format"`
	JSONField              string   `yaml:"json_field"`
	HostPublicIPs          []string `yaml:"host_public_ips"`
}

type Worker struct {
	ID                string           `yaml:"id"`
	Config            string           `yaml:"config"`
	CredentialsFile   string           `yaml:"credentials_file"`
	Management        WorkerManagement `yaml:"management"`
	UpstreamHTTPProxy string           `yaml:"upstream_http_proxy"`
	Enabled           bool             `yaml:"enabled"`
	ExpectedPublicIP  string           `yaml:"expected_public_ip"`
	Weight            int              `yaml:"weight"`
}

// UnmarshalYAML keeps workers enabled by default. A missing enabled key must
// not silently turn a configured VPN profile off. Because custom unmarshalling
// bypasses yaml.Decoder.KnownFields for this node, validate its keys here too.
func (w *Worker) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("worker must be a mapping")
	}
	workerFields := map[string]struct{}{
		"id": {}, "config": {}, "credentials_file": {}, "management": {},
		"upstream_http_proxy": {}, "enabled": {}, "expected_public_ip": {}, "weight": {},
	}
	managementFields := map[string]struct{}{
		"username_password": {}, "private_key_password_file": {},
		"challenge_response_command": {}, "challenge_timeout": {},
	}
	for index := 0; index < len(node.Content); index += 2 {
		key, value := node.Content[index], node.Content[index+1]
		if _, known := workerFields[key.Value]; !known {
			return fmt.Errorf("field %s not found in type config.Worker", key.Value)
		}
		if key.Value == "management" {
			if value.Kind != yaml.MappingNode {
				return errors.New("worker management must be a mapping")
			}
			for child := 0; child < len(value.Content); child += 2 {
				managementKey := value.Content[child]
				if _, known := managementFields[managementKey.Value]; !known {
					return fmt.Errorf(
						"field %s not found in type config.WorkerManagement", managementKey.Value,
					)
				}
			}
		}
	}
	type plainWorker Worker
	decoded := plainWorker{Enabled: true}
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*w = Worker(decoded)
	return nil
}

type WorkerManagement struct {
	UsernamePassword         bool     `yaml:"username_password"`
	PrivateKeyPasswordFile   string   `yaml:"private_key_password_file"`
	ChallengeResponseCommand string   `yaml:"challenge_response_command"`
	ChallengeTimeout         Duration `yaml:"challenge_timeout"`
}

// Duration deliberately accepts only YAML strings such as "5s". Requiring a
// unit avoids dangerous ambiguity between seconds, milliseconds, and nanoseconds.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("duration must be a quoted or plain string with a unit")
	}
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	d.Duration = value
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

func Defaults() Config {
	return Config{
		Version: CurrentVersion,
		Runtime: Runtime{
			StateDir:              "/var/lib/vpnpoold",
			RunDir:                "/run/vpnpoold",
			LogLevel:              "info",
			LogFormat:             "json",
			CleanupStaleResources: true,
		},
		OpenVPN: OpenVPN{
			Binary:            DefaultOpenVPNBinary,
			ProfilesDir:       "/etc/vpnpoold/profiles",
			ConnectTimeout:    Duration{Duration: 45 * time.Second},
			RestartMinBackoff: Duration{Duration: time.Second},
			RestartMaxBackoff: Duration{Duration: time.Minute},
			CrashLoopWindow:   Duration{Duration: 5 * time.Minute},
			CrashLoopLimit:    10,
		},
		Network: Network{
			NamespacePrefix:            "vpnpool",
			Subnet:                     "10.231.0.0/16",
			WorkerPrefixLength:         30,
			TunnelInterface:            "tun0",
			DisableIPv6WhenUnavailable: true,
		},
		Proxy: Proxy{
			Listen:             "127.0.0.1:1080",
			WorkerPort:         1081,
			HandshakeTimeout:   Duration{Duration: 10 * time.Second},
			ConnectTimeout:     Duration{Duration: 15 * time.Second},
			IdleTimeout:        Duration{Duration: 5 * time.Minute},
			MaxConnectAttempts: 0,
			Balancing: Balancing{
				Mode:               "least_connections",
				UniquenessEnforced: true,
				SessionSeparator:   "/",
			},
		},
		Metrics: Metrics{
			Enabled: false,
			Listen:  "127.0.0.1:9090",
		},
		Health: Health{
			Interval:               Duration{Duration: 10 * time.Second},
			Timeout:                Duration{Duration: 5 * time.Second},
			FailureThreshold:       1,
			SuccessThreshold:       2,
			ExpectedResponseFormat: "plain_text",
		},
	}
}
