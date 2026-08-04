package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dobrevit/vpnpoold/internal/netutil"
)

var (
	jsonFieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
)

type ValidationError struct {
	Problems []error
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d validation error(s)", len(e.Problems))
	for _, problem := range e.Problems {
		fmt.Fprintf(&b, "\n- %v", problem)
	}
	return b.String()
}

func (e *ValidationError) Unwrap() []error {
	return e.Problems
}

func (c *Config) Validate() error {
	var problems []error
	add := func(err error) {
		if err != nil {
			problems = append(problems, err)
		}
	}

	if c.Version != CurrentVersion {
		add(fmt.Errorf("version: got %d, supported version is %d", c.Version, CurrentVersion))
	}
	add(validateRuntime(c.Runtime))
	add(validateOpenVPN(c.OpenVPN))
	add(validateNetwork(c.Network, len(c.Workers)))
	add(validateProxy(c.Proxy))
	add(validateMetrics(c.Metrics))
	add(validateHealth(c.Health))
	add(validateWorkers(c.OpenVPN.ProfilesDir, c.Workers))

	if len(problems) != 0 {
		return &ValidationError{Problems: flattenValidationErrors(problems)}
	}
	return nil
}

func flattenValidationErrors(errs []error) []error {
	var flattened []error
	for _, err := range errs {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			flattened = append(flattened, validationErr.Problems...)
		} else {
			flattened = append(flattened, err)
		}
	}
	return flattened
}

func validateMetrics(metrics Metrics) error {
	if !metrics.Enabled {
		return nil
	}
	host, portText, err := net.SplitHostPort(metrics.Listen)
	if err != nil {
		return fmt.Errorf("metrics.listen: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return errors.New("metrics.listen must use a loopback IP literal")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("metrics.listen port must be between 1 and 65535")
	}
	return nil
}

func validateRuntime(runtime Runtime) error {
	var problems []error
	if !filepath.IsAbs(runtime.StateDir) {
		problems = append(problems, errors.New("runtime.state_dir must be an absolute path"))
	}
	if !filepath.IsAbs(runtime.RunDir) {
		problems = append(problems, errors.New("runtime.run_dir must be an absolute path"))
	}
	switch runtime.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, fmt.Errorf("runtime.log_level %q is unsupported", runtime.LogLevel))
	}
	switch runtime.LogFormat {
	case "json", "text":
	default:
		problems = append(problems, fmt.Errorf("runtime.log_format %q is unsupported", runtime.LogFormat))
	}
	return validationErrors(problems)
}

func validateOpenVPN(openvpn OpenVPN) error {
	var problems []error
	if !filepath.IsAbs(openvpn.Binary) {
		problems = append(problems, errors.New("openvpn.binary must be an absolute path"))
	} else if err := validateExecutable(openvpn.Binary); err != nil {
		problems = append(problems, fmt.Errorf("openvpn.binary: %w", err))
	}
	if !filepath.IsAbs(openvpn.ProfilesDir) {
		problems = append(problems, errors.New("openvpn.profiles_dir must be an absolute path"))
	} else if info, err := os.Lstat(openvpn.ProfilesDir); err != nil {
		problems = append(problems, fmt.Errorf("openvpn.profiles_dir: %w", err))
	} else if !info.IsDir() {
		problems = append(problems, errors.New("openvpn.profiles_dir must name a directory"))
	} else if info.Mode().Perm()&0o022 != 0 {
		problems = append(problems, errors.New("openvpn.profiles_dir must not be writable by group or other users"))
	}
	if openvpn.ConnectTimeout.Duration <= 0 {
		problems = append(problems, errors.New("openvpn.connect_timeout must be positive"))
	}
	if openvpn.RestartMinBackoff.Duration <= 0 {
		problems = append(problems, errors.New("openvpn.restart_min_backoff must be positive"))
	}
	if openvpn.RestartMaxBackoff.Duration < openvpn.RestartMinBackoff.Duration {
		problems = append(problems, errors.New("openvpn.restart_max_backoff must be greater than or equal to restart_min_backoff"))
	}
	if openvpn.CrashLoopWindow.Duration <= 0 {
		problems = append(problems, errors.New("openvpn.crash_loop_window must be positive"))
	}
	if openvpn.CrashLoopLimit <= 0 {
		problems = append(problems, errors.New("openvpn.crash_loop_limit must be positive"))
	}
	return validationErrors(problems)
}

func validateExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("must name a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("is not executable")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("must not be writable by group or other users")
	}
	if err := validateTrustedParent(path); err != nil {
		return err
	}
	return nil
}

func validateNetwork(networkConfig Network, workerCount int) error {
	var problems []error
	if !netutil.IsValidResourcePrefix(networkConfig.NamespacePrefix) {
		problems = append(problems, errors.New("network.namespace_prefix must start with a lowercase letter and contain only lowercase letters, digits, and hyphens"))
	}
	subnet, err := netip.ParsePrefix(networkConfig.Subnet)
	if err != nil {
		problems = append(problems, fmt.Errorf("network.subnet: %w", err))
	} else {
		subnet = subnet.Masked()
		if !subnet.Addr().Is4() {
			problems = append(problems, errors.New("network.subnet must be IPv4"))
		}
		if networkConfig.Subnet != subnet.String() {
			problems = append(problems, fmt.Errorf("network.subnet must be canonical network prefix %q", subnet.String()))
		}
		if networkConfig.WorkerPrefixLength < subnet.Bits() || networkConfig.WorkerPrefixLength > 30 {
			problems = append(problems, fmt.Errorf("network.worker_prefix_length must be between %d and 30", subnet.Bits()))
		} else {
			capacityBits := networkConfig.WorkerPrefixLength - subnet.Bits()
			capacity := uint64(1) << capacityBits
			if uint64(workerCount) > capacity {
				problems = append(problems, fmt.Errorf("network.subnet has capacity for %d worker subnet(s), but %d workers are configured", capacity, workerCount))
			}
		}
	}
	if !netutil.IsValidInterfaceName(networkConfig.HostUplinkInterface) {
		problems = append(problems, errors.New("network.host_uplink_interface must be a valid Linux interface name"))
	}
	if !netutil.IsValidInterfaceName(networkConfig.TunnelInterface) {
		problems = append(problems, errors.New("network.tunnel_interface must be a valid Linux interface name"))
	}
	seenDNSServers := make(map[netip.Addr]struct{}, len(networkConfig.DNSServers))
	for index, value := range networkConfig.DNSServers {
		address, parseErr := netip.ParseAddr(value)
		if parseErr != nil ||
			!address.Is4() ||
			!address.IsGlobalUnicast() ||
			address.IsLoopback() ||
			address.IsLinkLocalUnicast() ||
			address.IsMulticast() ||
			address.IsUnspecified() {
			problems = append(problems, fmt.Errorf("network.dns_servers[%d] must be a usable IPv4 unicast address", index))
			continue
		}
		address = address.Unmap()
		if _, exists := seenDNSServers[address]; exists {
			problems = append(problems, fmt.Errorf("network.dns_servers[%d] is duplicated", index))
		}
		seenDNSServers[address] = struct{}{}
	}
	return validationErrors(problems)
}

func validateProxy(proxy Proxy) error {
	var problems []error
	host, portText, err := net.SplitHostPort(proxy.Listen)
	if err != nil {
		problems = append(problems, fmt.Errorf("proxy.listen: %w", err))
	} else {
		ip, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			problems = append(problems, errors.New("proxy.listen host must be an IP literal"))
		} else if !ip.IsLoopback() && !proxy.Authentication.Enabled && !proxy.AllowInsecurePublicListener {
			problems = append(problems, errors.New("proxy.listen is non-loopback but authentication is disabled; enable authentication or explicitly set allow_insecure_public_listener"))
		}
		port, portErr := strconv.Atoi(portText)
		if portErr != nil || port < 1 || port > 65535 {
			problems = append(problems, errors.New("proxy.listen port must be between 1 and 65535"))
		}
	}
	if proxy.WorkerPort < 1 || proxy.WorkerPort > 65535 {
		problems = append(problems, errors.New("proxy.worker_port must be between 1 and 65535"))
	}
	if proxy.HandshakeTimeout.Duration <= 0 {
		problems = append(problems, errors.New("proxy.handshake_timeout must be positive"))
	}
	if proxy.ConnectTimeout.Duration <= 0 {
		problems = append(problems, errors.New("proxy.connect_timeout must be positive"))
	}
	if proxy.IdleTimeout.Duration <= 0 {
		problems = append(problems, errors.New("proxy.idle_timeout must be positive"))
	}
	if proxy.MaxConnectAttempts < 0 || proxy.MaxConnectAttempts > 100 {
		problems = append(problems, errors.New("proxy.max_connect_attempts must be between 0 and 100"))
	}
	if proxy.Authentication.Enabled {
		if !filepath.IsAbs(proxy.Authentication.UsersFile) {
			problems = append(problems, errors.New("proxy.authentication.users_file must be an absolute path when authentication is enabled"))
		} else {
			problems = append(problems, validatePrivateFile(
				"proxy.authentication.users_file",
				proxy.Authentication.UsersFile,
			)...)
		}
	}
	switch proxy.Balancing.Mode {
	case "round_robin", "least_connections", "source_hash", "username_hash", "session_hash":
	default:
		problems = append(problems, fmt.Errorf("proxy.balancing.mode %q is unsupported", proxy.Balancing.Mode))
	}
	if (proxy.Balancing.Mode == "username_hash" || proxy.Balancing.Mode == "session_hash") &&
		!proxy.Authentication.Enabled {
		problems = append(problems, fmt.Errorf("proxy.balancing.mode %q requires authentication", proxy.Balancing.Mode))
	}
	if proxy.Balancing.SessionSeparator == "" {
		problems = append(problems, errors.New("proxy.balancing.session_separator must not be empty"))
	}
	if len(proxy.Balancing.SessionSeparator) > 8 {
		problems = append(problems, errors.New("proxy.balancing.session_separator must be at most 8 bytes"))
	}
	return validationErrors(problems)
}

func validateHealth(health Health) error {
	var problems []error
	if health.Interval.Duration <= 0 {
		problems = append(problems, errors.New("health.interval must be positive"))
	}
	if health.Timeout.Duration <= 0 {
		problems = append(problems, errors.New("health.timeout must be positive"))
	}
	if health.Timeout.Duration > health.Interval.Duration {
		problems = append(problems, errors.New("health.timeout must not exceed health.interval"))
	}
	if health.FailureThreshold != 1 {
		problems = append(problems, errors.New("health.failure_threshold must be 1 to preserve immediate fail-closed withdrawal"))
	}
	if health.SuccessThreshold <= 0 {
		problems = append(problems, errors.New("health.success_threshold must be positive"))
	}
	parsedURL, err := url.Parse(health.IPCheckURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		problems = append(problems, errors.New("health.ip_check_url must be an absolute HTTP or HTTPS URL"))
	} else if reservedExampleHost(parsedURL.Hostname()) {
		problems = append(problems, errors.New("health.ip_check_url must not use a reserved example or .invalid domain"))
	}
	switch health.ExpectedResponseFormat {
	case "plain_text":
		if health.JSONField != "" {
			problems = append(problems, errors.New("health.json_field must be empty for plain_text responses"))
		}
	case "json":
		if !jsonFieldPattern.MatchString(health.JSONField) {
			problems = append(problems, errors.New("health.json_field is required for JSON responses and must be a simple dotted field path"))
		}
	default:
		problems = append(problems, fmt.Errorf("health.expected_response_format %q is unsupported", health.ExpectedResponseFormat))
	}
	seenHostIPs := make(map[netip.Addr]struct{}, len(health.HostPublicIPs))
	for index, value := range health.HostPublicIPs {
		address, parseErr := netip.ParseAddr(value)
		if parseErr != nil || !isPublicUnicast(address) {
			problems = append(problems, fmt.Errorf("health.host_public_ips[%d] must be a public unicast IP address", index))
			continue
		}
		address = address.Unmap()
		if _, exists := seenHostIPs[address]; exists {
			problems = append(problems, fmt.Errorf("health.host_public_ips[%d] is duplicated", index))
		}
		seenHostIPs[address] = struct{}{}
	}
	return validationErrors(problems)
}

func reservedExampleHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suffix := range []string{"example.com", "example.net", "example.org", "invalid"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func IsValidWorkerID(id string) bool {
	return netutil.IsValidWorkerID(id)
}

func validateWorkers(profilesDir string, workers []Worker) error {
	var problems []error
	if len(workers) == 0 {
		problems = append(problems, errors.New("workers must contain at least one worker"))
	}
	seen := make(map[string]struct{}, len(workers))
	for index, worker := range workers {
		field := fmt.Sprintf("workers[%d]", index)
		if !netutil.IsValidWorkerID(worker.ID) {
			problems = append(problems, fmt.Errorf("%s.id %q is invalid", field, worker.ID))
		} else if _, exists := seen[worker.ID]; exists {
			problems = append(problems, fmt.Errorf("%s.id %q is duplicated", field, worker.ID))
		} else {
			seen[worker.ID] = struct{}{}
		}
		if worker.Config == "" || filepath.Base(worker.Config) != worker.Config || filepath.Ext(worker.Config) != ".ovpn" {
			problems = append(problems, fmt.Errorf("%s.config must be a base filename ending in .ovpn", field))
		} else if filepath.IsAbs(profilesDir) {
			profilePath := filepath.Join(profilesDir, worker.Config)
			problems = append(problems, validatePrivateFile(
				field+".config",
				profilePath,
			)...)
		}
		if worker.CredentialsFile != "" {
			problems = append(problems, validatePrivateFile(
				field+".credentials_file",
				worker.CredentialsFile,
			)...)
		}
		if worker.Management.UsernamePassword && worker.CredentialsFile == "" {
			problems = append(problems, fmt.Errorf(
				"%s.management.username_password requires credentials_file",
				field,
			))
		}
		if worker.Management.PrivateKeyPasswordFile != "" {
			problems = append(problems, validatePrivateFile(
				field+".management.private_key_password_file",
				worker.Management.PrivateKeyPasswordFile,
			)...)
		}
		if command := worker.Management.ChallengeResponseCommand; command != "" {
			if !filepath.IsAbs(command) {
				problems = append(problems, fmt.Errorf(
					"%s.management.challenge_response_command must be an absolute path",
					field,
				))
			} else if info, err := os.Lstat(command); err != nil {
				problems = append(problems, fmt.Errorf(
					"%s.management.challenge_response_command: %w",
					field,
					err,
				))
			} else if !info.Mode().IsRegular() {
				problems = append(problems, fmt.Errorf(
					"%s.management.challenge_response_command must name a regular file",
					field,
				))
			} else if info.Mode().Perm()&0o111 == 0 {
				problems = append(problems, fmt.Errorf(
					"%s.management.challenge_response_command must be executable",
					field,
				))
			} else if info.Mode().Perm()&0o022 != 0 {
				problems = append(problems, fmt.Errorf(
					"%s.management.challenge_response_command must not be writable by group or other users",
					field,
				))
			} else if err := validateTrustedParent(command); err != nil {
				problems = append(problems, fmt.Errorf(
					"%s.management.challenge_response_command: %w",
					field,
					err,
				))
			}
		}
		challengeTimeout := worker.Management.ChallengeTimeout.Duration
		if challengeTimeout < 0 ||
			(challengeTimeout > 0 && challengeTimeout < time.Second) ||
			challengeTimeout > 5*time.Minute {
			problems = append(problems, fmt.Errorf(
				"%s.management.challenge_timeout must be zero or between 1s and 5m",
				field,
			))
		}
		if challengeTimeout > 0 &&
			worker.Management.ChallengeResponseCommand == "" {
			problems = append(problems, fmt.Errorf(
				"%s.management.challenge_timeout requires challenge_response_command",
				field,
			))
		}
		if worker.UpstreamHTTPProxy != "" {
			host, portText, splitErr := net.SplitHostPort(worker.UpstreamHTTPProxy)
			address, addressErr := netip.ParseAddr(host)
			port, portErr := strconv.Atoi(portText)
			if splitErr != nil ||
				addressErr != nil ||
				!address.Is4() ||
				address.IsUnspecified() ||
				address.IsLoopback() ||
				address.IsMulticast() ||
				portErr != nil ||
				port < 1 ||
				port > 65535 {
				problems = append(problems, fmt.Errorf(
					"%s.upstream_http_proxy must be an explicit IPv4 address and TCP port",
					field,
				))
			}
		}
		if worker.Weight <= 0 {
			problems = append(problems, fmt.Errorf("%s.weight must be positive", field))
		} else if worker.Weight > 100 {
			problems = append(problems, fmt.Errorf("%s.weight must not exceed 100", field))
		}
		if worker.ExpectedPublicIP != "" {
			ip, err := netip.ParseAddr(worker.ExpectedPublicIP)
			if err != nil || !isPublicUnicast(ip) {
				problems = append(problems, fmt.Errorf("%s.expected_public_ip must be a public unicast IP address", field))
			}
		}
	}
	return validationErrors(problems)
}

func validatePrivateFile(field, path string) []error {
	if !filepath.IsAbs(path) {
		return []error{fmt.Errorf("%s must be an absolute path", field)}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return []error{fmt.Errorf("%s: %w", field, err)}
	}
	if !info.Mode().IsRegular() {
		return []error{fmt.Errorf("%s must name a regular file", field)}
	}
	if info.Mode().Perm()&0o077 != 0 {
		return []error{fmt.Errorf(
			"%s must not be accessible by group or other users",
			field,
		)}
	}
	if err := validateTrustedParent(path); err != nil {
		return []error{fmt.Errorf("%s: %w", field, err)}
	}
	return nil
}

func validateTrustedParent(path string) error {
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("parent directory: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("parent directory must not be writable by group or other users")
	}
	return nil
}

func isPublicUnicast(ip netip.Addr) bool {
	return ip.IsValid() &&
		ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}

func validationErrors(problems []error) error {
	if len(problems) == 0 {
		return nil
	}
	return &ValidationError{Problems: problems}
}
