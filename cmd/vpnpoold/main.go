package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/dobrevit/vpnpoold/internal/buildinfo"
	"github.com/dobrevit/vpnpoold/internal/config"
	"github.com/dobrevit/vpnpoold/internal/control"
	daemonruntime "github.com/dobrevit/vpnpoold/internal/daemon"
	"github.com/dobrevit/vpnpoold/internal/health"
	"github.com/dobrevit/vpnpoold/internal/logging"
	"github.com/dobrevit/vpnpoold/internal/namespace"
	"github.com/dobrevit/vpnpoold/internal/openvpn"
	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/proxy/auth"
	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/proxy/socks5"
)

const defaultConfigPath = "/etc/vpnpoold/vpnpoold.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "worker-proxy":
		return runWorkerProxy(args[1:], stderr)
	case "validate-host":
		return runValidateHost(args[1:], stdout, stderr)
	case "daemon":
		return runDaemon(args[1:], stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "reload":
		return runReload(args[1:], stdout, stderr)
	case "worker":
		return runWorkerAction(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "version accepts no positional arguments")
		return 2
	}
	info := buildinfo.Current()
	switch *format {
	case "text":
		fmt.Fprintf(
			stdout,
			"vpnpoold %s (commit %s, built %s, %s)\n",
			info.Version,
			info.Commit,
			info.BuildDate,
			info.GoVersion,
		)
	case "json":
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			fmt.Fprintf(stderr, "write version: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintln(stderr, "version format must be text or json")
		return 2
	}
	return 0
}

func runWorkerAction(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "worker requires enable, disable, drain, undrain, or restart")
		return 2
	}
	action := args[0]
	switch action {
	case "enable", "disable", "drain", "undrain", "restart":
	default:
		fmt.Fprintf(stderr, "unsupported worker action %q\n", action)
		return 2
	}
	flags := flag.NewFlagSet("worker "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath, "path to the YAML configuration")
	timeout := flags.Duration("timeout", 5*time.Second, "control request timeout")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 1 || !config.IsValidWorkerID(flags.Arg(0)) {
		fmt.Fprintln(stderr, "worker action requires exactly one valid worker ID")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "worker action timeout must be positive")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load daemon configuration: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	workerID := flags.Arg(0)
	if err := control.WorkerAction(
		ctx,
		filepath.Join(cfg.Runtime.RunDir, "control.sock"),
		action,
		workerID,
	); err != nil {
		fmt.Fprintf(stderr, "%s worker %q: %v\n", action, workerID, err)
		return 1
	}
	fmt.Fprintf(stdout, "worker %s %s accepted\n", workerID, action)
	return 0
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath, "path to the YAML configuration")
	timeout := flags.Duration("timeout", 5*time.Second, "control request timeout")
	format := flags.String("format", "table", "output format: table or json")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "status accepts no positional arguments")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "status timeout must be positive")
		return 2
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintln(stderr, "status format must be table or json")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load daemon configuration: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	status, err := control.Status(ctx, filepath.Join(cfg.Runtime.RunDir, "control.sock"))
	if err != nil {
		fmt.Fprintf(stderr, "query daemon status: %v\n", err)
		return 1
	}
	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(status); err != nil {
			fmt.Fprintf(stderr, "write daemon status: %v\n", err)
			return 1
		}
		return 0
	}
	writeStatusTable(stdout, status)
	return 0
}

func writeStatusTable(output io.Writer, status control.StatusResponse) {
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "WORKER\tENABLED\tSTATE\tAVAILABLE\tDRAINING\tACTIVE\tVPN RESTARTS\tPROXY RESTARTS\tPUBLIC IP")
	for _, workerStatus := range status.Workers {
		publicIP := workerStatus.PublicIP
		if publicIP == "" {
			publicIP = "-"
		}
		fmt.Fprintf(table, "%s\t%t\t%s\t%t\t%t\t%d\t%d\t%d\t%s\n",
			workerStatus.ID,
			workerStatus.Enabled,
			workerStatus.State,
			workerStatus.Available,
			workerStatus.Draining,
			workerStatus.ActiveConnections,
			workerStatus.OpenVPNRestarts,
			workerStatus.ProxyRestarts,
			publicIP,
		)
	}
	_ = table.Flush()
}

func runReload(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("reload", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath, "path to the YAML configuration")
	timeout := flags.Duration("timeout", 5*time.Second, "control request timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "reload accepts no positional arguments")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "reload timeout must be positive")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load daemon configuration: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := control.Reload(ctx, filepath.Join(cfg.Runtime.RunDir, "control.sock")); err != nil {
		fmt.Fprintf(stderr, "request daemon reload: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "configuration reload accepted")
	return 0
}

func runDaemon(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath, "path to the YAML configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "daemon accepts no positional arguments")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "load daemon configuration: %v\n", err)
		return 1
	}
	logger, err := logging.New(stderr, cfg.Runtime.LogFormat, cfg.Runtime.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "configure logging: %v\n", err)
		return 1
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "vpnpoold daemon requires root privileges")
		return 1
	}
	instanceLock, err := daemonruntime.AcquireInstanceLock()
	if err != nil {
		fmt.Fprintf(stderr, "acquire daemon instance lock: %v\n", err)
		return 1
	}
	defer instanceLock.Close()

	authenticator, err := loadDaemonAuthenticator(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "load proxy users: %v\n", err)
		return 1
	}
	if err := ensureServiceDirectory(cfg.Runtime.StateDir); err != nil {
		fmt.Fprintf(stderr, "prepare state directory: %v\n", err)
		return 1
	}
	prerequisites, err := namespace.CheckHostPrerequisites(namespace.OSFileReader{})
	if err != nil {
		fmt.Fprintf(stderr, "host networking prerequisite: %v\n", err)
		return 1
	}
	for _, warning := range prerequisites.Warnings {
		logger.Warn("host networking warning", slog.String("warning", warning))
	}

	ipBinary, err := absoluteExecutable("ip")
	if err != nil {
		fmt.Fprintf(stderr, "find ip executable: %v\n", err)
		return 1
	}
	nftBinary, err := absoluteExecutable("nft")
	if err != nil {
		fmt.Fprintf(stderr, "find nft executable: %v\n", err)
		return 1
	}
	daemonBinary, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "resolve daemon executable: %v\n", err)
		return 1
	}
	daemonBinary, err = filepath.Abs(daemonBinary)
	if err != nil {
		fmt.Fprintf(stderr, "resolve daemon executable: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reloadRequests := make(chan struct{}, 1)
	requestReload := func(requestContext context.Context) error {
		select {
		case reloadRequests <- struct{}{}:
			return nil
		case <-requestContext.Done():
			return requestContext.Err()
		default:
			return errors.New("configuration reload is already pending")
		}
	}
	paths := daemonPaths{
		ipBinary: ipBinary, nftBinary: nftBinary, daemonBinary: daemonBinary,
	}
	runtime, err := buildDaemonRuntime(ctx, cfg, authenticator, paths, logger)
	if err != nil {
		fmt.Fprintf(stderr, "prepare daemon runtime: %v\n", err)
		return 1
	}
	runtime.SetReloadFunc(requestReload)
	logger.Info("daemon runtime prepared", slog.Int("workers", len(runtime.WorkerSnapshots())))
	activeRuntime := runtime

	hupSignals := make(chan os.Signal, 1)
	signal.Notify(hupSignals, syscall.SIGHUP)
	defer signal.Stop(hupSignals)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupSignals:
				select {
				case reloadRequests <- struct{}{}:
				default:
				}
			}
		}
	}()

	supervisor := daemonruntime.GenerationSupervisor{
		Initial: runtime,
		Logger:  logger,
		Prepare: func(prepareContext context.Context) (daemonruntime.ReloadCandidate, error) {
			drainingWorkers := make(map[string]bool)
			enabledOverrides := make(map[string]bool)
			for _, snapshot := range activeRuntime.WorkerSnapshots() {
				if snapshot.Draining {
					drainingWorkers[snapshot.ID] = true
				}
				if snapshot.EnabledOverridden {
					enabledOverrides[snapshot.ID] = snapshot.Enabled
				}
			}
			nextConfig, loadErr := config.Load(*configPath)
			if loadErr != nil {
				return daemonruntime.ReloadCandidate{}, fmt.Errorf("load replacement configuration: %w", loadErr)
			}
			nextLogger, logErr := logging.New(stderr, nextConfig.Runtime.LogFormat, nextConfig.Runtime.LogLevel)
			if logErr != nil {
				return daemonruntime.ReloadCandidate{}, fmt.Errorf("configure replacement logging: %w", logErr)
			}
			nextAuthenticator, authErr := loadDaemonAuthenticator(nextConfig)
			if authErr != nil {
				return daemonruntime.ReloadCandidate{}, fmt.Errorf("load replacement proxy users: %w", authErr)
			}
			if directoryErr := ensureServiceDirectory(nextConfig.Runtime.StateDir); directoryErr != nil {
				return daemonruntime.ReloadCandidate{}, fmt.Errorf("prepare replacement state directory: %w", directoryErr)
			}
			nextRuntime, buildErr := buildDaemonRuntime(
				prepareContext, nextConfig, nextAuthenticator, paths, nextLogger,
			)
			if buildErr != nil {
				return daemonruntime.ReloadCandidate{}, fmt.Errorf("prepare replacement runtime: %w", buildErr)
			}
			nextRuntime.SetReloadFunc(requestReload)
			for workerID := range drainingWorkers {
				if drainErr := nextRuntime.SetInitialWorkerDraining(workerID, true); drainErr != nil {
					// A removed worker needs no state transfer.
					continue
				}
			}
			for workerID, enabled := range enabledOverrides {
				if enableErr := nextRuntime.SetInitialWorkerEnabled(workerID, enabled); enableErr != nil {
					// A removed worker needs no state transfer.
					continue
				}
			}
			return daemonruntime.ReloadCandidate{
				Runtime: nextRuntime,
				Commit:  func() { activeRuntime = nextRuntime },
			}, nil
		},
	}
	if err := supervisor.Run(ctx, reloadRequests); err != nil {
		fmt.Fprintf(stderr, "run daemon: %v\n", err)
		return 1
	}
	return 0
}

type daemonPaths struct {
	ipBinary     string
	nftBinary    string
	daemonBinary string
}

func buildDaemonRuntime(
	ctx context.Context,
	cfg *config.Config,
	authenticator dispatcher.Authenticator,
	paths daemonPaths,
	logger *slog.Logger,
) (*daemonruntime.Runtime, error) {
	return (daemonruntime.Builder{
		Runner:        process.OSRunner{},
		Starter:       process.OSStarter{},
		Resolver:      net.DefaultResolver,
		ProfileReader: openvpn.OSProfileReader{},
		HostIPChecker: health.Checker{
			Client:         health.NewDirectHTTPClient(cfg.Health.Timeout.Duration),
			URL:            cfg.Health.IPCheckURL,
			ResponseFormat: cfg.Health.ExpectedResponseFormat,
			JSONField:      cfg.Health.JSONField,
		},
		IPBinary:     paths.ipBinary,
		NFTBinary:    paths.nftBinary,
		DaemonBinary: paths.daemonBinary,
		Logger:       logger,
	}).Build(ctx, cfg, authenticator)
}

func loadDaemonAuthenticator(cfg *config.Config) (dispatcher.Authenticator, error) {
	if cfg == nil || !cfg.Proxy.Authentication.Enabled {
		return nil, nil
	}
	store, err := auth.Load(cfg.Proxy.Authentication.UsersFile)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func absoluteExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable symlinks: %w", err)
	}
	if err := validateTrustedExecutable(path, uint32(os.Geteuid())); err != nil {
		return "", err
	}
	return path, nil
}

func validateTrustedExecutable(path string, daemonUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("executable must be a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("executable file is not executable")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("executable must not be writable by group or other users")
	}
	if !trustedFileOwner(info, daemonUID) {
		return errors.New("executable must be owned by root or the daemon user")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect executable directory: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("executable directory must not be writable by group or other users")
	}
	if !trustedFileOwner(parent, daemonUID) {
		return errors.New("executable directory must be owned by root or the daemon user")
	}
	return nil
}

func trustedFileOwner(info os.FileInfo, daemonUID uint32) bool {
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && (status.Uid == 0 || status.Uid == daemonUID)
}

func ensureServiceDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("directory path must be absolute")
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory must not be writable by group or other")
	}
	return nil
}

func runValidateHost(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "validate-host accepts no arguments")
		return 2
	}
	failed := false
	for _, binary := range []string{"ip", "nft", "openvpn"} {
		path, err := absoluteExecutable(binary)
		if err != nil {
			fmt.Fprintf(stderr, "missing required binary %s: %v\n", binary, err)
			failed = true
			continue
		}
		fmt.Fprintf(stdout, "%s: %s\n", binary, path)
	}
	prerequisites, err := namespace.CheckHostPrerequisites(namespace.OSFileReader{})
	if err != nil {
		fmt.Fprintf(stderr, "host networking prerequisite: %v\n", err)
		failed = true
	} else {
		fmt.Fprintln(stdout, "net.ipv4.ip_forward: enabled")
		for _, warning := range prerequisites.Warnings {
			fmt.Fprintf(stderr, "warning: %s\n", warning)
		}
	}
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		fmt.Fprintf(stderr, "network namespace support: %v\n", err)
		failed = true
	} else {
		fmt.Fprintln(stdout, "network namespaces: available")
	}
	if failed {
		return 1
	}
	fmt.Fprintln(stdout, "host prerequisites are available")
	return 0
}

func runWorkerProxy(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("worker-proxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", "", "namespace-side veth IP and TCP port")
	workerID := flags.String("worker-id", "", "validated worker identifier for logs")
	upstreamHTTPProxy := flags.String(
		"upstream-http-proxy",
		"",
		"optional in-tunnel HTTP CONNECT proxy address",
	)
	allowIPv6 := flags.Bool("allow-ipv6", false, "allow IPv6 CONNECT destinations")
	handshakeTimeout := flags.Duration("handshake-timeout", 10*time.Second, "SOCKS5 handshake deadline")
	connectTimeout := flags.Duration("connect-timeout", 15*time.Second, "destination connection deadline")
	idleTimeout := flags.Duration("idle-timeout", 5*time.Minute, "per-I/O idle deadline")
	logFormat := flags.String("log-format", "json", "json or text")
	logLevel := flags.String("log-level", "info", "debug, info, warn, or error")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "worker-proxy accepts no positional arguments")
		return 2
	}
	if err := validateWorkerListen(*listenAddress); err != nil {
		fmt.Fprintf(stderr, "worker-proxy listen address: %v\n", err)
		return 2
	}
	if !config.IsValidWorkerID(*workerID) {
		fmt.Fprintln(stderr, "worker-proxy --worker-id is invalid")
		return 2
	}
	if *upstreamHTTPProxy != "" {
		if err := validateWorkerUpstreamHTTPProxy(*upstreamHTTPProxy); err != nil {
			fmt.Fprintf(stderr, "worker-proxy upstream HTTP proxy: %v\n", err)
			return 2
		}
	}
	logger, err := logging.New(stderr, *logFormat, *logLevel)
	if err != nil {
		fmt.Fprintf(stderr, "configure logging: %v\n", err)
		return 2
	}
	var dialer socks5.Dialer = &net.Dialer{}
	if *upstreamHTTPProxy != "" {
		dialer = socks5.HTTPConnectDialer{
			ProxyAddress:     *upstreamHTTPProxy,
			NetDialer:        &net.Dialer{Timeout: *connectTimeout},
			HandshakeTimeout: *connectTimeout,
		}
	}
	server, err := socks5.NewServer(socks5.Config{
		HandshakeTimeout: *handshakeTimeout,
		ConnectTimeout:   *connectTimeout,
		IdleTimeout:      *idleTimeout,
		AllowIPv6:        *allowIPv6,
	}, dialer, logger)
	if err != nil {
		fmt.Fprintf(stderr, "configure worker proxy: %v\n", err)
		return 2
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", *listenAddress)
	if err != nil {
		fmt.Fprintf(stderr, "listen on namespace veth: %v\n", err)
		return 1
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("worker proxy listening",
		slog.String("worker", *workerID),
		slog.String("listen", *listenAddress),
	)
	if err := server.Serve(ctx, listener); err != nil {
		fmt.Fprintf(stderr, "serve worker proxy: %v\n", err)
		return 1
	}
	stats := server.Stats()
	logger.Info("worker proxy stopped",
		slog.String("worker", *workerID),
		slog.Uint64("connections_total", stats.ConnectionsTotal),
		slog.Uint64("bytes_from_clients", stats.BytesFromClients),
		slog.Uint64("bytes_to_clients", stats.BytesToClients),
	)
	return 0
}

func validateWorkerListen(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("host must be a namespace-side IP literal")
	}
	if ip.IsUnspecified() || ip.IsLoopback() {
		return errors.New("host must be the namespace-side veth address, not wildcard or loopback")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func validateWorkerUpstreamHTTPProxy(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("address must contain an IPv4 literal and TCP port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil ||
		!ip.Is4() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsMulticast() {
		return errors.New("host must be an explicit IPv4 unicast address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath, "path to the YAML configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "validate accepts no positional arguments")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration invalid: %v\n", err)
		return 1
	}
	if cfg.Proxy.Authentication.Enabled {
		if _, err := auth.Load(cfg.Proxy.Authentication.UsersFile); err != nil {
			fmt.Fprintf(stderr, "configuration invalid: validate users file: %v\n", err)
			return 1
		}
	}
	inspector := openvpn.Inspector{Reader: openvpn.OSProfileReader{}}
	for _, configuredWorker := range cfg.Workers {
		profilePath := filepath.Join(
			cfg.OpenVPN.ProfilesDir,
			configuredWorker.Config,
		)
		if _, err := inspector.Remotes(profilePath); err != nil {
			fmt.Fprintf(
				stderr,
				"configuration invalid: inspect worker %q profile: %v\n",
				configuredWorker.ID,
				err,
			)
			return 1
		}
	}

	logger, err := logging.New(stderr, cfg.Runtime.LogFormat, cfg.Runtime.LogLevel)
	if err != nil {
		fmt.Fprintf(stderr, "configure logging: %v\n", err)
		return 1
	}
	logger.Info("configuration validated",
		slog.String("config_path", *configPath),
		slog.Int("workers", len(cfg.Workers)),
	)
	fmt.Fprintln(stdout, "configuration is valid")
	return 0
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `usage: vpnpoold <command> [options]

commands:
  version        print build and runtime version metadata
  validate       validate configuration and referenced local files
  validate-host  validate required Linux tools and kernel settings
  daemon         run the host controller
  worker-proxy   run a namespace SOCKS5 worker
  status         query worker and dispatcher state
  reload         transactionally reload the configuration
  worker         enable, disable, drain, undrain, or restart a worker`)
}
