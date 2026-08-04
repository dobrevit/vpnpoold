package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dobrevit/vpnpoold/internal/balance"
	"github.com/dobrevit/vpnpoold/internal/config"
	"github.com/dobrevit/vpnpoold/internal/control"
	"github.com/dobrevit/vpnpoold/internal/controller"
	"github.com/dobrevit/vpnpoold/internal/firewall"
	"github.com/dobrevit/vpnpoold/internal/health"
	metricsserver "github.com/dobrevit/vpnpoold/internal/metrics"
	"github.com/dobrevit/vpnpoold/internal/namespace"
	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/openvpn"
	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

const workerStopTimeout = 10 * time.Second

type Builder struct {
	Runner        process.Runner
	Starter       process.Starter
	Resolver      openvpn.Resolver
	ProfileReader openvpn.ProfileReader
	HostIPChecker PublicIPChecker
	IPBinary      string
	NFTBinary     string
	DaemonBinary  string
	Logger        *slog.Logger
}

type preparedWorker struct {
	index       int
	config      config.Worker
	sourcePath  string
	groups      []openvpn.ResolvedRemote
	endpoints   []openvpn.ResolvedEndpoint
	allocation  netutil.Allocation
	derivedPath string
}

func (b Builder) Build(
	ctx context.Context,
	cfg *config.Config,
	authenticator dispatcher.Authenticator,
) (_ *Runtime, err error) {
	if cfg == nil {
		return nil, errors.New("configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate daemon configuration: %w", err)
	}
	if b.Runner == nil || b.Starter == nil || b.Resolver == nil || b.ProfileReader == nil {
		return nil, errors.New("runner, starter, resolver, and profile reader are required")
	}
	if !filepath.IsAbs(b.IPBinary) || !filepath.IsAbs(b.NFTBinary) ||
		!filepath.IsAbs(b.DaemonBinary) {
		return nil, errors.New("ip, nft, and daemon binary paths must be absolute")
	}
	if cfg.Proxy.Authentication.Enabled && authenticator == nil {
		return nil, errors.New("proxy authentication is enabled but no authenticator was provided")
	}
	if !cfg.Proxy.Authentication.Enabled && authenticator != nil {
		return nil, errors.New("proxy authentication is disabled but an authenticator was provided")
	}
	hostPublicIPs := make([]netip.Addr, 0, len(cfg.Health.HostPublicIPs)+1)
	for _, value := range cfg.Health.HostPublicIPs {
		hostPublicIPs = append(hostPublicIPs, netip.MustParseAddr(value).Unmap())
	}
	if len(hostPublicIPs) == 0 {
		if b.HostIPChecker == nil {
			return nil, errors.New("host public-IP discovery is required when health.host_public_ips is empty")
		}
		checkContext, cancel := context.WithTimeout(ctx, cfg.Health.Timeout.Duration)
		hostPublicIP, checkErr := b.HostIPChecker.Check(checkContext)
		cancel()
		if checkErr != nil {
			return nil, fmt.Errorf("discover direct host public IP: %w", checkErr)
		}
		if validateErr := health.ValidatePublicIP(hostPublicIP); validateErr != nil {
			return nil, fmt.Errorf("validate discovered direct host public IP: %w", validateErr)
		}
		hostPublicIPs = append(hostPublicIPs, hostPublicIP.Unmap())
	}

	parent, err := netip.ParsePrefix(cfg.Network.Subnet)
	if err != nil {
		return nil, fmt.Errorf("parse worker subnet: %w", err)
	}
	allocator, err := netutil.NewAllocator(parent, cfg.Network.WorkerPrefixLength)
	if err != nil {
		return nil, fmt.Errorf("configure worker subnet allocator: %w", err)
	}

	inspector := openvpn.Inspector{Reader: b.ProfileReader}
	var prepared []preparedWorker
	for index, workerConfig := range cfg.Workers {
		allocation, allocateErr := allocator.Allocate(index, workerConfig.ID, cfg.Network.NamespacePrefix)
		if allocateErr != nil {
			return nil, fmt.Errorf("allocate worker %q network: %w", workerConfig.ID, allocateErr)
		}
		sourcePath := filepath.Join(cfg.OpenVPN.ProfilesDir, workerConfig.Config)
		remotes, inspectErr := inspector.Remotes(sourcePath)
		if inspectErr != nil {
			return nil, fmt.Errorf("inspect worker %q OpenVPN remotes: %w", workerConfig.ID, inspectErr)
		}
		resolved, resolveErr := openvpn.ResolveRemoteGroups(ctx, b.Resolver, remotes)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve worker %q OpenVPN remotes: %w", workerConfig.ID, resolveErr)
		}
		ipv4Groups, filterErr := ipv4RemoteGroups(resolved)
		if filterErr != nil {
			return nil, fmt.Errorf("worker %q: %w", workerConfig.ID, filterErr)
		}
		prepared = append(prepared, preparedWorker{
			index:      index,
			config:     workerConfig,
			sourcePath: sourcePath,
			groups:     ipv4Groups,
			endpoints:  flattenRemoteGroups(ipv4Groups),
			allocation: allocation,
		})
	}
	generationDirectory, err := makeGenerationDirectory(cfg.Runtime.RunDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = removeGenerationDirectory(cfg.Runtime.RunDir, generationDirectory)
		}
	}()
	for index := range prepared {
		prepared[index].derivedPath = filepath.Join(
			generationDirectory, prepared[index].config.ID+".ovpn",
		)
		if writeErr := openvpn.WriteResolvedProfileWithCredentialOptions(
			b.ProfileReader,
			prepared[index].sourcePath,
			prepared[index].derivedPath,
			openvpn.CredentialOptions{
				File:                         prepared[index].config.CredentialsFile,
				QueryViaManagement:           prepared[index].config.Management.UsernamePassword,
				QueryPrivateKeyViaManagement: prepared[index].config.Management.PrivateKeyPasswordFile != "",
			},
			prepared[index].groups,
		); writeErr != nil {
			return nil, fmt.Errorf("derive worker %q OpenVPN profile: %w", prepared[index].config.ID, writeErr)
		}
	}

	dnsServers := make([]netip.Addr, 0, len(cfg.Network.DNSServers))
	for _, value := range cfg.Network.DNSServers {
		dnsServers = append(dnsServers, netip.MustParseAddr(value).Unmap())
	}
	namespaceManager, err := namespace.NewManagerWithDNS(
		b.Runner,
		b.IPBinary,
		dnsServers,
	)
	if err != nil {
		return nil, fmt.Errorf("configure namespace manager: %w", err)
	}
	firewallManager, err := firewall.NewManager(b.Runner, b.IPBinary, b.NFTBinary)
	if err != nil {
		return nil, fmt.Errorf("configure firewall manager: %w", err)
	}
	pool := dispatcher.NewRegistry()
	logger := b.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	front, err := dispatcher.New(
		dispatcher.Config{
			Mode:               balance.Mode(cfg.Proxy.Balancing.Mode),
			SessionSeparator:   cfg.Proxy.Balancing.SessionSeparator,
			HandshakeTimeout:   cfg.Proxy.HandshakeTimeout.Duration,
			ConnectTimeout:     cfg.Proxy.ConnectTimeout.Duration,
			IdleTimeout:        cfg.Proxy.IdleTimeout.Duration,
			AllowIPv6:          !cfg.Network.DisableIPv6WhenUnavailable,
			MaxConnectAttempts: cfg.Proxy.MaxConnectAttempts,
		},
		pool,
		dispatcher.SOCKSConnector{
			NetDialer:        &net.Dialer{Timeout: cfg.Proxy.ConnectTimeout.Duration},
			HandshakeTimeout: cfg.Proxy.HandshakeTimeout.Duration,
		},
		authenticator,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("configure host dispatcher: %w", err)
	}

	healthRegistry := health.NewRegistry()
	if err := healthRegistry.SetHostWANIPs(hostPublicIPs); err != nil {
		return nil, fmt.Errorf("configure host public-IP leak policy: %w", err)
	}
	var controlled []controlledWorker
	var hostVeths []string
	var hostEndpoints []netip.Addr
	for _, item := range prepared {
		workerController, model, createErr := b.buildWorker(
			cfg,
			item,
			namespaceManager,
			firewallManager,
			pool,
			front,
			healthRegistry,
			hostPublicIPs,
			generationDirectory,
		)
		if createErr != nil {
			return nil, createErr
		}
		controlled = append(controlled, controlledWorker{
			id: item.config.ID, run: workerController.Run, model: model,
			setDraining: workerController.SetDraining,
			restart:     workerController.Restart,
			allocation:  item.allocation,
			lifecycle:   newControlledLifecycle(item.config.Enabled),
		})
		hostVeths = append(hostVeths, item.allocation.HostVeth)
		for _, endpoint := range item.endpoints {
			hostEndpoints = append(hostEndpoints, endpoint.Address)
		}
	}

	runtime := &Runtime{
		workers:      controlled,
		namespace:    namespaceManager,
		cleanupStale: cfg.Runtime.CleanupStaleResources,
		dispatcher:   front,
		pool:         pool,
		firewall:     firewallManager,
		hostRules: firewall.HostRules{
			WorkerSubnet:     parent.Masked(),
			UplinkInterface:  cfg.Network.HostUplinkInterface,
			WorkerVeths:      hostVeths,
			OpenVPNEndpoints: uniqueAddresses(hostEndpoints),
		},
		listenAddress:       cfg.Proxy.Listen,
		runDirectory:        cfg.Runtime.RunDir,
		generationDirectory: generationDirectory,
		hostIPChecker:       b.HostIPChecker,
		hostIPRegistry:      healthRegistry,
		staticHostIPs:       configuredHostIPs(cfg.Health.HostPublicIPs),
		hostIPInterval:      cfg.Health.Interval.Duration,
		hostIPTimeout:       cfg.Health.Timeout.Duration,
		workerRestartBackoff: worker.Backoff{
			Minimum: cfg.OpenVPN.RestartMinBackoff.Duration,
			Maximum: cfg.OpenVPN.RestartMaxBackoff.Duration,
			Jitter:  0.2,
			Random:  cryptoRandom{},
		},
		workerRestartResetAfter: cfg.OpenVPN.CrashLoopWindow.Duration,
		logger:                  logger,
		listen: func(ctx context.Context, network, address string) (net.Listener, error) {
			return (&net.ListenConfig{}).Listen(ctx, network, address)
		},
	}
	controlServer, err := control.NewServerWithStats(
		filepath.Join(cfg.Runtime.RunDir, "control.sock"),
		runtime.WorkerSnapshots,
		front.Stats,
		runtime,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("configure control socket: %w", err)
	}
	runtime.control = controlServer
	if cfg.Metrics.Enabled {
		metrics, metricsErr := metricsserver.NewServer(runtime.WorkerSnapshots, front.Stats)
		if metricsErr != nil {
			return nil, fmt.Errorf("configure Prometheus metrics: %w", metricsErr)
		}
		runtime.metrics = metrics
		runtime.metricsAddress = cfg.Metrics.Listen
	}
	return runtime, nil
}

func (b Builder) buildWorker(
	cfg *config.Config,
	item preparedWorker,
	namespaceManager *namespace.Manager,
	firewallManager *firewall.Manager,
	pool *dispatcher.Registry,
	front *dispatcher.Dispatcher,
	healthRegistry *health.Registry,
	hostPublicIPs []netip.Addr,
	generationDirectory string,
) (*controller.Worker, *worker.Model, error) {
	endpoints := make([]firewall.Endpoint, 0, len(item.endpoints))
	for _, endpoint := range item.endpoints {
		endpoints = append(endpoints, firewall.Endpoint{
			Address: endpoint.Address, Protocol: endpoint.Protocol, Port: endpoint.Port,
		})
	}
	rules := firewall.WorkerRules{
		Mode:             firewall.ModeActive,
		VethInterface:    item.allocation.NamespaceVeth,
		TunnelInterface:  cfg.Network.TunnelInterface,
		HostAddress:      item.allocation.HostAddress.Addr(),
		ProxyPort:        uint16(cfg.Proxy.WorkerPort),
		OpenVPNEndpoints: endpoints,
	}
	proxyAddress := net.JoinHostPort(
		item.allocation.NamespaceAddress.Addr().String(),
		fmt.Sprint(cfg.Proxy.WorkerPort),
	)
	candidate := balance.Candidate{
		ID: item.config.ID, Address: proxyAddress, Weight: item.config.Weight,
	}
	if err := pool.Upsert(candidate); err != nil {
		return nil, nil, fmt.Errorf("register worker %q candidate: %w", item.config.ID, err)
	}

	model, err := worker.NewModel(item.config.ID)
	if err != nil {
		return nil, nil, err
	}
	launcher := openvpn.Launcher{
		Starter: b.Starter, IPBinary: b.IPBinary, OpenVPNBinary: cfg.OpenVPN.Binary,
	}
	launchSpec := openvpn.LaunchSpec{
		Namespace:        item.allocation.Namespace,
		ProfilePath:      item.derivedPath,
		WorkingDirectory: cfg.OpenVPN.ProfilesDir,
		TunnelInterface:  cfg.Network.TunnelInterface,
		ManagementSocket: filepath.Join(generationDirectory, item.config.ID+".management.sock"),
		AuthRetryInteract: item.config.Management.UsernamePassword ||
			item.config.Management.ChallengeResponseCommand != "",
	}
	if len(launchSpec.ManagementSocket) > 100 {
		return nil, nil, fmt.Errorf("worker %q management socket path is too long", item.config.ID)
	}
	probe := openvpn.LinuxTunnelProbe{
		Runner: b.Runner, IPBinary: b.IPBinary,
		Namespace: item.allocation.Namespace, TunnelInterface: cfg.Network.TunnelInterface,
	}
	backoff := worker.Backoff{
		Minimum: cfg.OpenVPN.RestartMinBackoff.Duration,
		Maximum: cfg.OpenVPN.RestartMaxBackoff.Duration,
		Jitter:  0.2,
		Random:  cryptoRandom{},
	}
	supervisorConfig := openvpn.SupervisorConfig{
		StartupTimeout:  cfg.OpenVPN.ConnectTimeout.Duration,
		CheckInterval:   tunnelCheckInterval(cfg.Health.Interval.Duration),
		CheckTimeout:    cfg.Health.Timeout.Duration,
		StopTimeout:     workerStopTimeout,
		CrashLoopWindow: cfg.OpenVPN.CrashLoopWindow.Duration,
		CrashLoopLimit:  cfg.OpenVPN.CrashLoopLimit,
		Backoff:         backoff,
	}
	var credentialProvider openvpn.CredentialProvider
	if item.config.Management.UsernamePassword ||
		item.config.Management.PrivateKeyPasswordFile != "" ||
		item.config.Management.ChallengeResponseCommand != "" {
		credentialProvider = &openvpn.FileCredentialProvider{
			UsernamePasswordFile:   item.config.CredentialsFile,
			PrivateKeyPasswordFile: item.config.Management.PrivateKeyPasswordFile,
			ChallengeCommand:       item.config.Management.ChallengeResponseCommand,
			ChallengeTimeout:       item.config.Management.ChallengeTimeout.Duration,
			Runner:                 b.Runner,
		}
	}
	vpn, err := controller.NewSupervisorService(func() *openvpn.Supervisor {
		return &openvpn.Supervisor{
			Config: supervisorConfig,
			Start: func(ctx context.Context) (process.ManagedProcess, error) {
				return launcher.Start(ctx, launchSpec)
			},
			Probe: probe,
			Management: openvpn.ManagementClient{
				SocketPath: launchSpec.ManagementSocket,
				Provider:   credentialProvider,
			},
		}
	})
	if err != nil {
		return nil, nil, err
	}

	proxyLauncher := controller.WorkerProxyLauncher{
		Starter: b.Starter,
		Readiness: controller.TCPProxyReadiness{
			Timeout:  cfg.Proxy.HandshakeTimeout.Duration,
			Interval: 25 * time.Millisecond,
		},
		IPBinary: b.IPBinary, DaemonBinary: b.DaemonBinary,
		Namespace: item.allocation.Namespace, WorkerID: item.config.ID,
		ListenAddress:     proxyAddress,
		UpstreamHTTPProxy: item.config.UpstreamHTTPProxy,
		HandshakeTimeout:  cfg.Proxy.HandshakeTimeout.Duration,
		ConnectTimeout:    cfg.Proxy.ConnectTimeout.Duration,
		IdleTimeout:       cfg.Proxy.IdleTimeout.Duration,
		AllowIPv6:         !cfg.Network.DisableIPv6WhenUnavailable,
		LogFormat:         cfg.Runtime.LogFormat, LogLevel: cfg.Runtime.LogLevel,
	}
	checker := health.Checker{
		Client: health.NewWorkerHTTPClient(
			proxyAddress,
			cfg.Proxy.ConnectTimeout.Duration,
			cfg.Proxy.HandshakeTimeout.Duration,
		),
		URL:            cfg.Health.IPCheckURL,
		ResponseFormat: cfg.Health.ExpectedResponseFormat,
		JSONField:      cfg.Health.JSONField,
	}
	var expected netip.Addr
	if item.config.ExpectedPublicIP != "" {
		expected = netip.MustParseAddr(item.config.ExpectedPublicIP)
	}
	verifier := &controller.PublicIPVerifier{
		WorkerID: item.config.ID,
		Checker:  checker,
		Registry: healthRegistry,
		Policy: health.VerificationPolicy{
			ExpectedIP:        expected,
			EnforceUniqueness: cfg.Proxy.Balancing.UniquenessEnforced,
		},
	}
	controllerWorker, err := controller.NewWorker(
		controller.WorkerSpec{
			ID: item.config.ID, Allocation: item.allocation,
			FirewallRules: rules, Candidate: candidate,
			HealthInterval:   cfg.Health.Interval.Duration,
			HealthTimeout:    cfg.Health.Timeout.Duration,
			SuccessThreshold: cfg.Health.SuccessThreshold,
			StopTimeout:      workerStopTimeout, ProxyBackoff: backoff,
		},
		controller.Dependencies{
			Namespace: namespaceManager, Firewall: firewallManager, VPN: vpn,
			StartProxy: proxyLauncher.Start, Verifier: verifier,
			Publisher: pool, Sessions: front, Model: model,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("configure worker %q controller: %w", item.config.ID, err)
	}
	return controllerWorker, model, nil
}

func configuredHostIPs(values []string) []netip.Addr {
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParseAddr(value).Unmap())
	}
	return result
}

func ipv4Endpoints(endpoints []openvpn.ResolvedEndpoint) []openvpn.ResolvedEndpoint {
	var result []openvpn.ResolvedEndpoint
	seen := make(map[openvpn.ResolvedEndpoint]struct{})
	for _, endpoint := range endpoints {
		endpoint.Address = endpoint.Address.Unmap()
		if !endpoint.Address.Is4() {
			continue
		}
		if _, exists := seen[endpoint]; !exists {
			seen[endpoint] = struct{}{}
			result = append(result, endpoint)
		}
	}
	return result
}

func ipv4RemoteGroups(groups []openvpn.ResolvedRemote) ([]openvpn.ResolvedRemote, error) {
	result := make([]openvpn.ResolvedRemote, 0, len(groups))
	for index, group := range groups {
		ipv4 := ipv4Endpoints(group.Endpoints)
		if len(ipv4) == 0 {
			return nil, fmt.Errorf("OpenVPN remote %d has no resolved IPv4 endpoint", index)
		}
		result = append(result, openvpn.ResolvedRemote{
			Source: group.Source, Endpoints: ipv4,
		})
	}
	return result, nil
}

func flattenRemoteGroups(groups []openvpn.ResolvedRemote) []openvpn.ResolvedEndpoint {
	var result []openvpn.ResolvedEndpoint
	seen := make(map[openvpn.ResolvedEndpoint]struct{})
	for _, group := range groups {
		for _, endpoint := range group.Endpoints {
			if _, exists := seen[endpoint]; !exists {
				seen[endpoint] = struct{}{}
				result = append(result, endpoint)
			}
		}
	}
	return result
}

func uniqueAddresses(addresses []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addresses))
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if _, exists := seen[address]; !exists {
			seen[address] = struct{}{}
			result = append(result, address)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result
}

func tunnelCheckInterval(healthInterval time.Duration) time.Duration {
	const maximum = 2 * time.Second
	if healthInterval < maximum {
		return healthInterval
	}
	return maximum
}

func makeGenerationDirectory(runDirectory string) (string, error) {
	if !filepath.IsAbs(runDirectory) {
		return "", errors.New("runtime run directory must be absolute")
	}
	if err := os.MkdirAll(runDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create runtime directory: %w", err)
	}
	info, err := os.Stat(runDirectory)
	if err != nil {
		return "", fmt.Errorf("inspect runtime directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("runtime directory must be private and inaccessible to group or other users")
	}
	directory, err := os.MkdirTemp(runDirectory, "generation-")
	if err != nil {
		return "", fmt.Errorf("create runtime generation directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return "", fmt.Errorf("restrict runtime generation directory: %w", err)
	}
	return directory, nil
}

func removeGenerationDirectory(runDirectory, generationDirectory string) error {
	if !filepath.IsAbs(runDirectory) || !filepath.IsAbs(generationDirectory) ||
		filepath.Dir(generationDirectory) != filepath.Clean(runDirectory) ||
		filepath.Base(generationDirectory) == "." {
		return errors.New("refusing to remove an unexpected generation directory")
	}
	return os.RemoveAll(generationDirectory)
}
