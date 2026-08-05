package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/dobrevit/vpnpoold/internal/config"
	daemonruntime "github.com/dobrevit/vpnpoold/internal/daemon"
	"github.com/dobrevit/vpnpoold/internal/health"
	"github.com/dobrevit/vpnpoold/internal/logging"
	"github.com/dobrevit/vpnpoold/internal/namespace"
	"github.com/dobrevit/vpnpoold/internal/openvpn"
	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/proxy/auth"
	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
)

func newDaemonCommand(stderr io.Writer) *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use:   "daemon",
		Short: "Run the host controller",
		Long: "The daemon requires root privileges. It resolves every profile and\n" +
			"writes derived configurations before any privileged network mutation,\n" +
			"then activates workers one at a time behind a fail-closed kill switch.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDaemon(configPath, stderr)
		},
	}
	command.Flags().StringVar(
		&configPath, "config", defaultConfigPath, "path to the YAML configuration",
	)
	return withEnvironment(command)
}

func runDaemon(configPath string, stderr io.Writer) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return runtimeErrorf("load daemon configuration: %v", err)
	}
	logger, err := logging.New(stderr, cfg.Runtime.LogFormat, cfg.Runtime.LogLevel)
	if err != nil {
		return runtimeErrorf("configure logging: %v", err)
	}
	if os.Geteuid() != 0 {
		return runtimeErrorf("vpnpoold daemon requires root privileges")
	}
	instanceLock, err := daemonruntime.AcquireInstanceLock()
	if err != nil {
		return runtimeErrorf("acquire daemon instance lock: %v", err)
	}
	defer instanceLock.Close()

	authenticator, err := loadDaemonAuthenticator(cfg)
	if err != nil {
		return runtimeErrorf("load proxy users: %v", err)
	}
	if err := ensureServiceDirectory(cfg.Runtime.StateDir); err != nil {
		return runtimeErrorf("prepare state directory: %v", err)
	}
	prerequisites, err := namespace.CheckHostPrerequisites(namespace.OSFileReader{})
	if err != nil {
		return runtimeErrorf("host networking prerequisite: %v", err)
	}
	for _, warning := range prerequisites.Warnings {
		logger.Warn("host networking warning", slog.String("warning", warning))
	}

	ipBinary, err := absoluteExecutable("ip")
	if err != nil {
		return runtimeErrorf("find ip executable: %v", err)
	}
	nftBinary, err := absoluteExecutable("nft")
	if err != nil {
		return runtimeErrorf("find nft executable: %v", err)
	}
	daemonBinary, err := os.Executable()
	if err != nil {
		return runtimeErrorf("resolve daemon executable: %v", err)
	}
	daemonBinary, err = filepath.Abs(daemonBinary)
	if err != nil {
		return runtimeErrorf("resolve daemon executable: %v", err)
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
		return runtimeErrorf("prepare daemon runtime: %v", err)
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
			nextConfig, loadErr := config.Load(configPath)
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
		return runtimeErrorf("run daemon: %v", err)
	}
	return nil
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
