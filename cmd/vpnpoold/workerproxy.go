package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/dobrevit/vpnpoold/internal/config"
	"github.com/dobrevit/vpnpoold/internal/logging"
	"github.com/dobrevit/vpnpoold/internal/proxy/workerproxy"
)

// newWorkerProxyCommand builds the namespace-side worker. The daemon re-execs
// this same binary through `ip netns exec` with a fixed argument vector and a
// minimal environment, so this command deliberately does NOT bind flags to the
// environment: ambient variables must not be able to move a worker's listener
// or widen its allowed client.
func newWorkerProxyCommand(stderr io.Writer) *cobra.Command {
	var (
		listenAddress     string
		allowedClient     string
		workerID          string
		upstreamHTTPProxy string
		allowIPv6         bool
		handshakeTimeout  time.Duration
		connectTimeout    time.Duration
		idleTimeout       time.Duration
		logFormat         string
		logLevel          string
	)
	command := &cobra.Command{
		Use:   "worker-proxy",
		Short: "Run a namespace SOCKS5 worker",
		Long: "Started by the daemon inside a worker network namespace. Running it\n" +
			"by hand is only useful for diagnostics; the listener must be the\n" +
			"namespace-side veth address.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := validateWorkerListen(listenAddress); err != nil {
				return usageErrorf("worker-proxy listen address: %v", err)
			}
			if !config.IsValidWorkerID(workerID) {
				return usageErrorf("worker-proxy --worker-id is invalid")
			}
			if upstreamHTTPProxy != "" {
				if err := validateWorkerUpstreamHTTPProxy(upstreamHTTPProxy); err != nil {
					return usageErrorf("worker-proxy upstream HTTP proxy: %v", err)
				}
			}
			logger, err := logging.New(stderr, logFormat, logLevel)
			if err != nil {
				return usageErrorf("configure logging: %v", err)
			}
			clientAddress, err := netip.ParseAddr(allowedClient)
			if err != nil {
				return usageErrorf("worker-proxy --allowed-client must be an IP literal")
			}
			server, err := workerproxy.New(workerproxy.Config{
				AllowedClientAddress: clientAddress,
				UpstreamHTTPProxy:    upstreamHTTPProxy,
				HandshakeTimeout:     handshakeTimeout,
				ConnectTimeout:       connectTimeout,
				IdleTimeout:          idleTimeout,
				AllowIPv6:            allowIPv6,
			}, logger)
			if err != nil {
				return usageErrorf("configure worker proxy: %v", err)
			}
			listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddress)
			if err != nil {
				return runtimeErrorf("listen on namespace veth: %v", err)
			}
			defer listener.Close()

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			logger.Info("worker proxy listening",
				slog.String("worker", workerID),
				slog.String("listen", listenAddress),
			)
			if err := server.Serve(ctx, listener); err != nil {
				return runtimeErrorf("serve worker proxy: %v", err)
			}
			logger.Info("worker proxy stopped", slog.String("worker", workerID))
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&listenAddress, "listen", "", "namespace-side veth IP and TCP port")
	flags.StringVar(&allowedClient, "allowed-client", "", "host-side veth IP allowed to use the proxy")
	flags.StringVar(&workerID, "worker-id", "", "validated worker identifier for logs")
	flags.StringVar(
		&upstreamHTTPProxy,
		"upstream-http-proxy",
		"",
		"optional in-tunnel HTTP CONNECT proxy address",
	)
	flags.BoolVar(&allowIPv6, "allow-ipv6", false, "allow IPv6 CONNECT destinations")
	flags.DurationVar(&handshakeTimeout, "handshake-timeout", 10*time.Second, "SOCKS5 handshake deadline")
	flags.DurationVar(&connectTimeout, "connect-timeout", 15*time.Second, "destination connection deadline")
	flags.DurationVar(&idleTimeout, "idle-timeout", 5*time.Minute, "per-I/O idle deadline")
	flags.StringVar(&logFormat, "log-format", "json", "json or text")
	flags.StringVar(&logLevel, "log-level", "info", "debug, info, warn, or error")
	return command
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
