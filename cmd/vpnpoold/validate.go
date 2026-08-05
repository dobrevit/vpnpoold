package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/dobrevit/vpnpoold/internal/config"
	"github.com/dobrevit/vpnpoold/internal/logging"
	"github.com/dobrevit/vpnpoold/internal/namespace"
	"github.com/dobrevit/vpnpoold/internal/openvpn"
	"github.com/dobrevit/vpnpoold/internal/proxy/auth"
)

func newValidateCommand(stdout, stderr io.Writer) *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and referenced local files",
		Long: "Validation checks the OpenVPN executable and every referenced profile\n" +
			"without modifying profile content. Profiles and secret files must be\n" +
			"private, regular, non-symlink files in directories that group and other\n" +
			"users cannot modify.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return runtimeErrorf("configuration invalid: %v", err)
			}
			if cfg.Proxy.Authentication.Enabled {
				if _, err := auth.Load(cfg.Proxy.Authentication.UsersFile); err != nil {
					return runtimeErrorf("configuration invalid: validate users file: %v", err)
				}
			}
			inspector := openvpn.Inspector{Reader: openvpn.OSProfileReader{}}
			for _, configuredWorker := range cfg.Workers {
				profilePath := filepath.Join(cfg.OpenVPN.ProfilesDir, configuredWorker.Config)
				if _, err := inspector.Remotes(profilePath); err != nil {
					return runtimeErrorf(
						"configuration invalid: inspect worker %q profile: %v",
						configuredWorker.ID,
						err,
					)
				}
			}
			logger, err := logging.New(stderr, cfg.Runtime.LogFormat, cfg.Runtime.LogLevel)
			if err != nil {
				return runtimeErrorf("configure logging: %v", err)
			}
			logger.Info("configuration validated",
				slog.String("config_path", configPath),
				slog.Int("workers", len(cfg.Workers)),
			)
			fmt.Fprintln(stdout, "configuration is valid")
			return nil
		},
	}
	command.Flags().StringVar(
		&configPath, "config", defaultConfigPath, "path to the YAML configuration",
	)
	return withEnvironment(command)
}

func newValidateHostCommand(stdout, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "validate-host",
		Short: "Validate required Linux tools and kernel settings",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
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
				// The individual failures are already on stderr.
				return &exitError{code: 1, err: errHostPrerequisites}
			}
			fmt.Fprintln(stdout, "host prerequisites are available")
			return nil
		},
	}
	return command
}
