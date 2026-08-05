package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dobrevit/vpnpoold/internal/config"
	"github.com/dobrevit/vpnpoold/internal/control"
)

func newReloadCommand(stdout io.Writer) *cobra.Command {
	var (
		configPath string
		timeout    time.Duration
	)
	command := &cobra.Command{
		Use:   "reload",
		Short: "Transactionally reload the configuration",
		Long: "Reload rebuilds a complete candidate runtime while the current\n" +
			"generation stays live. If activation fails the retained generation is\n" +
			"restarted, so an invalid configuration never interrupts traffic.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if timeout <= 0 {
				return usageErrorf("reload timeout must be positive")
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return runtimeErrorf("load daemon configuration: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := control.Reload(ctx, filepath.Join(cfg.Runtime.RunDir, "control.sock")); err != nil {
				return runtimeErrorf("request daemon reload: %v", err)
			}
			fmt.Fprintln(stdout, "configuration reload accepted")
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&configPath, "config", defaultConfigPath, "path to the YAML configuration")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "control request timeout")
	return withEnvironment(command)
}
