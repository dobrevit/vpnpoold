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

type workerAction struct {
	name  string
	short string
}

var workerActions = []workerAction{
	{"enable", "Permit a fresh, fully verified worker startup"},
	{"disable", "Fail-closed teardown; persists as an operator override across reloads"},
	{"drain", "Stop new assignments without terminating established sessions"},
	{"undrain", "Resume new assignments"},
	{"restart", "Withdraw the worker, close its sessions, and request a new VPN generation"},
}

func newWorkerCommand(stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "worker",
		Short: "Enable, disable, drain, undrain, or restart a worker",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErrorf("worker requires enable, disable, drain, undrain, or restart")
		},
	}
	for _, action := range workerActions {
		command.AddCommand(newWorkerActionCommand(action, stdout))
	}
	return command
}

func newWorkerActionCommand(action workerAction, stdout io.Writer) *cobra.Command {
	var (
		configPath string
		timeout    time.Duration
	)
	command := &cobra.Command{
		Use:               action.name + " WORKER_ID",
		Short:             action.short,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeWorkerIDs(&configPath, &timeout),
		RunE: func(_ *cobra.Command, args []string) error {
			workerID := args[0]
			if !config.IsValidWorkerID(workerID) {
				return usageErrorf("worker action requires exactly one valid worker ID")
			}
			if timeout <= 0 {
				return usageErrorf("worker action timeout must be positive")
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return runtimeErrorf("load daemon configuration: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := control.WorkerAction(
				ctx,
				filepath.Join(cfg.Runtime.RunDir, "control.sock"),
				action.name,
				workerID,
			); err != nil {
				return runtimeErrorf("%s worker %q: %v", action.name, workerID, err)
			}
			fmt.Fprintf(stdout, "worker %s %s accepted\n", workerID, action.name)
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&configPath, "config", defaultConfigPath, "path to the YAML configuration")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "control request timeout")
	return withEnvironment(command)
}

// completeWorkerIDs offers the configured worker IDs for shell completion. It
// reads the configuration rather than the control socket so completion also
// works while the daemon is stopped, and stays silent on any error.
func completeWorkerIDs(
	configPath *string,
	_ *time.Duration,
) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		identifiers := make([]string, 0, len(cfg.Workers))
		for _, configured := range cfg.Workers {
			identifiers = append(identifiers, configured.ID)
		}
		return identifiers, cobra.ShellCompDirectiveNoFileComp
	}
}
