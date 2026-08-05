package main

import (
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// envPrefix maps a flag name onto its environment variable: --log-level is
// VPNPOOLD_LOG_LEVEL. An explicit flag always wins over the environment.
const envPrefix = "VPNPOOLD_"

func newRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "vpnpoold",
		Short: "Isolated OpenVPN egress pool with a single SOCKS5 dispatcher",
		Long: "vpnpoold runs each OpenVPN client profile in its own Linux network\n" +
			"namespace and exposes the healthy exits through one host-side SOCKS5\n" +
			"dispatcher.\n\n" +
			"Every flag can also be supplied through the environment, prefixed with\n" +
			envPrefix + " and upper-cased: --config becomes " + envPrefix + "CONFIG.\n" +
			"An explicitly supplied flag always overrides the environment.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// The previous parser exited 2 on an unknown command and printed usage.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErrorf("%s", strings.TrimSpace(cmd.UsageString()))
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.CompletionOptions.DisableDescriptions = false

	root.AddCommand(
		newVersionCommand(stdout),
		newValidateCommand(stdout, stderr),
		newValidateHostCommand(stdout, stderr),
		newDaemonCommand(stderr),
		newWorkerProxyCommand(stderr),
		newStatusCommand(stdout),
		newReloadCommand(stdout),
		newWorkerCommand(stdout),
	)
	return root
}

// bindEnvironment fills in any flag the caller did not set explicitly from the
// environment. It is deliberately not applied to worker-proxy: that command is
// exec'd by the daemon with a fixed argument vector and a minimal environment,
// and ambient variables must never be able to alter a namespace worker's
// listen address or allowed client.
func bindEnvironment(cmd *cobra.Command) error {
	var bindErr error
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if bindErr != nil || flag.Changed {
			return
		}
		value, ok := os.LookupEnv(environmentName(flag.Name))
		if !ok {
			return
		}
		if err := cmd.Flags().Set(flag.Name, value); err != nil {
			bindErr = usageErrorf(
				"invalid %s for --%s: %v", environmentName(flag.Name), flag.Name, err,
			)
		}
	})
	return bindErr
}

func environmentName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// withEnvironment wires bindEnvironment into a command's PreRunE.
func withEnvironment(cmd *cobra.Command) *cobra.Command {
	cmd.PreRunE = func(command *cobra.Command, _ []string) error {
		return bindEnvironment(command)
	}
	return cmd
}
