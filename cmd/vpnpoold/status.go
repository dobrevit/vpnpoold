package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dobrevit/vpnpoold/internal/config"
	"github.com/dobrevit/vpnpoold/internal/control"
)

func newStatusCommand(stdout io.Writer) *cobra.Command {
	var (
		configPath string
		timeout    time.Duration
		format     string
	)
	command := &cobra.Command{
		Use:   "status",
		Short: "Query worker and dispatcher state",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if timeout <= 0 {
				return usageErrorf("status timeout must be positive")
			}
			if format != "table" && format != "json" {
				return usageErrorf("status format must be table or json")
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return runtimeErrorf("load daemon configuration: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			status, err := control.Status(ctx, filepath.Join(cfg.Runtime.RunDir, "control.sock"))
			if err != nil {
				return runtimeErrorf("query daemon status: %v", err)
			}
			if format == "json" {
				encoder := json.NewEncoder(stdout)
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(status); err != nil {
					return runtimeErrorf("write daemon status: %v", err)
				}
				return nil
			}
			writeStatusTable(stdout, status)
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&configPath, "config", defaultConfigPath, "path to the YAML configuration")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "control request timeout")
	flags.StringVar(&format, "format", "table", "output format: table or json")
	return withEnvironment(command)
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
