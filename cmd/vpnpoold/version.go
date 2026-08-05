package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/dobrevit/vpnpoold/internal/buildinfo"
)

func newVersionCommand(stdout io.Writer) *cobra.Command {
	var format string
	command := &cobra.Command{
		Use:   "version",
		Short: "Print build and runtime version metadata",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := buildinfo.Current()
			switch format {
			case "text":
				modified := ""
				if info.Modified {
					modified = ", modified working tree"
				}
				fmt.Fprintf(
					stdout,
					"vpnpoold %s (commit %s, built %s, %s%s)\n",
					info.Version,
					info.Commit,
					info.BuildDate,
					info.GoVersion,
					modified,
				)
			case "json":
				if err := json.NewEncoder(stdout).Encode(info); err != nil {
					return runtimeErrorf("write version: %v", err)
				}
			default:
				return usageErrorf("version format must be text or json")
			}
			return nil
		},
	}
	command.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return withEnvironment(command)
}
