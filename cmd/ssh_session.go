package cmd

import (
	"fmt"
	"netbarrier/core"

	"github.com/spf13/cobra"
)

var sshSessionCmd = &cobra.Command{
	Use:   "ssh-session-monitor",
	Short: "Monitor SSH sessions (start and duration) using eBPF",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running SSH Session Monitor")
		if err := core.RunSSHSessionMonitor(); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(sshSessionCmd)
}
