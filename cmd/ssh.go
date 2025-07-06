package cmd

import (
	"fmt"
	"netbarrier/core"

	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:   "ssh-monitor",
	Short: "Run SSH connection monitor using eBPF",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running SSH Monitor")
		core.RunSSHMonitor()
	},
}

func init() {
	rootCmd.AddCommand(sshCmd)
}
