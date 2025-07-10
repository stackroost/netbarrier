package cmd

import (
	"fmt"
	"netbarrier/core"

	"github.com/spf13/cobra"
)

var sshFailCmd = &cobra.Command{
	Use:   "ssh-fail-monitor",
	Short: "Run SSH failed login monitor using eBPF",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running SSH Fail Monitor")
		core.RunSSHFailMonitor()
	},
}

func init() {
	rootCmd.AddCommand(sshFailCmd)
}
