package cmd

import (
	"fmt"
	"netbarrier/core"

	"github.com/spf13/cobra"
)

var udpCmd = &cobra.Command{
	Use:   "udp-monitor",
	Short: "Monitor all UDP traffic using sys_sendto (kprobe)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running UDP Monitor")
		core.RunUDPMonitor()
	},
}

func init() {
	rootCmd.AddCommand(udpCmd)
}
