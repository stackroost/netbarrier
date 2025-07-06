package cmd

import (
	"fmt"
	"netbarrier/core"

	"github.com/spf13/cobra"
)

var connCmd = &cobra.Command{
	Use:   "connections",
	Short: "Run TCP connect monitor using eBPF",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running Connection Monitor")
		core.RunConnectMonitor()
	},
}

func init() {
	rootCmd.AddCommand(connCmd)
}
