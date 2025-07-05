package cmd

import (
	"fmt"
	"netbarrier/core"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "netbarrier",
	Short: "NetBarrier - eBPF-based real-time intrusion prevention system",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting NetBarrier agent (default)")
		core.StartAgent()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
