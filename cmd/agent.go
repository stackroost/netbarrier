package cmd

import (
	"fmt"
	"netbarrier/core"

	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Start the NetBarrier monitoring agent",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("NetBarrier agent started via command")
		core.StartAgent()
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
}
