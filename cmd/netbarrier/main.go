package main

import (
	"flag"
	"fmt"
	"log"
	"netbarrier/internal/capture"
	"netbarrier/internal/filter"
	"netbarrier/internal/logging"
)

func main() {
	iface := flag.String("interface", "eth0", "Network interface to monitor")
	configPath := flag.String("config", "../../config/rules.json", "Path to rules config file")
	flag.Parse()

	logger, err := logging.NewLogger()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Close()

	rules, err := filter.LoadRules(*configPath)
	if err != nil {
		log.Fatalf("Failed to load rules: %v", err)
	}

	fmt.Printf("NetBarrier starting on interface %s...\n", *iface)
	err = capture.Start(*iface, rules, logger)
	if err != nil {
		log.Fatalf("Capture failed: %v", err)
	}
}