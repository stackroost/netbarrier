package core

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"os/signal"
"syscall"

)

func runMonitor(path, progName, mapName, hookType, hookFunc string) {
	fmt.Printf("Starting monitor: %s → %s:%s\n", progName, hookType, hookFunc)

	// Read eBPF object
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read eBPF object: %v", err)
	}

	// Load BPF
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Get program
	prog, ok := coll.Programs[progName]
	if !ok {
		log.Fatalf("Program %s not found", progName)
	}
	defer prog.Close()

	// Attach hook
	var lk link.Link
	if hookType == "kprobe" {
		lk, err = link.Kprobe(hookFunc, prog, nil)
	} else {
		lk, err = link.Tracepoint("syscalls", hookFunc, prog, nil)
	}
	if err != nil {
		log.Fatalf("Failed to attach: %v", err)
	}
	defer lk.Close()

	// Get map
	m, ok := coll.Maps[mapName]
	if !ok {
		log.Fatalf("Map %s not found", mapName)
	}
	defer m.Close()

	fmt.Println("eBPF attached. Watching...")

	// Print every 3 sec
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			var (
				key   uint32
				value uint32
				iter  = m.Iterate()
				total uint32 = 0
			)

			fmt.Printf("[%s] PID -> Attempts:\n", mapName)
			for iter.Next(&key, &value) {
				fmt.Printf("  %d -> %d\n", key, value)
				total += value
			}
			fmt.Printf("[%s] Total Attempts: %d\n\n", mapName, total)

			if err := iter.Err(); err != nil {
				log.Printf("Iteration error: %v", err)
			}

		case <-sig:
			fmt.Println("Monitor stopped")
			return
		}
	}
}