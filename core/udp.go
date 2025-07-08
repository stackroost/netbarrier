package core

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type udpKey struct {
	PID   uint32
	DstIP uint32
}

func RunUDPMonitor() {
	const (
		bpfFile  = "bin/udp_monitor.o"
		mapName  = "udp_attempts"
		progName = "udp_monitor"
	)

	fmt.Println("Starting UDP Monitor...")

	spec, err := ebpf.LoadCollectionSpec(bpfFile)
	if err != nil {
		log.Fatalf("Failed to load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load eBPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	if prog == nil {
		log.Fatalf("Program '%s' not found in collection", progName)
	}
	defer prog.Close()

	// Attach to __x64_sys_sendmsg (or change to sendto if needed)
	kp, err := link.Kprobe("__x64_sys_sendmsg", prog, nil)
	if err != nil {
		log.Fatalf("Attach to __x64_sys_sendmsg failed: %v", err)
	}
	defer kp.Close()

	m := coll.Maps[mapName]
	if m == nil {
		log.Fatalf("Map '%s' not found", mapName)
	}
	defer m.Close()

	fmt.Println("eBPF probe attached. Watching UDP sends per PID and IP...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, unix.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var (
				key   udpKey
				value uint32
				total uint32
			)

			fmt.Println("[udp_attempts] PID@IP -> Count")
			iter := m.Iterate()
			for iter.Next(&key, &value) {
				ipStr := FormatIPv4(key.DstIP)
				fmt.Printf("  %d@%s -> %d\n", key.PID, ipStr, value)
				total += value
			}
			fmt.Printf("[udp_attempts] Total: %d\n\n", total)

			if err := iter.Err(); err != nil {
				log.Printf("Map iteration error: %v", err)
			}
		case <-sig:
			fmt.Println("Monitor stopped.")
			return
		}
	}
}
