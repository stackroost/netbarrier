package core

import (
	"encoding/binary"
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
		progName = "trace_udp"
		mapName  = "udp_attempts"
		hookFunc = "sys_enter_sendto"
	)

	fmt.Printf("Starting monitor: %s → kprobe:%s\n", progName, hookFunc)

	// Load compiled eBPF object
	spec, err := ebpf.LoadCollectionSpec(bpfFile)
	if err != nil {
		log.Fatalf("Load spec failed: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Load collection failed: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	if prog == nil {
		log.Fatalf("Program '%s' not found", progName)
	}
	defer prog.Close()
	
	lk, err := link.Tracepoint("syscalls", "sys_enter_sendto", prog, nil)
	if err != nil {
		log.Fatalf("Attach failed: %v", err)
	}
	defer lk.Close()

	m := coll.Maps[mapName]
	if m == nil {
		log.Fatalf("Map '%s' not found", mapName)
	}
	defer m.Close()

	fmt.Println("eBPF attached. Watching UDP sends per PID and IP...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, unix.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			iter := m.Iterate()
			var (
				key   udpKey
				value uint32
				total uint32
			)

			fmt.Println("[udp_attempts] PID@IP -> Count")
			for iter.Next(&key, &value) {
				ipStr := formatIPv4(key.DstIP)
				fmt.Printf("  %d@%s -> %d\n", key.PID, ipStr, value)
				total += value
			}
			fmt.Printf("[udp_attempts] Total: %d\n\n", total)

			if err := iter.Err(); err != nil {
				log.Printf("Iter error: %v", err)
			}

		case <-sig:
			fmt.Println("Monitor stopped")
			return
		}
	}
}

func formatIPv4(n uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
