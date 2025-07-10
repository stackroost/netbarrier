package core

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Must match the Rust struct `SshKey { pid: u32, ip: u32 }`
type sshKey struct {
	PID uint32
	IP  uint32
}

func RunSSHMonitor() {
	const (
		bpfFile  = "bin/ssh_monitor.o"
		progName = "trace_ssh"
		mapName  = "ssh_attempts"
	)

	fmt.Printf("Starting SSH monitor: %s on tracepoint sys_enter_connect\n", progName)

	spec, err := ebpf.LoadCollectionSpec(bpfFile)
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs[progName]
	if !ok {
		log.Fatalf("Program %s not found in .o file", progName)
	}
	defer prog.Close()

	kprobe, err := link.Kprobe("tcp_v4_connect", prog, nil)
if err != nil {
	log.Fatalf("Failed to attach kprobe: %v", err)
}
defer kprobe.Close()


	m, ok := coll.Maps[mapName]
	if !ok {
		log.Fatalf("Map %s not found", mapName)
	}
	defer m.Close()

	fmt.Println("eBPF program attached. Watching SSH connections every 3 seconds...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			iter := m.Iterate()
			var key sshKey
			var value uint32
			total := uint32(0)

			fmt.Println("[ssh_attempts] PID@IP -> Count")
			for iter.Next(&key, &value) {
				ipStr := FormatIPv4(key.IP)
				fmt.Printf("  %d@%s -> %d\n", key.PID, ipStr, value)
				total += value
			}

			if err := iter.Err(); err != nil {
				log.Printf("Map iteration error: %v", err)
			}
			fmt.Printf("[ssh_attempts] Total Attempts: %d\n\n", total)

		case <-sig:
			fmt.Println("Stopping SSH monitor...")
			return
		}
	}
}
