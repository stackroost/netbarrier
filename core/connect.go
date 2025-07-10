package core

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type connectKey struct {
	PID  uint32
	IP   uint32
	Port uint16
	Pad  uint16 // for 4-byte alignment
}

func RunConnectMonitor() {
	const (
		objPath   = "bin/connect_count.o"
		progName  = "count_connect"
		mapName   = "connect_attempts"
		tpCat     = "syscalls"
		tpEvent   = "sys_enter_connect"
	)

	fmt.Printf("Starting monitor: %s → tracepoint:%s:%s\n", progName, tpCat, tpEvent)

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	if prog == nil {
		log.Fatalf("Program %s not found in object file", progName)
	}
	defer prog.Close()

	// Correct: Tracepoint, not Kprobe
	tp, err := link.Tracepoint(tpCat, tpEvent, prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	m := coll.Maps[mapName]
	if m == nil {
		log.Fatalf("Map %s not found", mapName)
	}
	defer m.Close()

	fmt.Println("eBPF tracepoint attached. Monitoring connections...")

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// Handle Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			var key connectKey
			var value uint32
			iter := m.Iterate()
			total := uint32(0)

			fmt.Println("[connect_attempts] PID@IP:PORT → Count")
			for iter.Next(&key, &value) {
				fmt.Printf("  %s (PID %d) → %s:%d → %d\n",
					resolveProcessName(int(key.PID)),
					key.PID,
					FormatIPv4(key.IP),
					key.Port,
					value,
				)
				total += value
			}

			if err := iter.Err(); err != nil {
				log.Printf("Map iteration error: %v", err)
			}
			fmt.Printf("[connect_attempts] Total Attempts: %d\n\n", total)

		case <-sig:
			fmt.Println("Connection monitor stopped.")
			return
		}
	}
}

func resolveProcessName(pid int) string {
	path := "/proc/" + strconv.Itoa(pid) + "/comm"
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return string(bytes.TrimSpace(data))
}
