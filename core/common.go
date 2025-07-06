package core

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func runMonitor(path, progName, mapName, hookType, hookName string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read eBPF object: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		log.Fatalf("Failed to load eBPF spec from %s: %v", path, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs[progName]
	if !ok {
		log.Fatalf("Program %s not found in %s", progName, path)
	}
	defer prog.Close()

	m, ok := coll.Maps[mapName]
	if !ok {
		log.Fatalf("Map %s not found in %s", mapName, path)
	}
	defer m.Close()

	var lnk link.Link

	switch hookType {
	case "tracepoint":
		lnk, err = link.Tracepoint("syscalls", hookName, prog, nil)
	case "kprobe":
		lnk, err = link.Kprobe(hookName, prog, nil)
	default:
		log.Fatalf("Unsupported hook type: %s", hookType)
	}
	if err != nil {
		log.Fatalf("Failed to attach %s: %v", hookName, err)
	}
	defer lnk.Close()

	fmt.Printf("eBPF loaded: %s → %s:%s\n", progName, hookType, hookName)

	for {
		time.Sleep(3 * time.Second)

		var (
			key   uint32
			value uint32
			iter  = m.Iterate()
		)

		fmt.Printf("[%s] PID -> Count:\n", mapName)
		for iter.Next(&key, &value) {
			fmt.Printf("  %d -> %d\n", key, value)
		}

		if err := iter.Err(); err != nil {
			log.Printf("[%s] iteration error: %v", mapName, err)
		}
	}
}
