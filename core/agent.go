package core

import (
	"bytes"
	_"embed"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)


//go:embed ebpf/ssh_block.o
var ebpfProgram []byte

func StartAgent() {
	fmt.Println("NetBarrier Agent Started")

	// Load eBPF object spec
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProgram))
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Declare struct matching the program symbol
	objs := struct {
		CountSsh *ebpf.Program `ebpf:"count_ssh"`
	}{}

	// Load and assign
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign eBPF objects: %v", err)
	}
	defer objs.CountSsh.Close()

	// Attach to tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.CountSsh, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Println("eBPF program attached to sys_enter_connect")

	select {}
}
