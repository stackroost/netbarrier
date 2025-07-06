package core

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed ebpf/ssh_block.o
var ebpfProgram []byte

func StartAgent() {
	fmt.Println("NetBarrier Agent Started")

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProgram))
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	objs := struct {
		CountSsh    *ebpf.Program `ebpf:"count_ssh"`
		SshAttempts *ebpf.Map     `ebpf:"ssh_attempts"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign eBPF objects: %v", err)
	}
	defer objs.CountSsh.Close()
	defer objs.SshAttempts.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.CountSsh, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Println("eBPF program attached to sys_enter_connect")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			time.Sleep(3 * time.Second)

			var (
				key   uint32
				value uint32
				iter  = objs.SshAttempts.Iterate()
			)

			fmt.Println("SSH Attempt Counts:")
			for iter.Next(&key, &value) {
				fmt.Printf("  PID %d -> Attempts %d\n", key, value)
			}

			if err := iter.Err(); err != nil {
				log.Printf("Iteration error: %v", err)
			}
		}
	}()

	<-sig
	fmt.Println("NetBarrier shutting down")
}
