package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Match Rust layout (repr(C))
type SshSessionEvent struct {
	Pid         uint32
	Uid         uint32
	StartTimeNs uint64
	DurationNs  uint64
	Comm        [16]byte
}

func RunSSHSessionMonitor() error {
	spec, err := ebpf.LoadCollectionSpec("bin/ssh_session_monitor.o")
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}

	// Load with no pinning or options
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}
	defer coll.Close()

	// Get maps
	ringbufMap := coll.Maps["SSH_SESSION_RINGBUF"]
	if ringbufMap == nil {
		return fmt.Errorf("map SSH_SESSION_RINGBUF not found")
	}

	// Attach kprobe to track shell exec
	kp, err := link.Kprobe("do_execveat_common", coll.Programs["track_shell_start"], nil)
	if err != nil {
		return fmt.Errorf("attach kprobe: %w", err)
	}
	defer kp.Close()

	// Attach tracepoint to track process exit
	tp, err := link.Tracepoint("sched", "sched_process_exit", coll.Programs["sched_process_exit"], nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer tp.Close()

	log.Println("SSH Session Monitor started. Waiting for events...")

	// Set up ring buffer reader
	reader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer reader.Close()

	// Graceful shutdown on Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

loop:
	for {
		select {
		case <-sig:
			log.Println("Exiting SSH Session Monitor...")
			break loop
		default:
			record, err := reader.Read()
			if err != nil {
				if err != ringbuf.ErrClosed {
					log.Printf("read ringbuf: %v", err)
				}
				continue
			}

			var event SshSessionEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("decode event: %v", err)
				continue
			}

			start := time.Unix(0, int64(event.StartTimeNs))
			duration := time.Duration(event.DurationNs)
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

			fmt.Printf("[ssh_session] PID=%d UID=%d Comm=%s Started=%s Duration=%s\n",
				event.Pid, event.Uid, comm, start.Format(time.RFC3339), duration)
		}
	}

	return nil
}
