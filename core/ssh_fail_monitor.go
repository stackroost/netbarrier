package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type sshFailEvent struct {
	Pid         uint32
	Uid         uint32
	TimestampNs uint64
	Comm        [16]byte
	FailReason  uint8
	_           [7]byte // padding
}

var attemptCount = struct {
	sync.Mutex
	data map[uint32]int // map[PID] -> count
}{
	data: make(map[uint32]int),
}

func RunSSHFailMonitor() {
	spec, err := ebpf.LoadCollectionSpec("bin/ssh_fail_monitor.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	objs := struct {
		SshFailMonitor *ebpf.Program `ebpf:"ssh_fail_monitor"`
		SshFailRingbuf *ebpf.Map     `ebpf:"SSH_FAIL_RINGBUF"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer func() {
		_ = objs.SshFailMonitor.Close()
		_ = objs.SshFailRingbuf.Close()
	}()

	libpamPath := findLibPam()
	if libpamPath == "" {
		log.Fatal("libpam.so not found")
	}
	log.Printf("Using libpam at: %s", libpamPath)

	up, err := link.OpenExecutable(libpamPath)
	if err != nil {
		log.Fatalf("OpenExecutable failed: %v", err)
	}

	attached, err := up.Uretprobe("pam_authenticate", objs.SshFailMonitor, nil)
	if err != nil {
		log.Fatalf("Failed to attach uretprobe: %v", err)
	}
	defer attached.Close()

	log.Println("Successfully attached uretprobe to pam_authenticate")

	rd, err := ringbuf.NewReader(objs.SshFailRingbuf)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Println("SSH fail monitor started. Press Ctrl+C to stop.")
	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sig, os.Interrupt)

	go func() {
		for {
			select {
			case <-done:
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if !strings.Contains(err.Error(), "closed") {
						log.Printf("ringbuf read failed: %v", err)
					}
					continue
				}

				var event sshFailEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					log.Printf("binary read failed: %v", err)
					continue
				}

				username := lookupUsername(event.Uid)
				processName := strings.TrimRight(string(event.Comm[:]), "\x00")
				reason := "unknown"
				switch event.FailReason {
				case 1:
					reason = "invalid password"
				case 2:
					reason = "invalid user"
				}

				attemptCount.Lock()
				attemptCount.data[event.Pid]++
				count := attemptCount.data[event.Pid]
				attemptCount.Unlock()

				fmt.Printf(
					"%s (PID %d, UID %d, user: %s) → Failed SSH login: %s [Attempt #%d]\n",
					processName, event.Pid, event.Uid, username, reason, count,
				)
			}
		}
	}()

	<-sig
	fmt.Println("\nExiting SSH monitor.")
	close(done)
}

func lookupUsername(uid uint32) string {
	userObj, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "unknown"
	}
	return userObj.Username
}

func findLibPam() string {
	possiblePaths := []string{
		"/lib/x86_64-linux-gnu/libpam.so.0",
		"/lib64/libpam.so.0",
		"/usr/lib/libpam.so.0",
		"/usr/lib64/libpam.so.0",
		"/lib/libpam.so.0",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
