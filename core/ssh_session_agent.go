package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type ShellEvent struct {
	Pid       uint32
	Uid       uint32
	EventType uint8
	_         [3]byte // padding
	Comm      [16]byte
}

func uidToUsername(uid uint32) string {
	uidStr := strconv.Itoa(int(uid))
	u, err := user.LookupId(uidStr)
	if err != nil {
		return "unknown"
	}
	return u.Username
}

func RunSSHSessionMonitor() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("bin/ssh_session_monitor.o")
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}

	objs := struct {
		TrackShellStart *ebpf.Program `ebpf:"track_shell_start"`
		TrackShellExit  *ebpf.Program `ebpf:"track_shell_exit"`
		EVENTS          *ebpf.Map     `ebpf:"EVENTS"`
		Sessions        *ebpf.Map     `ebpf:"sessions"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load & assign: %w", err)
	}
	defer objs.TrackShellStart.Close()
	defer objs.TrackShellExit.Close()
	defer objs.EVENTS.Close()
	defer objs.Sessions.Close()

	tpStart, err := link.Tracepoint("sched", "sched_process_exec", objs.TrackShellStart, nil)
	if err != nil {
		return fmt.Errorf("attach exec tracepoint: %w", err)
	}
	defer tpStart.Close()

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TrackShellExit, nil)
	if err != nil {
		return fmt.Errorf("attach exit tracepoint: %w", err)
	}
	defer tpExit.Close()

	rd, err := perf.NewReader(objs.EVENTS, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("open perf reader: %w", err)
	}
	defer rd.Close()

	log.Println("Monitoring shell sessions. Press Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	active := make(map[uint32]ShellEvent)

loop:
	for {
		select {
		case <-sig:
			log.Println("Exiting.")
			break loop

		default:
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					break loop
				}
				log.Printf("perf read error: %v", err)
				continue
			}

			var ev ShellEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("decode error: %v", err)
				continue
			}

			username := uidToUsername(ev.Uid)
			action := "START"
			if ev.EventType == 1 {
				action = "EXIT"
				delete(active, ev.Pid)
			} else {
				active[ev.Pid] = ev
			}

			fmt.Printf("[%s] %s PID=%d UID=%d USER=%s COMM=%s\n",
				time.Now().Format("15:04:05"),
				action,
				ev.Pid,
				ev.Uid,
				username,
				bytes.TrimRight(ev.Comm[:], "\x00"))

			fmt.Println("Active Shell Sessions:")
			for _, s := range active {
				userStr := uidToUsername(s.Uid)
				fmt.Printf("- PID %d, UID %d, USER=%s, COMM=%s\n",
					s.Pid, s.Uid, userStr, bytes.TrimRight(s.Comm[:], "\x00"))
			}
			fmt.Println()
		}
	}

	return nil
}
