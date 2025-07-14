# NetBarrier

NetBarrier is a real-time Linux security and session monitoring tool built with Go and Rust-based eBPF programs. It tracks SSH and shell sessions, detects failed login attempts, monitors TCP/UDP connections, and provides user-level visibility into system activity.

## Features

- SSH and shell session tracking with real-time user and TTY resolution
- Failed SSH login detection for brute-force monitoring
- TCP and UDP connection monitoring using low-overhead eBPF probes
- Go-based agent for communication and reporting
- Written with performance and minimalism in mind, using pure eBPF and Go without external dependencies

## Requirements

- Linux kernel 5.10 or higher
- Go 1.20+
- Rust (for Rust-based eBPF, or Clang/LLVM for C-based eBPF)
- Root privileges to load eBPF programs

## Build

Clone the repository and build both the eBPF programs and the Go agent.

```bash
git clone https://github.com/stackroost/netbarrier
cd netbarrier
```
