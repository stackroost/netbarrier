# NetBarrier

**NetBarrier** is a real-time security monitoring and intrusion prevention system for Linux servers built using **eBPF** (extended Berkeley Packet Filter). It provides fine-grained visibility into SSH connections, TCP/UDP activity, and user sessions, empowering server administrators with deep observability and proactive defense.

---

## Features

- Monitor SSH connections and failed login attempts
- Track active SSH sessions and durations
- Real-time TCP and UDP traffic monitoring
- Lightweight Go-based agent with eBPF integration
- Suitable for production systems, CI pipelines, and cloud infrastructure

---

## Installation

Clone the repository and build:

```bash
git clone https://github.com/stackroost/netbarrier.git
cd netbarrier
go build -o netbarrier main.go
```

---

## Usage

Run the CLI with:

```bash
./netbarrier <command>
```

---

## Commands

### 🛡️ Agent

| Command             | Description                                        |
|---------------------|----------------------------------------------------|
| `netbarrier`        | Start the default NetBarrier agent                 |
| `netbarrier agent`  | Start the monitoring agent manually                |

---

### 📡 Network Monitoring

| Command                     | Description                                       |
|-----------------------------|---------------------------------------------------|
| `netbarrier connections`    | Run TCP connection monitor using eBPF             |
| `netbarrier udp-monitor`    | Monitor all UDP send traffic using `sys_sendto`   |

---

### 🔐 SSH Monitoring

| Command                           | Description                                             |
|-----------------------------------|---------------------------------------------------------|
| `netbarrier ssh-monitor`          | Track all SSH connection attempts                      |
| `netbarrier ssh-fail-monitor`     | Monitor failed SSH login attempts using eBPF           |
| `netbarrier ssh-session-monitor`  | Track active shell/SSH sessions and durations          |

---

## License

MIT License © [Stackroost](https://github.com/stackroost)
