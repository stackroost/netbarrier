# NetBarrier

**NetBarrier** is an advanced, Go-based firewall for Linux, built to secure networks with robust packet filtering, logging, and a foundation for cutting-edge features like deep packet inspection (DPI), rate limiting, and eBPF integration. Leveraging Go’s concurrency and Linux’s networking stack, it’s designed for performance and extensibility.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Unlicensed-lightgrey.svg)]()

## Features
- **Packet Filtering**: Filter traffic by IP, port, protocol (TCP/UDP), and action (allow/drop).
- **Logging**: Real-time packet logging for monitoring and analysis.
- **Modular Architecture**: Easily extendable for advanced security features.
- **Linux Optimized**: Native support for Linux networking capabilities.

*Note*: This is a work-in-progress project. Packet dropping and advanced features are in development.

## Prerequisites
- **OS**: Linux (e.g., Ubuntu, Debian)
- **Go**: 1.21 or higher
- **Dependencies**:
  - `libpcap-dev` (for packet capture)
  - Go module: `github.com/google/gopacket`

## Installation

### Set Up Your Environment
Install the required tools on Linux:
```bash
sudo apt update
sudo apt install golang libpcap-dev make -y