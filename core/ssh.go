package core

import (
)

func RunSSHMonitor() {
	runMonitor("bin/ssh_monitor.o", "count_ssh", "ssh_attempts", "kprobe", "sys_connect")
}

