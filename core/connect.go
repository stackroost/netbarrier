package core

import (
)

func RunConnectMonitor() {
	runMonitor("bin/connect_count.o", "count_connect", "connect_attempts", "tracepoint", "sys_enter_connect")
}
