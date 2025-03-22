package logging

import (
	"fmt"
	"time"
)

type Logger struct{}

func NewLogger() (*Logger, error) {
	return &Logger{}, nil
}

func (l *Logger) Close() error {
	return nil
}

func (l *Logger) LogPacket(srcIP, dstIP string, srcPort, dstPort int, protocol, action string) {
	fmt.Printf("%s | %s:%d -> %s:%d [%s] - Action: %s\n",
		time.Now().Format(time.RFC3339), srcIP, srcPort, dstIP, dstPort, protocol, action)
}