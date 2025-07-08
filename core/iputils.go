package core

import (
	"encoding/binary"
	"net"
)

func FormatIPv4(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b).String()
}
