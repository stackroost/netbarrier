package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"netbarrier/internal/filter"
	"netbarrier/internal/logging"
)

func Start(iface string, rules []filter.FirewallRule, logger *logging.Logger) error {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		go filter.ProcessPacket(packet, rules, logger)
	}
	return nil
}