package filter

import (
	"encoding/json"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"netbarrier/internal/logging"
)

type FirewallRule struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
}

func LoadRules(configPath string) ([]FirewallRule, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var rules []FirewallRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func ProcessPacket(packet gopacket.Packet, rules []FirewallRule, logger *logging.Logger) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	var srcPort, dstPort int
	var protocol string

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
		protocol = "tcp"
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
			protocol = "udp"
		} else {
			return
		}
	}

	for _, rule := range rules {
		if matchesRule(ip.SrcIP.String(), ip.DstIP.String(), srcPort, dstPort, protocol, rule) {
			logger.LogPacket(ip.SrcIP.String(), ip.DstIP.String(), srcPort, dstPort, protocol, rule.Action)
			if rule.Action == "drop" {
				return
			}
			break
		}
	}
}

func matchesRule(srcIP, dstIP string, srcPort, dstPort int, protocol string, rule FirewallRule) bool {
	return (rule.SrcIP == "0.0.0.0/0" || rule.SrcIP == srcIP) &&
		(rule.DstIP == "" || rule.DstIP == dstIP) &&
		(rule.SrcPort == 0 || rule.SrcPort == srcPort) &&
		(rule.DstPort == 0 || rule.DstPort == dstPort) &&
		(rule.Protocol == "" || rule.Protocol == protocol)
}