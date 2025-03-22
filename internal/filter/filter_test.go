package filter

import "testing"

func TestMatchesRule(t *testing.T) {
	rule := FirewallRule{SrcIP: "192.168.1.1", DstPort: 80, Protocol: "tcp", Action: "drop"}
	if !matchesRule("192.168.1.1", "10.0.0.1", 12345, 80, "tcp", rule) {
		t.Errorf("Expected rule to match")
	}
}