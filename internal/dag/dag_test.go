package dag

import (
	"testing"

	"netdiff/pkg/model"
)

func TestDAGEarliestDivergencePolicyRule(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Host: "api.corp", Port: 443},
		DNS:    &model.DNSReport{Success: true, ARecords: []string{"10.40.8.21"}},
		Route: &model.RouteReport{
			DestinationIP:   "10.40.8.21",
			PolicyRule:      "from all to 10.40.0.0/16 lookup 200",
			Table:           200,
			TableName:       "table 200",
			EgressInterface: "tun0",
		},
		Interface: &model.InterfaceReport{Role: "tunnel"},
		TCP:       &model.TCPReport{Status: model.TCPStatusConnected},
	}

	bad := &model.Snapshot{
		Target: model.Target{Host: "api.corp", Port: 443},
		DNS:    &model.DNSReport{Success: true, ARecords: []string{"10.40.8.21"}},
		Route: &model.RouteReport{
			DestinationIP:   "10.40.8.21",
			PolicyRule:      "default main",
			Table:           254,
			TableName:       "main",
			EgressInterface: "eth0",
		},
		Interface: &model.InterfaceReport{Role: "physical"},
		TCP:       &model.TCPReport{Status: model.TCPStatusTimeout},
	}

	d := BuildDAG(good, bad)
	if d.EarliestDivergence == nil {
		t.Fatal("expected earliest divergence node, got nil")
	}
	if d.EarliestDivergence.Type != NodePolicyRule {
		t.Errorf("expected earliest divergence to be %s, got %s", NodePolicyRule, d.EarliestDivergence.Type)
	}
}

func TestDAGEarliestDivergenceDNS(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Host: "api.corp", Port: 443},
		DNS:    &model.DNSReport{Success: true, ARecords: []string{"10.40.8.21"}},
		TCP:    &model.TCPReport{Status: model.TCPStatusConnected},
	}

	bad := &model.Snapshot{
		Target: model.Target{Host: "api.corp", Port: 443},
		DNS:    &model.DNSReport{Success: false},
		TCP:    &model.TCPReport{Status: model.TCPStatusTimeout},
	}

	d := BuildDAG(good, bad)
	if d.EarliestDivergence == nil {
		t.Fatal("expected earliest divergence node, got nil")
	}
	if d.EarliestDivergence.Type != NodeDNS {
		t.Errorf("expected earliest divergence to be %s, got %s", NodeDNS, d.EarliestDivergence.Type)
	}
}
