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

func TestEarliestDivergenceWhenRouteLookupFails(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{
			Host: "10.10.0.2",
		},
		Route: &model.RouteReport{
			Table:           254,
			TableName:       "main",
			EgressInterface: "veth-client",
			PreferredSource: "10.10.0.1",
			Success:         true,
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusConnected,
		},
	}

	bad := &model.Snapshot{
		Target: good.Target,
		Route: &model.RouteReport{
			Table:     254,
			TableName: "main",
			Success:   false,
			Error:     "Network is unreachable",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusUnreachable,
		},
	}

	graph := BuildDAG(good, bad)

	if graph == nil || graph.EarliestDivergence == nil {
		t.Fatal("expected earliest divergence")
	}

	if graph.EarliestDivergence.Type != NodeRouteLookup {
		t.Fatalf(
			"expected route lookup divergence, got %s",
			graph.EarliestDivergence.Type,
		)
	}
}
