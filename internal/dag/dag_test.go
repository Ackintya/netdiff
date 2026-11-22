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

func TestDAGEarliestDivergenceNeighbor(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Host: "10.10.0.2", Port: 8080, IsIP: true},
		Route: &model.RouteReport{
			DestinationIP:   "10.10.0.2",
			Table:           254,
			TableName:       "main",
			EgressInterface: "veth-client",
			Success:         true,
		},
		Neighbor: &model.NeighborReport{
			IP:      "10.10.0.2",
			MAC:     "52:54:00:12:34:56",
			State:   "REACHABLE",
			Present: true,
		},
		TCP: &model.TCPReport{Status: model.TCPStatusConnected},
	}

	bad := &model.Snapshot{
		Target: good.Target,
		Route: &model.RouteReport{
			DestinationIP:   "10.10.0.2",
			Table:           254,
			TableName:       "main",
			EgressInterface: "veth-client",
			Success:         true,
		},
		Neighbor: &model.NeighborReport{
			IP:      "10.10.0.2",
			State:   "INCOMPLETE",
			Present: false,
		},
		TCP: &model.TCPReport{Status: model.TCPStatusTimeout},
	}

	d := BuildDAG(good, bad)
	if d == nil || d.EarliestDivergence == nil {
		t.Fatal("expected earliest divergence")
	}

	if d.EarliestDivergence.Type != NodeNeighbor {
		t.Fatalf("expected earliest divergence to be %s, got %s", NodeNeighbor, d.EarliestDivergence.Type)
	}
}

func TestDAGEarliestDivergenceTLS(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Host: "api.corp", Port: 443, Protocol: "https"},
		Route: &model.RouteReport{
			DestinationIP:   "10.10.0.2",
			Table:           254,
			TableName:       "main",
			EgressInterface: "eth0",
			Success:         true,
		},
		TCP: &model.TCPReport{Status: model.TCPStatusConnected},
		TLS: &model.TLSReport{
			HandshakeSuccess: true,
			Version:          "TLS 1.3",
			CipherSuite:      "TLS_AES_128_GCM_SHA256",
			Subject:          "api.corp",
		},
	}

	bad := &model.Snapshot{
		Target: good.Target,
		Route: &model.RouteReport{
			DestinationIP:   "10.10.0.2",
			Table:           254,
			TableName:       "main",
			EgressInterface: "eth0",
			Success:         true,
		},
		TCP: &model.TCPReport{Status: model.TCPStatusConnected},
		TLS: &model.TLSReport{
			HandshakeSuccess: false,
			Error:            "x509: certificate signed by unknown authority",
			ErrorCategory:    "untrusted_root",
		},
	}

	d := BuildDAG(good, bad)
	if d == nil || d.EarliestDivergence == nil {
		t.Fatal("expected earliest divergence")
	}

	if d.EarliestDivergence.Type != NodeTLS {
		t.Fatalf("expected earliest divergence to be %s, got %s", NodeTLS, d.EarliestDivergence.Type)
	}
}
