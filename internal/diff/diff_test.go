package diff

import (
	"testing"
	"time"

	"netdiff/pkg/model"
)

func TestRoutingDivergenceScenario(t *testing.T) {
	tgt := model.Target{
		Raw:      "api.internal:443",
		Host:     "api.internal",
		Port:     443,
		Protocol: "tcp",
	}

	goodSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Metadata: model.SnapshotMetadata{
			NetDiffVersion: "0.1.0",
			CapturedAt:     time.Now(),
			Hostname:       "host-working",
		},
		Target: tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			ARecords: []string{"10.40.8.21"},
			Success:  true,
		},
		Route: &model.RouteReport{
			DestinationIP:   "10.40.8.21",
			Table:           200,
			TableName:       "200",
			EgressInterface: "tun0",
			PreferredSource: "10.8.0.14",
			Success:         true,
		},
		Interface: &model.InterfaceReport{
			Name:     "tun0",
			Role:     "tunnel",
			IsTunnel: true,
			MTU:      1420,
		},
		TCP: &model.TCPReport{
			Status:    model.TCPStatusConnected,
			LatencyMs: 25,
		},
	}

	badSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Metadata: model.SnapshotMetadata{
			NetDiffVersion: "0.1.0",
			CapturedAt:     time.Now(),
			Hostname:       "host-failing",
		},
		Target: tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			ARecords: []string{"10.40.8.21"},
			Success:  true,
		},
		Route: &model.RouteReport{
			DestinationIP:   "10.40.8.21",
			Table:           254,
			TableName:       "main",
			EgressInterface: "eth0",
			PreferredSource: "192.168.1.84",
			Success:         true,
		},
		Interface: &model.InterfaceReport{
			Name:     "eth0",
			Role:     "physical",
			IsTunnel: false,
			MTU:      1500,
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusTimeout,
		},
	}

	report := Compare(goodSnap, badSnap)
	if report == nil {
		t.Fatal("expected non-nil comparison report")
	}

	// Verify route/interface differences are marked HIGH relevance
	var foundHighRoute bool
	var foundHighInterface bool
	for _, d := range report.Differences {
		if d.Category == "Route" && d.Field == "egress_interface" && d.Relevance == model.RelevanceHigh {
			foundHighRoute = true
		}
		if d.Category == "Interface" && d.Field == "interface_role" && d.Relevance == model.RelevanceHigh {
			foundHighInterface = true
		}
	}

	if !foundHighRoute {
		t.Errorf("expected egress_interface diff to be ranked HIGH relevance")
	}
	if !foundHighInterface {
		t.Errorf("expected interface_role diff to be ranked HIGH relevance")
	}
}

func TestDNSDivergenceScenario(t *testing.T) {
	tgt := model.Target{
		Raw:  "api.internal:443",
		Host: "api.internal",
		Port: 443,
	}

	goodSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			ARecords: []string{"10.40.8.21"},
			Success:  true,
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusConnected,
		},
	}

	badSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			Success:  false,
			Error:    "no such host",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusFailed,
		},
	}

	report := Compare(goodSnap, badSnap)
	var foundDNSHigh bool
	for _, d := range report.Differences {
		if d.Category == "DNS" && d.Relevance == model.RelevanceHigh {
			foundDNSHigh = true
		}
	}

	if !foundDNSHigh {
		t.Errorf("expected DNS failure to be ranked HIGH relevance")
	}
}

func TestConnectionRefusedBehavior(t *testing.T) {
	tgt := model.Target{
		Raw:  "10.40.8.21:443",
		Host: "10.40.8.21",
		Port: 443,
		IsIP: true,
	}

	goodSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		Route: &model.RouteReport{
			Table:           200,
			EgressInterface: "tun0",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusConnected,
		},
	}

	badSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		Route: &model.RouteReport{
			Table:           254,
			EgressInterface: "tun0",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusRefused, // Connection refused confirms host was reached!
		},
	}

	report := Compare(goodSnap, badSnap)
	for _, d := range report.Differences {
		if d.Category == "Route" && d.Field == "routing_table" {
			if d.Relevance == model.RelevanceHigh {
				t.Errorf("expected routing diff to be downgraded from HIGH when connection was actively refused")
			}
		}
	}
}

func TestRouteLookupFailureDivergence(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{
			Raw:  "10.10.0.2:8080",
			Host: "10.10.0.2",
			Port: 8080,
		},
		Route: &model.RouteReport{
			DestinationIP:   "10.10.0.2",
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
			DestinationIP: "10.10.0.2",
			Success:       false,
			Error:         "Network is unreachable",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusUnreachable,
		},
	}

	report := Compare(good, bad)

	for _, d := range report.Differences {
		if d.Field == "route_lookup_success" {
			if d.Relevance != model.RelevanceHigh {
				t.Fatalf("expected HIGH relevance, got %v", d.Relevance)
			}
			return
		}
	}

	t.Fatal("expected route_lookup_success difference, but none was found")
}

func TestInterfaceStateDivergence(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		Route:  &model.RouteReport{EgressInterface: "veth-client", Success: true},
		Interface: &model.InterfaceReport{
			Name:      "veth-client",
			Flags:     []string{"UP", "BROADCAST", "MULTICAST"},
			OperState: "up",
		},
		TCP: &model.TCPReport{Status: model.TCPStatusConnected},
	}

	bad := &model.Snapshot{
		Target: good.Target,
		Route:  &model.RouteReport{EgressInterface: "veth-client", Success: true},
		Interface: &model.InterfaceReport{
			Name:      "veth-client",
			Flags:     []string{"BROADCAST", "MULTICAST"},
			OperState: "down",
		},
		TCP: &model.TCPReport{Status: model.TCPStatusFailed},
	}

	report := Compare(good, bad)
	var foundAdminDiff, foundOperDiff bool
	for _, d := range report.Differences {
		if d.Category == "Interface" && d.Field == "admin_state" && d.Relevance == model.RelevanceHigh {
			foundAdminDiff = true
			if d.WorkingValue != "UP" || d.FailingValue != "DOWN" {
				t.Errorf("unexpected admin values: %s vs %s", d.WorkingValue, d.FailingValue)
			}
		}
		if d.Category == "Interface" && d.Field == "oper_state" && d.Relevance == model.RelevanceHigh {
			foundOperDiff = true
		}
	}

	if !foundAdminDiff {
		t.Error("expected HIGH relevance admin_state diff")
	}
	if !foundOperDiff {
		t.Error("expected HIGH relevance oper_state diff")
	}
}

func TestFirewallDropRelevance(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		Route:  &model.RouteReport{EgressInterface: "eth0", Success: true},
		TCP:    &model.TCPReport{Status: model.TCPStatusConnected},
		Firewall: &model.FirewallReport{
			Backend: "none",
			Active:  false,
		},
	}

	bad := &model.Snapshot{
		Target: good.Target,
		Route:  &model.RouteReport{EgressInterface: "eth0", Success: true},
		TCP:    &model.TCPReport{Status: model.TCPStatusTimeout},
		Firewall: &model.FirewallReport{
			Backend: "iptables",
			Active:  true,
		},
	}

	report := Compare(good, bad)
	var foundFwHigh bool
	for _, d := range report.Differences {
		if d.Category == "Firewall" && d.Relevance == model.RelevanceHigh {
			foundFwHigh = true
		}
	}

	if !foundFwHigh {
		t.Error("expected Firewall diff to be promoted to HIGH when connection timed out and firewall is active")
	}
}

func TestGenerateSummary_NoTCPLeakage(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		Route: &model.RouteReport{
			EgressInterface: "vpn0",
			PolicyRule:      "from all to 10.10.0.0/16 lookup 200",
			Success:         true,
		},
		TCP: &model.TCPReport{Status: model.TCPStatusConnected},
	}

	bad := &model.Snapshot{
		Target: good.Target,
		Route: &model.RouteReport{
			EgressInterface: "eth0",
			Success:         true,
		},
		TCP: &model.TCPReport{Status: model.TCPStatusTimeout},
	}

	report := Compare(good, bad)
	// Summary should mention Policy Rule or Egress Interface rationale, NOT tcp diff rationale
	if report.Summary == "" {
		t.Fatal("expected non-empty summary")
	}
	if report.Differences[0].Category == "TCP" && report.Summary == report.Differences[0].Rationale {
		t.Errorf("summary improperly matched TCP symptom rationale: %s", report.Summary)
	}
}

func TestGenerateSummary_RefusedPort(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		Route:  &model.RouteReport{EgressInterface: "eth0", Success: true},
		TCP:    &model.TCPReport{Status: model.TCPStatusConnected},
	}

	bad := &model.Snapshot{
		Target: good.Target,
		Route:  &model.RouteReport{EgressInterface: "eth0", Success: true},
		TCP:    &model.TCPReport{Status: model.TCPStatusRefused},
	}

	report := Compare(good, bad)
	if report.Summary == "" {
		t.Fatal("expected summary for refused port")
	}
	if !containsSubstr(report.Summary, "refused") {
		t.Errorf("expected summary to mention refused connection, got: %s", report.Summary)
	}
}

func TestNeighborARPFailureDivergence(t *testing.T) {
	good := &model.Snapshot{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		Route:  &model.RouteReport{EgressInterface: "veth-client", Success: true},
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
		Route:  &model.RouteReport{EgressInterface: "veth-client", Success: true},
		Neighbor: &model.NeighborReport{
			IP:      "10.10.0.2",
			State:   "INCOMPLETE",
			Present: false,
		},
		TCP: &model.TCPReport{Status: model.TCPStatusTimeout},
	}

	report := Compare(good, bad)
	var foundNeighDiff bool
	for _, d := range report.Differences {
		if d.Category == "Neighbor" && d.Relevance == model.RelevanceHigh {
			foundNeighDiff = true
			if !containsSubstr(d.Rationale, "Layer 2") {
				t.Errorf("expected rationale to mention Layer 2, got: %s", d.Rationale)
			}
		}
	}

	if !foundNeighDiff {
		t.Fatal("expected HIGH relevance Neighbor diff when neighbor is INCOMPLETE and TCP timed out")
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && len(sub) > 0 && stringsContains(s, sub)))
}

func stringsContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
