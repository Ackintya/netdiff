package ai

import (
	"context"
	"strings"
	"testing"

	"netdiff/pkg/model"
)

func TestExplain_PolicyDivergence(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		WorkingHost: "host-good",
		FailingHost: "host-bad",
		Target: model.Target{
			Raw:  "10.40.8.21:8080",
			Host: "10.40.8.21",
			Port: 8080,
		},
		EarliestDivergence: "Policy Rule: from all to 10.40.0.0/16 lookup 200 != default main",
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				EgressInterface: "tun0",
				Table:           200,
			},
			TCP: &model.TCPReport{
				Status:    model.TCPStatusConnected,
				LatencyMs: 15,
			},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				EgressInterface: "eth0",
				Table:           254,
			},
			TCP: &model.TCPReport{
				Status: model.TCPStatusTimeout,
			},
		},
		Differences: []model.Difference{
			{
				Category:     "Policy",
				Field:        "policy_rule",
				WorkingValue: "from all to 10.40.0.0/16 lookup 200",
				FailingValue: "missing / lookup main",
				Relevance:    model.RelevanceHigh,
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "Policy routing rule divergence") {
		t.Errorf("expected summary to mention policy routing divergence, got: %s", explanation.Summary)
	}

	if len(explanation.Hypotheses) == 0 {
		t.Fatalf("expected at least one hypothesis, got 0")
	}

	if explanation.Hypotheses[0].SupportLevel != "strong" {
		t.Errorf("expected strong support, got: %s", explanation.Hypotheses[0].SupportLevel)
	}

	if explanation.NextBestProbe == nil {
		t.Fatalf("expected next best probe, got nil")
	}

	if explanation.NextBestProbe.ProbeName != "TEST_TCP_BIND_INTERFACE" {
		t.Errorf("expected TEST_TCP_BIND_INTERFACE, got: %s", explanation.NextBestProbe.ProbeName)
	}

	if explanation.NextBestProbe.Parameter != "tun0" {
		t.Errorf("expected parameter 'tun0', got: %s", explanation.NextBestProbe.Parameter)
	}
}

func TestExplain_DNSDivergence(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{
			Raw:  "api.corp:443",
			Host: "api.corp",
			Port: 443,
		},
		WorkingSnapshot: &model.Snapshot{
			DNS: &model.DNSReport{
				Nameservers: []string{"10.0.0.2"},
			},
			TCP: &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			DNS: &model.DNSReport{
				Nameservers: []string{"8.8.8.8"},
			},
			TCP: &model.TCPReport{Status: model.TCPStatusRefused},
		},
		Differences: []model.Difference{
			{
				Category:     "DNS",
				Field:        "resolution_success",
				WorkingValue: "true",
				FailingValue: "false (nxdomain)",
				Relevance:    model.RelevanceHigh,
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "DNS resolution divergence") {
		t.Errorf("expected summary to mention DNS divergence, got: %s", explanation.Summary)
	}

	if explanation.NextBestProbe == nil || explanation.NextBestProbe.ProbeName != "TEST_DNS_WITH_RESOLVER" {
		t.Errorf("expected TEST_DNS_WITH_RESOLVER, got: %+v", explanation.NextBestProbe)
	}
}

func TestExplain_FirewallDivergence(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{Raw: "api.corp:443", Host: "api.corp", Port: 443},
		WorkingSnapshot: &model.Snapshot{
			TCP: &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			TCP: &model.TCPReport{Status: model.TCPStatusTimeout},
		},
		Differences: []model.Difference{
			{
				Category:     "Firewall",
				Field:        "drop_rule",
				WorkingValue: "none",
				FailingValue: "DROP tcp dpt:443",
				Relevance:    model.RelevanceHigh,
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "Firewall") {
		t.Errorf("expected summary to mention Firewall, got: %s", explanation.Summary)
	}
}

func TestExplain_InterfaceStateDivergence(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				EgressInterface: "veth-client",
				Success:         true,
			},
			TCP: &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				EgressInterface: "veth-client",
				Success:         true,
			},
			TCP: &model.TCPReport{Status: model.TCPStatusFailed},
		},
		Differences: []model.Difference{
			{
				Category:     "Interface",
				Field:        "admin_state",
				WorkingValue: "UP",
				FailingValue: "DOWN",
				Relevance:    model.RelevanceHigh,
				Rationale:    "Interface administrative state differs: working is UP while failing is DOWN.",
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "Interface link state divergence") {
		t.Errorf("expected summary to mention interface link state divergence, got: %s", explanation.Summary)
	}

	if explanation.NextBestProbe == nil {
		t.Fatal("expected recommended probe")
	}

	if explanation.NextBestProbe.ProbeName != "TEST_INTERFACE_STATE" {
		t.Errorf("expected TEST_INTERFACE_STATE probe, got: %s", explanation.NextBestProbe.ProbeName)
	}

	if explanation.NextBestProbe.Parameter != "veth-client" {
		t.Errorf("expected probe parameter 'veth-client', got: %s", explanation.NextBestProbe.Parameter)
	}
}

func TestExplain_RouteLookupFailure(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				EgressInterface: "veth-client",
				Success:         true,
			},
			TCP: &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				Success: false,
				Error:   "Network is unreachable",
			},
			TCP: &model.TCPReport{Status: model.TCPStatusUnreachable},
		},
		Differences: []model.Difference{
			{
				Category:       "Route",
				Field:          "route_lookup_success",
				WorkingValue:   "true",
				FailingValue:   "false",
				Relevance:      model.RelevanceHigh,
				DependencyNode: "Route",
				Rationale:      "Route lookup outcome changed. Failure evidence: Network is unreachable",
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "Route lookup failed") {
		t.Errorf("expected summary to mention route lookup failed, got: %s", explanation.Summary)
	}

	if strings.Contains(explanation.Summary, "eth0") {
		t.Errorf("summary should NOT invent fallback interface eth0: %s", explanation.Summary)
	}

	if explanation.NextBestProbe == nil || explanation.NextBestProbe.ProbeName != "TEST_INTERFACE_STATE" {
		t.Errorf("expected TEST_INTERFACE_STATE probe, got: %+v", explanation.NextBestProbe)
	}
}

func TestExplain_ConnectionRefusedClosedPort(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "veth-client", Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "veth-client", Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusRefused},
		},
		Differences: []model.Difference{
			{
				Category:     "TCP",
				Field:        "status",
				WorkingValue: "connected",
				FailingValue: "refused",
				Relevance:    model.RelevanceHigh,
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "actively refused") {
		t.Errorf("expected summary to indicate connection actively refused, got: %s", explanation.Summary)
	}
	if !strings.Contains(explanation.Summary, "not listening") {
		t.Errorf("expected summary to explain service is not listening, got: %s", explanation.Summary)
	}
}

func TestConfidenceAssignment(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "veth-client", Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{Success: false, Error: "Network is unreachable"},
			TCP:   &model.TCPReport{Status: model.TCPStatusUnreachable},
		},
		Differences: []model.Difference{
			{
				Category:     "Route",
				Field:        "route_lookup_success",
				WorkingValue: "true",
				FailingValue: "false",
				Relevance:    model.RelevanceHigh,
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(explanation.Hypotheses) == 0 {
		t.Fatalf("expected hypotheses, got none")
	}

	for _, h := range explanation.Hypotheses {
		if h.ConfidencePct <= 0 || h.ConfidencePct > 100 {
			t.Errorf("hypothesis %q has invalid ConfidencePct %d", h.Title, h.ConfidencePct)
		}
	}
}

func TestExplain_NeighborARPDivergence(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		WorkingSnapshot: &model.Snapshot{
			Route:    &model.RouteReport{EgressInterface: "veth-client", Success: true},
			Neighbor: &model.NeighborReport{IP: "10.10.0.2", MAC: "52:54:00:12:34:56", State: "REACHABLE", Present: true},
			TCP:      &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route:    &model.RouteReport{EgressInterface: "veth-client", Success: true},
			Neighbor: &model.NeighborReport{IP: "10.10.0.2", State: "INCOMPLETE", Present: false},
			TCP:      &model.TCPReport{Status: model.TCPStatusTimeout},
		},
		Differences: []model.Difference{
			{
				Category:     "Neighbor",
				Field:        "arp_state",
				WorkingValue: "REACHABLE",
				FailingValue: "INCOMPLETE",
				Relevance:    model.RelevanceHigh,
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "neighbor resolution (ARP/NDP)") {
		t.Errorf("expected summary to mention neighbor resolution (ARP/NDP), got: %s", explanation.Summary)
	}

	if len(explanation.Hypotheses) == 0 {
		t.Fatal("expected at least one hypothesis")
	}

	if !strings.Contains(explanation.Hypotheses[0].Title, "ARP Resolution Failed") {
		t.Errorf("expected hypothesis title to mention ARP, got: %s", explanation.Hypotheses[0].Title)
	}
}

func TestExplain_TLSCertificateDivergence(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		Target: model.Target{Raw: "api.internal.corp:443", Host: "api.internal.corp", Port: 443, Protocol: "https"},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "eth0", Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusConnected},
			TLS: &model.TLSReport{
				HandshakeSuccess: true,
				Version:          "TLS 1.3",
			},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "eth0", Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusConnected},
			TLS: &model.TLSReport{
				HandshakeSuccess: false,
				Error:            "x509: certificate signed by unknown authority",
				ErrorCategory:    "untrusted_root",
			},
		},
		Differences: []model.Difference{
			{
				Category:     "TLS",
				Field:        "tls_handshake",
				WorkingValue: "success (TLS 1.3)",
				FailingValue: "failed (x509: certificate signed by unknown authority)",
				Relevance:    model.RelevanceHigh,
			},
		},
	}

	explanation, err := reasoner.Explain(context.Background(), report, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(explanation.Summary, "TLS certificate") {
		t.Errorf("expected summary to mention TLS certificate, got: %s", explanation.Summary)
	}

	if len(explanation.Hypotheses) == 0 {
		t.Fatal("expected hypotheses for TLS failure")
	}

	if !strings.Contains(explanation.Hypotheses[0].Title, "Root CA") {
		t.Errorf("expected hypothesis to mention Root CA, got: %s", explanation.Hypotheses[0].Title)
	}

	if explanation.Remediation == nil {
		t.Fatal("expected remediation for TLS untrusted root")
	}
	if !strings.Contains(explanation.Remediation.ImmediateBash, "update-ca-certificates") {
		t.Errorf("expected ca-certificates update command, got: %s", explanation.Remediation.ImmediateBash)
	}
}

func TestExplain_RemediationCoverage(t *testing.T) {
	reasoner := NewReasoner()

	// Test Policy Remediation
	policyRep := &model.ComparisonReport{
		Target: model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "tun0", Table: 200, Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "eth0", Table: 254, Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusTimeout},
		},
		Differences: []model.Difference{
			{Category: "Policy", Field: "policy_rule", WorkingValue: "to 10.40.0.0/16 lookup 200", FailingValue: "missing", Relevance: model.RelevanceHigh},
		},
	}
	expPolicy, err := reasoner.Explain(context.Background(), policyRep, false)
	if err != nil || expPolicy.Remediation == nil {
		t.Fatalf("expected policy remediation, got err: %v", err)
	}
	if !strings.Contains(expPolicy.Remediation.ImmediateBash, "ip rule add to 10.40.8.21/32 lookup 200") {
		t.Errorf("unexpected policy bash: %s", expPolicy.Remediation.ImmediateBash)
	}
	if !strings.Contains(expPolicy.Remediation.RollbackBash, "ip rule del to 10.40.8.21/32 lookup 200") {
		t.Errorf("unexpected policy rollback bash: %s", expPolicy.Remediation.RollbackBash)
	}
	if !strings.Contains(expPolicy.Remediation.PermanentConfig, "routing-policy") {
		t.Errorf("expected netplan routing policy, got: %s", expPolicy.Remediation.PermanentConfig)
	}

	// Test Policy Remediation with Hostname Target and Destination IP Resolution
	policyHostnameRep := &model.ComparisonReport{
		Target: model.Target{Raw: "api.internal.company:443", Host: "api.internal.company", Port: 443, IsIP: false},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{DestinationIP: "10.40.8.21", EgressInterface: "tun0", Table: 200, Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{DestinationIP: "10.40.8.21", EgressInterface: "eth0", Table: 254, Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusTimeout},
		},
		Differences: []model.Difference{
			{Category: "Policy", Field: "policy_rule", WorkingValue: "to 10.40.0.0/16 lookup 200", FailingValue: "missing", Relevance: model.RelevanceHigh},
		},
	}
	expPolicyHost, err := reasoner.Explain(context.Background(), policyHostnameRep, false)
	if err != nil || expPolicyHost.Remediation == nil {
		t.Fatalf("expected policy remediation for hostname, got err: %v", err)
	}
	if !strings.Contains(expPolicyHost.Remediation.ImmediateBash, "ip rule add to 10.40.8.21/32 lookup 200") {
		t.Errorf("expected resolved IP in policy bash, got: %s", expPolicyHost.Remediation.ImmediateBash)
	}
	if !strings.Contains(expPolicyHost.Remediation.RollbackBash, "ip rule del to 10.40.8.21/32 lookup 200") {
		t.Errorf("expected resolved IP in rollback bash, got: %s", expPolicyHost.Remediation.RollbackBash)
	}

	// Test Firewall Remediation
	fwRep := &model.ComparisonReport{
		Target:          model.Target{Raw: "api.corp:443", Host: "api.corp", Port: 443},
		WorkingSnapshot: &model.Snapshot{TCP: &model.TCPReport{Status: model.TCPStatusConnected}},
		FailingSnapshot: &model.Snapshot{TCP: &model.TCPReport{Status: model.TCPStatusTimeout}},
		Differences: []model.Difference{
			{Category: "Firewall", Field: "drop_rule", WorkingValue: "none", FailingValue: "DROP tcp dpt:443", Relevance: model.RelevanceHigh},
		},
	}
	expFW, err := reasoner.Explain(context.Background(), fwRep, false)
	if err != nil || expFW.Remediation == nil {
		t.Fatalf("expected firewall remediation, got err: %v", err)
	}
	if !strings.Contains(expFW.Remediation.ImmediateBash, "iptables -D OUTPUT -p tcp --dport 443 -j DROP") {
		t.Errorf("unexpected firewall bash: %s", expFW.Remediation.ImmediateBash)
	}
	if !strings.Contains(expFW.Remediation.RollbackBash, "iptables -A OUTPUT -p tcp --dport 443 -j DROP") {
		t.Errorf("unexpected firewall rollback bash: %s", expFW.Remediation.RollbackBash)
	}

	// Test Interface Remediation
	ifaceRep := &model.ComparisonReport{
		Target: model.Target{Raw: "10.0.0.1:80", Host: "10.0.0.1", Port: 80},
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "eth1", Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{EgressInterface: "eth1", Success: true},
			TCP:   &model.TCPReport{Status: model.TCPStatusTimeout},
		},
		Differences: []model.Difference{
			{Category: "Interface", Field: "admin_state", WorkingValue: "UP", FailingValue: "DOWN", Relevance: model.RelevanceHigh},
		},
	}
	expIface, err := reasoner.Explain(context.Background(), ifaceRep, false)
	if err != nil || expIface.Remediation == nil {
		t.Fatalf("expected interface remediation, got err: %v", err)
	}
	if !strings.Contains(expIface.Remediation.ImmediateBash, "ip link set dev eth1 up") {
		t.Errorf("unexpected iface bash: %s", expIface.Remediation.ImmediateBash)
	}
	if !strings.Contains(expIface.Remediation.RollbackBash, "ip link set dev eth1 down") {
		t.Errorf("unexpected iface rollback bash: %s", expIface.Remediation.RollbackBash)
	}
}

func TestAsk_DeterministicGrounded(t *testing.T) {
	reasoner := NewReasoner()
	report := &model.ComparisonReport{
		WorkingHost: "host-good",
		FailingHost: "host-bad",
		Target: model.Target{
			Raw:  "10.40.8.21:8080",
			Host: "10.40.8.21",
			Port: 8080,
		},
		EarliestDivergence: "Policy Rule: from all to 10.40.0.0/16 lookup 200 != default main",
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				EgressInterface: "tun0",
				Table:           200,
			},
			TCP: &model.TCPReport{
				Status:    model.TCPStatusConnected,
				LatencyMs: 15,
			},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				EgressInterface: "eth0",
				Table:           254,
			},
			TCP: &model.TCPReport{
				Status: model.TCPStatusTimeout,
			},
		},
		Differences: []model.Difference{
			{
				Category:     "Policy",
				Field:        "policy_rule",
				WorkingValue: "from all to 10.40.0.0/16 lookup 200",
				FailingValue: "missing / lookup main",
				Relevance:    model.RelevanceHigh,
				Rationale:    "Traffic on failing host drops into main table instead of policy table 200",
			},
		},
	}

	// 1. General question
	ans, err := reasoner.Ask(context.Background(), report, "Why is host-bad failing to connect?")
	if err != nil {
		t.Fatalf("unexpected ask error: %v", err)
	}
	if !strings.Contains(ans, "Earliest Divergence") || !strings.Contains(ans, "10.40.8.21:8080") {
		t.Errorf("expected answer grounded in target and divergence, got: %s", ans)
	}

	// 2. Specific question about rule / routing
	ansRule, err := reasoner.Ask(context.Background(), report, "Is there an ip rule difference?")
	if err != nil {
		t.Fatalf("unexpected ask error: %v", err)
	}
	if !strings.Contains(ansRule, "Policy") || !strings.Contains(ansRule, "lookup 200") {
		t.Errorf("expected answer mentioning policy rule, got: %s", ansRule)
	}

	// 3. Question asking for fix / remediation
	ansFix, err := reasoner.Ask(context.Background(), report, "How do I fix this issue?")
	if err != nil {
		t.Fatalf("unexpected ask error: %v", err)
	}
	if !strings.Contains(ansFix, "ip rule add") {
		t.Errorf("expected answer with remediation command, got: %s", ansFix)
	}
}
