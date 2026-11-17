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
