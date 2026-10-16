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
