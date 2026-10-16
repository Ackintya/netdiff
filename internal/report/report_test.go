package report

import (
	"strings"
	"testing"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

func TestGenerateMarkdown(t *testing.T) {
	comp := &model.ComparisonReport{
		WorkingHost: "dev-laptop",
		FailingHost: "dev-desktop",
		Target: model.Target{
			Raw:      "api.corp:443",
			Host:     "api.corp",
			Port:     443,
			Protocol: "tcp",
		},
		EarliestDivergence: "Policy Rule: from all to 10.40.0.0/16 lookup 200 != default main",
		WorkingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux"},
			Route: &model.RouteReport{
				EgressInterface: "tun0",
				Table:           200,
				Gateway:         "10.8.0.1",
				PreferredSource: "10.8.0.14",
				PolicyRule:      "from all to 10.40.0.0/16 lookup 200",
			},
			TCP: &model.TCPReport{
				Status:    model.TCPStatusConnected,
				LatencyMs: 22,
			},
		},
		FailingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux"},
			Route: &model.RouteReport{
				EgressInterface: "eth0",
				Table:           254,
				Gateway:         "192.168.1.1",
				PreferredSource: "192.168.1.84",
			},
			TCP: &model.TCPReport{
				Status: model.TCPStatusTimeout,
			},
		},
		Differences: []model.Difference{
			{
				Category:     "Policy",
				WorkingValue: "from all to 10.40.0.0/16 lookup 200",
				FailingValue: "missing / lookup main",
				Relevance:    model.RelevanceHigh,
				Rationale:    "Policy rule omitted.",
			},
		},
	}

	exp := &ai.ExplanationReport{
		Summary: "Policy routing divergence caused eth0 egress instead of tun0.",
		Hypotheses: []ai.DiagnosticHypothesis{
			{
				Title:        "Missing ip rule",
				SupportLevel: "strong",
				Rationale:    "Route table bypass.",
			},
		},
		NextBestProbe: &ai.DiagnosticProbeChoice{
			ProbeName: "TEST_TCP_BIND_INTERFACE",
			Parameter: "tun0",
			Reason:    "Bypass policy table to verify tunnel.",
		},
	}

	md := GenerateMarkdown(comp, exp)

	if !strings.Contains(md, "# NetDiff Incident Report: api.corp:443") {
		t.Errorf("expected header to contain target, got: %s", md)
	}
	if !strings.Contains(md, "Root Cause Identified") {
		t.Errorf("expected Root Cause section, got: %s", md)
	}
	if !strings.Contains(md, "| **Egress Interface**") && !strings.Contains(md, "| **Route Egress**") {
		t.Errorf("expected Route Egress in table, got: %s", md)
	}
	if !strings.Contains(md, "netdiff probe TEST_TCP_BIND_INTERFACE tun0 -t api.corp:443") {
		t.Errorf("expected probe command suggestion in markdown, got: %s", md)
	}
}
