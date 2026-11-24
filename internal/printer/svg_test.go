package printer

import (
	"strings"
	"testing"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

func TestRenderSVG_PolicyDivergence(t *testing.T) {
	comp := &model.ComparisonReport{
		Target: model.Target{
			Raw:      "api.internal.company:443",
			Host:     "api.internal.company",
			Port:     443,
			Protocol: "tcp",
		},
		WorkingHost:        "developer-laptop",
		FailingHost:        "developer-workstation",
		EarliestDivergence: "Policy Rule: from all to 10.40.0.0/16 lookup 200 != default main",
		WorkingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				DestinationIP:   "10.40.8.21",
				Table:           200,
				TableName:       "table 200",
				Gateway:         "10.8.0.1",
				EgressInterface: "tun0",
				PreferredSource: "10.8.0.14",
				PolicyRule:      "from all to 10.40.0.0/16 lookup 200",
				Success:         true,
			},
			Interface: &model.InterfaceReport{
				Name:      "tun0",
				MTU:       1420,
				OperState: "up",
			},
			TCP: &model.TCPReport{
				Status:    model.TCPStatusConnected,
				LatencyMs: 27,
			},
		},
		FailingSnapshot: &model.Snapshot{
			Route: &model.RouteReport{
				DestinationIP:   "10.40.8.21",
				Table:           254,
				TableName:       "main",
				Gateway:         "192.168.1.1",
				EgressInterface: "eth0",
				PreferredSource: "192.168.1.84",
				Success:         true,
			},
			Interface: &model.InterfaceReport{
				Name:      "eth0",
				MTU:       1500,
				OperState: "up",
			},
			TCP: &model.TCPReport{
				Status: model.TCPStatusTimeout,
			},
		},
	}

	exp := &ai.ExplanationReport{
		Summary: "Missing policy routing rule lookup 200.",
		Remediation: &ai.RemediationPlan{
			ImmediateBash:   "sudo ip rule add to 10.40.8.21/32 lookup 200",
			VerificationCmd: "ip rule show | grep 200",
			Explanation:     "Directs traffic for target to table 200 via tun0.",
		},
	}

	svg := RenderSVG(comp, exp)
	if svg == "" {
		t.Fatal("RenderSVG returned empty string")
	}

	if !strings.HasPrefix(svg, "<svg") {
		t.Errorf("expected SVG to start with <svg, got: %s", svg[:30])
	}

	if !strings.HasSuffix(strings.TrimSpace(svg), "</svg>") {
		t.Errorf("expected SVG to end with </svg>")
	}

	expectedSubstrings := []string{
		"api.internal.company:443",
		"DEVELOPER-LAPTOP",
		"DEVELOPER-WORKSTATION",
		"ROOT CAUSE",
		"sudo ip rule add to 10.40.8.21/32 lookup 200",
		"ACTIONABLE REMEDIATION PLAYBOOK",
		"Policy Routing (ip rule)",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(svg, sub) {
			t.Errorf("expected SVG to contain %q", sub)
		}
	}
}

func TestRenderSVG_NilSafe(t *testing.T) {
	svg := RenderSVG(nil, nil)
	if svg != "" {
		t.Errorf("expected empty string for nil report, got length %d", len(svg))
	}
}
