package printer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

func TestPrintGraph_PolicyDivergence(t *testing.T) {
	comp := &model.ComparisonReport{
		WorkingHost: "dev-laptop",
		FailingHost: "dev-desktop",
		Target: model.Target{
			Raw:      "api.corp:443",
			Host:     "api.corp",
			Port:     443,
			Protocol: "https",
		},
		EarliestDivergence: "Policy Rule: from all to 10.40.0.0/16 lookup 200 != lookup main",
		WorkingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux"},
			Route: &model.RouteReport{
				EgressInterface: "tun0",
				Table:           200,
				TableName:       "200",
				Gateway:         "10.8.0.1",
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
				LatencyMs: 22,
				SocketInfo: &model.TCPSocketInfo{
					RTTUs:        1840,
					TotalRetrans: 0,
					SndCwnd:      10,
				},
			},
			TLS: &model.TLSReport{
				HandshakeSuccess: true,
				Version:          "TLS 1.3",
				Issuer:           "Let's Encrypt",
			},
		},
		FailingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux"},
			Route: &model.RouteReport{
				EgressInterface: "eth0",
				Table:           254,
				TableName:       "main",
				Gateway:         "192.168.1.1",
				PreferredSource: "192.168.1.84",
				PolicyRule:      "default main",
				Success:         true,
			},
			Interface: &model.InterfaceReport{
				Name:      "eth0",
				MTU:       1500,
				OperState: "up",
			},
			TCP: &model.TCPReport{
				Status:    model.TCPStatusTimeout,
				LatencyMs: 5000,
			},
		},
		Differences: []model.Difference{
			{
				Category:       "Policy",
				Field:          "policy_rule",
				WorkingValue:   "from all to 10.40.0.0/16 lookup 200",
				FailingValue:   "default main",
				Relevance:      model.RelevanceHigh,
				DependencyNode: "Policy Rule",
				Rationale:      "Traffic is not matching policy routing table 200 on failing host.",
			},
		},
	}

	exp := &ai.ExplanationReport{
		Summary: "Policy routing divergence caused traffic to route out eth0 instead of tun0.",
		Hypotheses: []ai.DiagnosticHypothesis{
			{
				Title:        "Missing Policy Rule",
				SupportLevel: "strong",
				Rationale:    "Traffic falls through to physical interface.",
			},
		},
		NextBestProbe: &ai.DiagnosticProbeChoice{
			ProbeName: "TEST_TCP_BIND_INTERFACE",
			Parameter: "tun0",
			Reason:    "Validate whether binding directly to tun0 connects successfully.",
		},
	}

	var buf bytes.Buffer
	p := &Printer{Out: &buf}
	p.PrintGraph(comp, exp)

	out := buf.String()

	if !strings.Contains(out, "NetDiff Causal Dependency Graph") {
		t.Errorf("expected graph header")
	}
	if !strings.Contains(out, "api.corp:443") {
		t.Errorf("expected target")
	}
	if !strings.Contains(out, "Policy Routing (ip rule)") {
		t.Errorf("expected policy routing stage")
	}
	if !strings.Contains(out, "ROOT CAUSE (Earliest Divergence)") {
		t.Errorf("expected root cause marker")
	}
	if !strings.Contains(out, "FIB Route Lookup") {
		t.Errorf("expected route lookup sub-branch")
	}
	if !strings.Contains(out, "Kernel Socket Stats") {
		t.Errorf("expected kernel socket stats sub-branch")
	}
	if !strings.Contains(out, "TLS Handshake") {
		t.Errorf("expected TLS stage")
	}
	if !strings.Contains(out, "netdiff probe TEST_TCP_BIND_INTERFACE tun0 -t api.corp:443") {
		t.Errorf("expected probe suggestion, got: %s", out)
	}
}

func TestPrintGraph_TLSFailure(t *testing.T) {
	comp := &model.ComparisonReport{
		WorkingHost: "host-a",
		FailingHost: "host-b",
		Target: model.Target{
			Raw:      "auth.internal:443",
			Host:     "auth.internal",
			Port:     443,
			Protocol: "https",
		},
		EarliestDivergence: "TLS Handshake: untrusted_root",
		WorkingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux", CapturedAt: time.Now()},
			Route:    &model.RouteReport{EgressInterface: "eth0", Success: true},
			TCP:      &model.TCPReport{Status: model.TCPStatusConnected, LatencyMs: 8},
			TLS: &model.TLSReport{
				HandshakeSuccess: true,
				Version:          "TLS 1.3",
				CipherSuite:      "TLS_AES_128_GCM_SHA256",
			},
		},
		FailingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{OS: "linux", CapturedAt: time.Now()},
			Route:    &model.RouteReport{EgressInterface: "eth0", Success: true},
			TCP:      &model.TCPReport{Status: model.TCPStatusConnected, LatencyMs: 8},
			TLS: &model.TLSReport{
				HandshakeSuccess: false,
				Error:            "x509: certificate signed by unknown authority",
				ErrorCategory:    "untrusted_root",
			},
		},
	}

	exp := &ai.ExplanationReport{
		Summary: "TLS certificate rejected due to missing enterprise CA root.",
		NextBestProbe: &ai.DiagnosticProbeChoice{
			ProbeName: "TEST_DIRECT_IP",
			Parameter: "auth.internal",
			Reason:    "Validate direct IP reachability without TLS.",
		},
	}

	var buf bytes.Buffer
	p := &Printer{Out: &buf}
	p.PrintGraph(comp, exp)

	out := buf.String()
	if !strings.Contains(out, "TLS Handshake") {
		t.Errorf("expected TLS Handshake stage")
	}
	if !strings.Contains(out, "untrusted_root") {
		t.Errorf("expected untrusted_root error category")
	}
}
