package printer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

func TestConfidenceBar(t *testing.T) {
	tests := []struct {
		pct      int
		expected string
	}{
		{0, "░░░░░░░░░░░░░░░░░░░░"},
		{50, "██████████░░░░░░░░░░"},
		{100, "████████████████████"},
		{-10, "░░░░░░░░░░░░░░░░░░░░"},
		{110, "████████████████████"},
	}

	for _, tt := range tests {
		got := confidenceBar(tt.pct)
		if got != tt.expected {
			t.Errorf("confidenceBar(%d) = %q, want %q", tt.pct, got, tt.expected)
		}
	}
}

func TestWrapText(t *testing.T) {
	text := "This is a simple sentence that should wrap nicely across multiple lines when width is small."
	wrapped := wrapText(text, 25, "  ")
	lines := strings.Split(wrapped, "\n")
	if len(lines) < 2 {
		t.Errorf("expected multiple lines, got %d", len(lines))
	}
	if !strings.HasPrefix(lines[1], "  ") {
		t.Errorf("expected indent prefix on wrapped line, got %q", lines[1])
	}
}

func TestPrintCapturePath(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Out: &buf}

	snap := &model.Snapshot{
		Target: model.Target{
			Raw:  "10.10.0.2:8080",
			Host: "10.10.0.2",
			Port: 8080,
			IsIP: true,
		},
		Metadata: model.SnapshotMetadata{
			Hostname:   "nd-client",
			CapturedAt: time.Now(),
		},
		Route: &model.RouteReport{
			Success:         true,
			EgressInterface: "veth-client",
			PreferredSource: "10.10.0.1",
			TableName:       "main",
		},
		Interface: &model.InterfaceReport{
			Name:      "veth-client",
			Flags:     []string{"UP", "BROADCAST"},
			MTU:       1500,
			OperState: "up",
		},
		TCP: &model.TCPReport{
			Status:     model.TCPStatusConnected,
			LocalAddr:  "10.10.0.1:52149",
			RemoteIP:   "10.10.0.2",
			RemotePort: 8080,
			LatencyMs:  2,
		},
	}

	p.PrintCapturePath(snap)
	out := buf.String()

	if !strings.Contains(out, "Captured: 10.10.0.2:8080") {
		t.Errorf("expected output to contain target, got: %s", out)
	}
	if !strings.Contains(out, "veth-client") {
		t.Errorf("expected output to contain interface name, got: %s", out)
	}
	if !strings.Contains(out, "connected") {
		t.Errorf("expected output to contain connected status, got: %s", out)
	}
}

func TestPrintDiagnosis(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Out: &buf}

	comp := &model.ComparisonReport{
		Target: model.Target{
			Raw:  "10.10.0.2:8080",
			Host: "10.10.0.2",
			Port: 8080,
		},
		WorkingHost:        "host-good",
		FailingHost:        "host-bad",
		EarliestDivergence: "Route:route_lookup_success working=true -> failing=false",
		WorkingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{CapturedAt: time.Now(), Hostname: "host-good"},
			Route:    &model.RouteReport{Success: true, EgressInterface: "veth-client"},
			TCP:      &model.TCPReport{Status: model.TCPStatusConnected},
		},
		FailingSnapshot: &model.Snapshot{
			Metadata: model.SnapshotMetadata{CapturedAt: time.Now(), Hostname: "host-bad"},
			Route:    &model.RouteReport{Success: false, Error: "Network is unreachable"},
			TCP:      &model.TCPReport{Status: model.TCPStatusUnreachable},
		},
		Differences: []model.Difference{
			{
				Category:  "Route",
				Field:     "route_lookup_success",
				Relevance: model.RelevanceHigh,
			},
		},
	}

	exp := &ai.ExplanationReport{
		Summary:  "Route lookup failed in the failing environment.",
		Provider: "deterministic",
		Hypotheses: []ai.DiagnosticHypothesis{
			{
				Title:         "Previously Used Interface Is Down or Unavailable",
				SupportLevel:  "moderate",
				ConfidencePct: 45,
				Rationale:     "An unavailable interface causes its route to disappear.",
			},
		},
		NextBestProbe: &ai.DiagnosticProbeChoice{
			ProbeName: "TEST_INTERFACE_STATE",
			Parameter: "veth-client",
			Reason:    "Inspect whether interface exists and is UP.",
		},
	}

	p.PrintDiagnosis(comp, exp)
	out := buf.String()

	if !strings.Contains(out, "NETDIFF DIAGNOSIS") {
		t.Errorf("expected diagnosis header, got: %s", out)
	}
	if !strings.Contains(out, "PATH CHAIN") {
		t.Errorf("expected path chain, got: %s", out)
	}
	if !strings.Contains(out, "ROOT CAUSE") {
		t.Errorf("expected root cause, got: %s", out)
	}
	if !strings.Contains(out, "45%") {
		t.Errorf("expected confidence percentage, got: %s", out)
	}
	if !strings.Contains(out, "netdiff probe TEST_INTERFACE_STATE veth-client") {
		t.Errorf("expected probe command, got: %s", out)
	}
}

func TestPrintCheck(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Out: &buf}

	snapGood := &model.Snapshot{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		Route:  &model.RouteReport{EgressInterface: "veth-client"},
		TCP: &model.TCPReport{
			Status:     model.TCPStatusConnected,
			LocalAddr:  "10.10.0.1:52149",
			RemoteIP:   "10.10.0.2",
			RemotePort: 8080,
			LatencyMs:  2,
		},
	}

	p.PrintCheck(snapGood)
	if !strings.Contains(buf.String(), "connected") {
		t.Errorf("expected connected, got %s", buf.String())
	}

	buf.Reset()
	snapBad := &model.Snapshot{
		Target: model.Target{Raw: "10.10.0.2:8080", Host: "10.10.0.2", Port: 8080},
		Route:  &model.RouteReport{Success: false, Error: "Network is unreachable"},
	}
	p.PrintCheck(snapBad)
	if !strings.Contains(buf.String(), "unreachable") {
		t.Errorf("expected unreachable, got %s", buf.String())
	}

	buf.Reset()
	snapTLSBad := &model.Snapshot{
		Target: model.Target{Raw: "api.corp:443", Host: "api.corp", Port: 443, Protocol: "https"},
		TCP:    &model.TCPReport{Status: model.TCPStatusConnected},
		TLS: &model.TLSReport{
			HandshakeSuccess: false,
			Error:            "x509: certificate signed by unknown authority",
		},
	}
	p.PrintCheck(snapTLSBad)
	if !strings.Contains(buf.String(), "tls_failed") {
		t.Errorf("expected tls_failed, got %s", buf.String())
	}
}
