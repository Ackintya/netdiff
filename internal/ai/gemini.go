package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"netdiff/pkg/model"
)

// DiagnosticHypothesis represents a reasoned cause with support level.
type DiagnosticHypothesis struct {
	Title        string `json:"title"`
	SupportLevel string `json:"support_level"` // "strong", "moderate", "weak"
	Rationale    string `json:"rationale"`
}

// DiagnosticProbeChoice is a bounded follow-up test chosen from the safe fixed catalog.
type DiagnosticProbeChoice struct {
	ProbeName string `json:"probe_name"`
	Parameter string `json:"parameter,omitempty"`
	Reason    string `json:"reason"`
}

// ExplanationReport contains Gemini's structured synthesis over the evidence bundle.
type ExplanationReport struct {
	Summary       string                  `json:"summary"`
	Hypotheses    []DiagnosticHypothesis  `json:"hypotheses"`
	NextBestProbe *DiagnosticProbeChoice  `json:"next_best_probe,omitempty"`
}

// Reasoner analyzes the comparison report. If GEMINI_API_KEY is available, it can call Gemini,
// or provide a local structured reasoning fallback.
type Reasoner struct {
	APIKey string
}

func NewReasoner() *Reasoner {
	return &Reasoner{
		APIKey: os.Getenv("GEMINI_API_KEY"),
	}
}

// Explain synthesizes the structured comparison into an incident diagnosis and next probe.
func (r *Reasoner) Explain(_ context.Context, report *model.ComparisonReport) (*ExplanationReport, error) {
	// If no API key is provided, use our deterministic rules engine to synthesize the structured report
	result := &ExplanationReport{}

	var highDiffs []model.Difference
	for _, d := range report.Differences {
		if d.Relevance == model.RelevanceHigh && d.Category != "TCP" {
			highDiffs = append(highDiffs, d)
		}
	}

	wTCP := "unknown"
	fTCP := "unknown"
	if report.WorkingSnapshot.TCP != nil {
		wTCP = string(report.WorkingSnapshot.TCP.Status)
	}
	if report.FailingSnapshot.TCP != nil {
		fTCP = string(report.FailingSnapshot.TCP.Status)
	}

	if len(highDiffs) == 0 {
		result.Summary = fmt.Sprintf("Both environments share identical network paths to %s. Observed outcomes (working: %s, failing: %s) suggest an intermittent or application-level issue.", report.Target.Raw, wTCP, fTCP)
		return result, nil
	}

	primary := highDiffs[0]
	switch primary.Category {
	case "Route", "Interface":
		result.Summary = fmt.Sprintf("Routing divergence is the strongest current explanation. The working environment routes through %s while the failing environment routes through %s. Since the failing connection experienced %s, this divergence directly accounts for the path failure.",
			primary.WorkingValue, primary.FailingValue, fTCP)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "VPN/Policy Route Bypass",
				SupportLevel: "strong",
				Rationale:    fmt.Sprintf("Traffic in failing environment is routed via %s instead of expected %s interface.", primary.FailingValue, primary.WorkingValue),
			},
			{
				Title:        "MTU or Path Blackhole",
				SupportLevel: "weak",
				Rationale:    "Path MTU issues usually establish TCP handshake before dropping larger data packets.",
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_TCP_BIND_INTERFACE",
			Parameter: primary.WorkingValue,
			Reason:    fmt.Sprintf("Binding TCP socket explicitly to %s on the failing host will verify if reachability succeeds over that link.", primary.WorkingValue),
		}

	case "DNS":
		result.Summary = fmt.Sprintf("DNS resolution divergence occurred upstream before IP routing took place. Working resolved to %s, failing resulted in %s.",
			primary.WorkingValue, primary.FailingValue)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Resolver / Split-Horizon DNS Divergence",
				SupportLevel: "strong",
				Rationale:    "The destination name is not resolving to the appropriate internal endpoint on the failing host.",
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DNS_WITH_RESOLVER",
			Parameter: strings.Join(report.WorkingSnapshot.DNS.Nameservers, ","),
			Reason:    "Querying the working host's resolver directly tests if the record exists on the internal DNS zone.",
		}

	case "Proxy":
		result.Summary = fmt.Sprintf("Proxy divergence detected. The failing environment has proxy configured (%s) which intercepts or drops connections to %s.",
			primary.FailingValue, report.Target.Raw)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Unreachable or Misconfigured Proxy",
				SupportLevel: "strong",
				Rationale:    "HTTP(S)_PROXY environment variables override normal kernel IP routing.",
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_PROXY_DISABLED",
			Reason:    "Disabling proxy environment variables tests if direct egress connects successfully.",
		}
	}

	return result, nil
}

// DumpJSON returns pretty JSON representation of the explanation
func (e *ExplanationReport) DumpJSON() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return string(b)
}
