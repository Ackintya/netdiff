package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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
	Summary       string                 `json:"summary"`
	Hypotheses    []DiagnosticHypothesis `json:"hypotheses"`
	NextBestProbe *DiagnosticProbeChoice `json:"next_best_probe,omitempty"`
	Provider      string                 `json:"provider"` // "gemini" or "deterministic"
	Notice        string                 `json:"notice,omitempty"`
}

// Allowed safe probe catalog names
var allowedProbes = map[string]bool{
	"TEST_TCP_BIND_INTERFACE": true,
	"TEST_TCP_BIND_SOURCE":    true,
	"TEST_DNS_WITH_RESOLVER":  true,
	"TEST_PROXY_DISABLED":     true,
	"TEST_DIRECT_IP":          true,
	"TEST_INTERFACE_STATE":    true,
}

// Reasoner analyzes the comparison report. If GEMINI_API_KEY is available and requested,
// it queries Gemini with strict structured output, or falls back to the deterministic causal engine.
type Reasoner struct {
	APIKey     string
	Model      string
	HTTPClient *http.Client
}

func NewReasoner() *Reasoner {
	modelName := os.Getenv("GEMINI_MODEL")
	if modelName == "" {
		modelName = "gemini-2.5-flash"
	}
	return &Reasoner{
		APIKey: os.Getenv("GEMINI_API_KEY"),
		Model:  modelName,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Explain synthesizes the structured comparison into an incident diagnosis and recommended probe.
func (r *Reasoner) Explain(ctx context.Context, report *model.ComparisonReport, useAI bool) (*ExplanationReport, error) {
	if useAI && r.APIKey != "" {
		aiReport, err := r.callGemini(ctx, report)
		if err == nil && aiReport != nil && aiReport.Summary != "" {
			aiReport.Provider = "gemini"
			return aiReport, nil
		}
		// If AI call failed, gracefully fall back to deterministic engine with notice
		fallback, dErr := r.explainDeterministic(report)
		if fallback != nil {
			fallback.Notice = fmt.Sprintf("Notice: Gemini API call failed (%v); fell back to deterministic engine.", err)
		}
		return fallback, dErr
	}

	return r.explainDeterministic(report)
}

// explainDeterministic produces structured diagnosis using the causal DAG and relevance rankings.
func (r *Reasoner) explainDeterministic(report *model.ComparisonReport) (*ExplanationReport, error) {
	result := &ExplanationReport{
		Provider: "deterministic",
	}

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
		if fTCP == string(model.TCPStatusRefused) {
			result.Summary = fmt.Sprintf("Both environments share identical network paths to %s. The connection was actively refused (TCP RST) by port %d, confirming complete bidirectional network reachability but indicating the target service is not listening or refusing connections.", report.Target.Raw, report.Target.Port)
			result.Hypotheses = []DiagnosticHypothesis{
				{
					Title:        "Target Service Down or Port Closed",
					SupportLevel: "strong",
					Rationale:    fmt.Sprintf("Destination host responded with TCP RST on port %d. Network routing, ARP, and packet delivery succeeded.", report.Target.Port),
				},
				{
					Title:        "Endpoint Firewall Sending TCP Reset",
					SupportLevel: "moderate",
					Rationale:    "A local or endpoint firewall rule configured to REJECT with tcp-reset can mimic a closed port.",
				},
			}
			result.NextBestProbe = &DiagnosticProbeChoice{
				ProbeName: "TEST_DIRECT_IP",
				Parameter: report.Target.Host,
				Reason:    "Validate reachability to the destination IP directly to confirm endpoint host responsiveness.",
			}
			return result, nil
		}

		result.Summary = fmt.Sprintf("Both environments share identical network paths to %s. Observed outcomes (working: %s, failing: %s) suggest an intermittent endpoint failure or application-level drop.", report.Target.Raw, wTCP, fTCP)
		return result, nil
	}

	workingIface := "unspecified"
	if report.WorkingSnapshot.Route != nil && report.WorkingSnapshot.Route.EgressInterface != "" {
		workingIface = report.WorkingSnapshot.Route.EgressInterface
	}
	failingIface := "unspecified"
	if report.FailingSnapshot.Route != nil && report.FailingSnapshot.Route.EgressInterface != "" {
		failingIface = report.FailingSnapshot.Route.EgressInterface
	}

	primary := highDiffs[0]

	// Handle route lookup failure before ordinary egress mismatches.
	// A failed lookup does not identify an alternative interface.
	if primary.Category == "Route" &&
		primary.Field == "route_lookup_success" &&
		report.WorkingSnapshot.Route != nil &&
		report.FailingSnapshot.Route != nil &&
		report.WorkingSnapshot.Route.Success &&
		!report.FailingSnapshot.Route.Success {

		workingRoute := report.WorkingSnapshot.Route
		failingRoute := report.FailingSnapshot.Route

		result.Summary = fmt.Sprintf(
			"Route lookup failed in the failing environment for %s. "+
				"The working environment routed through %s, while the failing "+
				"environment returned: %s. TCP outcome: %s. "+
				"The underlying cause has not yet been confirmed.",
			report.Target.Raw,
			workingRoute.EgressInterface,
			failingRoute.Error,
			fTCP,
		)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Previously Used Interface Is Down or Unavailable",
				SupportLevel: "moderate",
				Rationale:    "An unavailable interface can cause its connected route to become unusable. Interface state needs verification.",
			},
			{
				Title:        "Missing or Incorrect Route",
				SupportLevel: "moderate",
				Rationale:    "The failing environment has no usable route to the destination. The routing table and policy rules should be inspected.",
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_INTERFACE_STATE",
			Parameter: workingRoute.EgressInterface,
			Reason:    "Inspect whether the previously used interface still exists and is UP in the failing environment.",
		}

		return result, nil
	}

	switch primary.Category {
	case "Policy":
		result.Summary = fmt.Sprintf("Policy routing rule divergence is the primary root cause. The working environment routes target traffic through %s via rule '%s', while the failing environment is missing this policy rule and falls back to %s. Because the failing host routes traffic out %s, the connection encountered %s.",
			workingIface, primary.WorkingValue, failingIface, failingIface, fTCP)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Missing or Misordered Policy Routing Rule (ip rule)",
				SupportLevel: "strong",
				Rationale:    fmt.Sprintf("Traffic to destination is not captured by policy routing rules on the failing host, dropping into the main table and physical egress %s instead of %s.", failingIface, workingIface),
			},
			{
				Title:        "Inactive Tunnel Interface or VPN Disconnect",
				SupportLevel: "moderate",
				Rationale:    fmt.Sprintf("If the VPN daemon or tunnel failed to initialize, route rules for %s may not be active.", workingIface),
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_TCP_BIND_INTERFACE",
			Parameter: workingIface,
			Reason:    fmt.Sprintf("Binding TCP socket explicitly to %s on the failing host bypasses policy routing evaluation and tests if the underlying tunnel link is functional.", workingIface),
		}

	case "Interface":
		result.Summary = fmt.Sprintf("Interface link state divergence is the primary observed difference. Interface %s is %s in the working environment, but %s in the failing environment. TCP outcome: %s.",
			workingIface, primary.WorkingValue, primary.FailingValue, fTCP)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Interface Down, Missing, or Disconnected",
				SupportLevel: "strong",
				Rationale:    fmt.Sprintf("The interface required for the egress path is not active on the failing host (%s vs %s).", primary.WorkingValue, primary.FailingValue),
			},
			{
				Title:        "Physical Link or Driver Issue",
				SupportLevel: "moderate",
				Rationale:    "Operational state changes can be caused by carrier loss, unplugged cable, or virtual interface teardown.",
			},
		}

		probeParam := workingIface
		if probeParam == "unspecified" && report.WorkingSnapshot.Interface != nil {
			probeParam = report.WorkingSnapshot.Interface.Name
		}
		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_INTERFACE_STATE",
			Parameter: probeParam,
			Reason:    fmt.Sprintf("Directly inspect interface administrative flags and operational status for %s.", probeParam),
		}

	case "Route":
		if failingIface == "unspecified" {
			result.Summary = fmt.Sprintf("Routing divergence detected for %s. The working environment routes through %s, while the failing environment has no valid route (%s). TCP outcome: %s.",
				report.Target.Raw, workingIface, primary.FailingValue, fTCP)
		} else {
			result.Summary = fmt.Sprintf("Routing divergence is the strongest candidate explanation. The working environment routes through %s while the failing environment routes through %s. Observed TCP outcome: %s.",
				workingIface, failingIface, fTCP)
		}

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Routing Table or Egress Mismatch",
				SupportLevel: "strong",
				Rationale:    fmt.Sprintf("Traffic routing to %s diverges between environments.", report.Target.Raw),
			},
			{
				Title:        "Missing Route or Policy Rule",
				SupportLevel: "moderate",
				Rationale:    "A missing subnet route or policy routing rule causes packets to follow default routing or fail lookup.",
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_TCP_BIND_INTERFACE",
			Parameter: workingIface,
			Reason:    fmt.Sprintf("Binding TCP socket explicitly to %s on the failing host tests whether reachability succeeds over that link.", workingIface),
		}

	case "DNS":
		result.Summary = fmt.Sprintf("DNS resolution divergence occurred upstream before IP routing took place. Working resolved to %s, failing resulted in %s.",
			primary.WorkingValue, primary.FailingValue)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Resolver or DNS Record Divergence",
				SupportLevel: "strong",
				Rationale:    "The destination name is not resolving to the appropriate internal endpoint on the failing host.",
			},
		}

		nameservers := "8.8.8.8"
		if report.WorkingSnapshot.DNS != nil && len(report.WorkingSnapshot.DNS.Nameservers) > 0 {
			nameservers = strings.Join(report.WorkingSnapshot.DNS.Nameservers, ",")
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DNS_WITH_RESOLVER",
			Parameter: nameservers,
			Reason:    "Querying the working host's resolver directly tests if the record exists on that DNS zone.",
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

	case "Firewall":
		result.Summary = fmt.Sprintf("Firewall filter divergence detected. Active packet filtering is present on the failing environment (%s) while TCP connection timed out (working: %s, failing: %s).",
			primary.FailingValue, wTCP, fTCP)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Connection Blocked by Host Packet Filtering (iptables/nftables)",
				SupportLevel: "strong",
				Rationale:    fmt.Sprintf("Host firewall rules are active on the failing host while connection attempts to %s timed out.", report.Target.Raw),
			},
			{
				Title:        "Upstream or Intermediate Firewall Drop",
				SupportLevel: "moderate",
				Rationale:    "An intermediate firewall, security group, or network ACL may also be dropping packets.",
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DIRECT_IP",
			Parameter: report.Target.Host,
			Reason:    "Testing direct IP reachability isolates hostname/domain filtering rules from network interface ACLs.",
		}

	default:
		result.Summary = fmt.Sprintf("Network divergence detected in %s (%s vs %s). This path divergence directly accounts for observed TCP outcome (%s).",
			primary.Category, primary.WorkingValue, primary.FailingValue, fTCP)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        fmt.Sprintf("%s Configuration Divergence", primary.Category),
				SupportLevel: "strong",
				Rationale:    primary.Rationale,
			},
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DIRECT_IP",
			Parameter: report.Target.Host,
			Reason:    "Validates direct IP reachability to isolate transport layer drops from higher layer configurations.",
		}
	}

	return result, nil
}

// callGemini issues a structured generateContent call to Google Gemini REST API.
func (r *Reasoner) callGemini(ctx context.Context, report *model.ComparisonReport) (*ExplanationReport, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", r.Model, r.APIKey)

	prompt := r.buildPrompt(report)

	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]interface{}{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"responseMimeType": "application/json",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal gemini request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create gemini request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini http request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read gemini response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini api returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(respBytes, &geminiResp); err != nil {
		return nil, fmt.Errorf("unmarshal gemini response wrapper: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty candidates returned by gemini")
	}

	rawText := geminiResp.Candidates[0].Content.Parts[0].Text

	var explanation ExplanationReport
	if err := json.Unmarshal([]byte(rawText), &explanation); err != nil {
		return nil, fmt.Errorf("unmarshal explanation JSON from gemini (%s): %w", rawText, err)
	}

	// Validate bounded probe against allowed safe catalog
	if explanation.NextBestProbe != nil {
		if !allowedProbes[explanation.NextBestProbe.ProbeName] {
			// Clamp to safe default if Gemini hallucinates an unsupported probe
			explanation.NextBestProbe.ProbeName = "TEST_TCP_BIND_INTERFACE"
			if report.WorkingSnapshot.Route != nil && report.WorkingSnapshot.Route.EgressInterface != "" {
				explanation.NextBestProbe.Parameter = report.WorkingSnapshot.Route.EgressInterface
			}
			explanation.NextBestProbe.Reason = "Validate connectivity over working interface link."
		}
	}

	return &explanation, nil
}

func (r *Reasoner) buildPrompt(report *model.ComparisonReport) string {
	diffSummary := make([]string, 0)
	for _, d := range report.Differences {
		if d.Relevance == model.RelevanceHigh || d.Relevance == model.RelevanceMedium {
			diffSummary = append(diffSummary, fmt.Sprintf("- [%s] %s: working=%q, failing=%q (rationale: %s)",
				d.Relevance, d.Field, d.WorkingValue, d.FailingValue, d.Rationale))
		}
	}

	wTCP := "none"
	fTCP := "none"
	if report.WorkingSnapshot.TCP != nil {
		wTCP = fmt.Sprintf("status=%s latency=%dms", report.WorkingSnapshot.TCP.Status, report.WorkingSnapshot.TCP.LatencyMs)
	}
	if report.FailingSnapshot.TCP != nil {
		fTCP = fmt.Sprintf("status=%s latency=%dms", report.FailingSnapshot.TCP.Status, report.FailingSnapshot.TCP.LatencyMs)
	}

	return fmt.Sprintf(`You are NetDiff's diagnostic reasoning engine. You are analyzing network path differences for connection target: %s
Working Host: %s (TCP Outcome: %s)
Failing Host: %s (TCP Outcome: %s)
Earliest Root Cause Divergence in DAG: %s

Ranked Differences:
%s

Your task:
1. Synthesize a concise 2-3 sentence executive summary explaining why the connection works in the working environment but fails in the failing environment.
2. Provide 1 to 3 diagnostic hypotheses with support_level ("strong", "moderate", or "weak") and rationale.
3. Recommend ONE next_best_probe selected strictly from this safe fixed catalog:
   - TEST_TCP_BIND_INTERFACE (parameter: interface name like tun0, eth0)
   - TEST_TCP_BIND_SOURCE (parameter: source IP address)
   - TEST_DNS_WITH_RESOLVER (parameter: nameserver IP address)
   - TEST_PROXY_DISABLED (parameter: empty)
   - TEST_DIRECT_IP (parameter: destination IP address)
   - TEST_INTERFACE_STATE (parameter: interface name like eth0, veth-client)

Return ONLY valid JSON matching this schema:
{
  "summary": "...",
  "hypotheses": [
    {
      "title": "...",
      "support_level": "strong|moderate|weak",
      "rationale": "..."
    }
  ],
  "next_best_probe": {
    "probe_name": "TEST_TCP_BIND_INTERFACE",
    "parameter": "tun0",
    "reason": "..."
  }
}`, report.Target.Raw, report.WorkingHost, wTCP, report.FailingHost, fTCP, report.EarliestDivergence, strings.Join(diffSummary, "\n"))
}

// DumpJSON returns pretty JSON representation of the explanation
func (e *ExplanationReport) DumpJSON() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return string(b)
}
