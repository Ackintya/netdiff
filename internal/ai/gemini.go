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

	"netdiff/internal/config"
	"netdiff/pkg/model"
)

// DiagnosticHypothesis represents a reasoned cause with support level.
type DiagnosticHypothesis struct {
	Title         string `json:"title"`
	SupportLevel  string `json:"support_level"` // "strong", "moderate", "weak"
	Rationale     string `json:"rationale"`
	ConfidencePct int    `json:"confidence_pct,omitempty"` // 0-100 visual confidence
}

func supportToConfidence(level string) int {
	switch strings.ToLower(level) {
	case "strong":
		return 85
	case "moderate":
		return 45
	case "weak":
		return 15
	default:
		return 50
	}
}

// DiagnosticProbeChoice is a bounded follow-up test chosen from the safe fixed catalog.
type DiagnosticProbeChoice struct {
	ProbeName string `json:"probe_name"`
	Parameter string `json:"parameter,omitempty"`
	Reason    string `json:"reason"`
}

// RemediationPlan provides copy-pasteable resolution actions for the failing environment.
type RemediationPlan struct {
	ImmediateBash   string `json:"immediate_bash"`
	PermanentConfig string `json:"permanent_config,omitempty"`
	VerificationCmd string `json:"verification_cmd,omitempty"`
	Explanation     string `json:"explanation,omitempty"`
}

// ExplanationReport contains Gemini's structured synthesis over the evidence bundle.
type ExplanationReport struct {
	Summary       string                 `json:"summary"`
	Hypotheses    []DiagnosticHypothesis `json:"hypotheses"`
	Remediation   *RemediationPlan       `json:"remediation,omitempty"`
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
		cfg, _ := config.Load()
		if cfg != nil && cfg.GeminiModel != "" {
			modelName = cfg.GeminiModel
		} else {
			modelName = "gemini-2.5-flash"
		}
	}
	return &Reasoner{
		APIKey: config.GetAPIKey(),
		Model:  modelName,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// HasAPIKey returns true if a Gemini API key is configured in env or config file.
func (r *Reasoner) HasAPIKey() bool {
	return strings.TrimSpace(r.APIKey) != ""
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
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("sudo systemctl status $(ss -tlpn 'sport = :%d' | awk 'NR==2 {print $NF}') || sudo netstat -tlpn | grep %d", report.Target.Port, report.Target.Port),
				PermanentConfig: fmt.Sprintf("Ensure service listening on port %d is enabled and started: sudo systemctl enable --now <service>", report.Target.Port),
				VerificationCmd: fmt.Sprintf("nc -zv %s %d", report.Target.Host, report.Target.Port),
				Explanation:     fmt.Sprintf("TCP RST indicates network reachability is intact but no daemon is accepting connections on port %d.", report.Target.Port),
			}
			result.NextBestProbe = &DiagnosticProbeChoice{
				ProbeName: "TEST_DIRECT_IP",
				Parameter: report.Target.Host,
				Reason:    "Validate reachability to the destination IP directly to confirm endpoint host responsiveness.",
			}
			return finalizeHypotheses(result), nil
		}

		result.Summary = fmt.Sprintf("Both environments share identical network paths to %s. Observed outcomes (working: %s, failing: %s) suggest an intermittent endpoint failure or application-level drop.", report.Target.Raw, wTCP, fTCP)
		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("ip route get %s && ping -c 3 %s", report.Target.Host, report.Target.Host),
			PermanentConfig: "Verify application service health and check /var/log/syslog on destination host.",
			VerificationCmd: fmt.Sprintf("netdiff check %s", report.Target.Raw),
			Explanation:     fmt.Sprintf("Validate direct path reachability and application daemon responsiveness for %s.", report.Target.Raw),
		}
		return finalizeHypotheses(result), nil
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

		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("sudo ip route add %s/32 dev %s", report.Target.Host, workingRoute.EgressInterface),
			PermanentConfig: fmt.Sprintf("Ensure interface %s is UP and routing daemon or VPN client is running.", workingRoute.EgressInterface),
			VerificationCmd: fmt.Sprintf("ip route get %s", report.Target.Host),
			Explanation:     fmt.Sprintf("Restores route towards %s via interface %s after route lookup failure on the failing host.", report.Target.Host, workingRoute.EgressInterface),
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_INTERFACE_STATE",
			Parameter: workingRoute.EgressInterface,
			Reason:    "Inspect whether the previously used interface still exists and is UP in the failing environment.",
		}

		return finalizeHypotheses(result), nil
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

		workingTable := 200
		if report.WorkingSnapshot.Route != nil && report.WorkingSnapshot.Route.Table != 0 {
			workingTable = report.WorkingSnapshot.Route.Table
		}
		targetHost := report.Target.Host
		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("sudo ip rule add to %s/32 lookup %d", targetHost, workingTable),
			PermanentConfig: fmt.Sprintf("# /etc/netplan/99-netdiff-policy.yaml\nnetwork:\n  version: 2\n  ethernets:\n    %s:\n      routing-policy:\n        - to: %s/32\n          table: %d", workingIface, targetHost, workingTable),
			VerificationCmd: fmt.Sprintf("ip rule show | grep %d", workingTable),
			Explanation:     fmt.Sprintf("Adds a policy routing rule directing traffic for %s to table %d, routing via %s instead of fallback default %s.", targetHost, workingTable, workingIface, failingIface),
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

		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("sudo ip link set dev %s up", probeParam),
			PermanentConfig: "sudo systemctl restart systemd-networkd # or: sudo netplan apply",
			VerificationCmd: fmt.Sprintf("ip link show dev %s", probeParam),
			Explanation:     fmt.Sprintf("Brings interface %s administratively UP so network traffic can egress.", probeParam),
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

		gw := ""
		if report.WorkingSnapshot.Route != nil && report.WorkingSnapshot.Route.Gateway != "" {
			gw = fmt.Sprintf(" via %s", report.WorkingSnapshot.Route.Gateway)
		}
		targetHost := report.Target.Host
		permGw := ""
		if gw != "" {
			permGw = fmt.Sprintf("\n          via: %s", strings.TrimPrefix(gw, " via "))
		}
		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("sudo ip route add %s/32%s dev %s", targetHost, gw, workingIface),
			PermanentConfig: fmt.Sprintf("# /etc/netplan/99-netdiff-routes.yaml\nnetwork:\n  version: 2\n  ethernets:\n    %s:\n      routes:\n        - to: %s/32%s", workingIface, targetHost, permGw),
			VerificationCmd: fmt.Sprintf("ip route get %s", targetHost),
			Explanation:     fmt.Sprintf("Installs missing routing table entry for destination %s directing out interface %s.", targetHost, workingIface),
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

		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("sudo resolvectl dns $(ip route show default | awk '{print $5}') %s", nameservers),
			PermanentConfig: fmt.Sprintf("# /etc/systemd/resolved.conf\n[Resolve]\nDNS=%s", nameservers),
			VerificationCmd: fmt.Sprintf("resolvectl query %s", report.Target.Host),
			Explanation:     fmt.Sprintf("Configures the working DNS resolver (%s) so %s resolves correctly.", nameservers, report.Target.Host),
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

		result.Remediation = &RemediationPlan{
			ImmediateBash:   "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY",
			PermanentConfig: "# Remove proxy exports from /etc/environment or ~/.bashrc",
			VerificationCmd: "env | grep -i proxy || echo 'Proxy cleared'",
			Explanation:     "Removes proxy environment variables that intercept and drop outbound socket connections.",
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

		port := report.Target.Port
		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("sudo iptables -D OUTPUT -p tcp --dport %d -j DROP", port),
			PermanentConfig: "# Save rules after deletion\nsudo iptables-save > /etc/iptables/rules.v4",
			VerificationCmd: fmt.Sprintf("sudo iptables -L OUTPUT -n -v | grep %d || echo 'No blocking rule'", port),
			Explanation:     fmt.Sprintf("Removes the iptables DROP rule blocking outbound TCP traffic to port %d.", port),
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DIRECT_IP",
			Parameter: report.Target.Host,
			Reason:    "Testing direct IP reachability isolates hostname/domain filtering rules from network interface ACLs.",
		}

	case "Neighbor":
		targetIP := report.Target.Host
		if report.WorkingSnapshot.Neighbor != nil && report.WorkingSnapshot.Neighbor.IP != "" {
			targetIP = report.WorkingSnapshot.Neighbor.IP
		} else if report.FailingSnapshot.Neighbor != nil && report.FailingSnapshot.Neighbor.IP != "" {
			targetIP = report.FailingSnapshot.Neighbor.IP
		}
		result.Summary = fmt.Sprintf("Layer 2 neighbor resolution (ARP/NDP) failure is the primary root cause. IP routing succeeded, but the failing host cannot resolve the MAC address for next-hop %s (state: %s). Observed TCP outcome: %s.",
			targetIP, primary.FailingValue, fTCP)

		result.Hypotheses = []DiagnosticHypothesis{
			{
				Title:        "Gateway or Next-Hop Unreachable (ARP Resolution Failed)",
				SupportLevel: "strong",
				Rationale:    fmt.Sprintf("The next-hop IP (%s) exists in the routing table, but neighbor state is %s with no MAC address. The target host or router may be offline, powered down, or unreachable on the physical/virtual wire.", targetIP, primary.FailingValue),
			},
			{
				Title:        "Layer 2 Network Isolation or VLAN Mismatch",
				SupportLevel: "moderate",
				Rationale:    "Broadcast ARP requests are not receiving a response, possibly due to switch port isolation, security ACLs, or an incorrect VLAN tag.",
			},
		}

		neighIP := targetIP
		workingMAC := ""
		if report.WorkingSnapshot.Neighbor != nil && report.WorkingSnapshot.Neighbor.MAC != "" {
			workingMAC = report.WorkingSnapshot.Neighbor.MAC
		}
		if workingMAC != "" {
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("sudo ip neigh replace %s lladdr %s dev %s nud reachable", neighIP, workingMAC, workingIface),
				PermanentConfig: fmt.Sprintf("Verify Layer 2 switch port VLAN tag and physical connectivity for %s.", workingIface),
				VerificationCmd: fmt.Sprintf("ip neigh show %s", neighIP),
				Explanation:     fmt.Sprintf("Installs the working MAC address (%s) for next-hop %s into the kernel ARP table.", workingMAC, neighIP),
			}
		} else {
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("sudo ip neigh flush to %s dev %s && arping -c 3 -I %s %s", neighIP, failingIface, failingIface, neighIP),
				PermanentConfig: fmt.Sprintf("Verify switch port isolation, security ACLs, or VLAN tags for next-hop %s.", neighIP),
				VerificationCmd: fmt.Sprintf("ip neigh show %s", neighIP),
				Explanation:     fmt.Sprintf("Flushes stale ARP entry and broadcasts ARP requests to re-learn next hop %s MAC address.", neighIP),
			}
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DIRECT_IP",
			Parameter: targetIP,
			Reason:    "Validate whether the next-hop IP responds to direct IP ICMP/ping or if Layer 2 is completely unmapped.",
		}

	case "TLS":
		fTLS := report.FailingSnapshot.TLS
		errStr := "handshake failed"
		errCat := "handshake_failed"
		if fTLS != nil && fTLS.Error != "" {
			errStr = fTLS.Error
			errCat = fTLS.ErrorCategory
		}

		switch errCat {
		case "untrusted_root":
			result.Summary = fmt.Sprintf("TLS certificate verification failure for %s. TCP connection succeeded, but TLS handshake failed because the certificate authority is untrusted on the failing host: %s.", report.Target.Raw, errStr)
			result.Hypotheses = []DiagnosticHypothesis{
				{
					Title:        "Missing Root CA in System Trust Store",
					SupportLevel: "strong",
					Rationale:    "The endpoint presented a certificate signed by an authority missing from the failing host's CA trust store. This commonly happens in minimal container images missing ca-certificates or private internal PKI roots.",
				},
				{
					Title:        "Self-Signed or Custom CA Certificate",
					SupportLevel: "moderate",
					Rationale:    "If the endpoint uses a self-signed certificate, the client requires explicit CA bundle configuration.",
				},
			}
			result.Remediation = &RemediationPlan{
				ImmediateBash:   "sudo cp <ca-cert.crt> /usr/local/share/ca-certificates/ && sudo update-ca-certificates",
				PermanentConfig: "Include ca-certificates and private corporate CA bundle in base container/VM image build.",
				VerificationCmd: fmt.Sprintf("openssl s_client -connect %s:%d -servername %s < /dev/null", report.Target.Host, report.Target.Port, report.Target.Host),
				Explanation:     fmt.Sprintf("Installs missing Certificate Authority root certificate into the system trust store on %s.", report.FailingHost),
			}
		case "expired":
			result.Summary = fmt.Sprintf("TLS certificate expired for %s. TCP transport succeeded, but TLS validation rejected the expired certificate: %s.", report.Target.Raw, errStr)
			result.Hypotheses = []DiagnosticHypothesis{
				{
					Title:        "Expired TLS Certificate on Endpoint",
					SupportLevel: "strong",
					Rationale:    fmt.Sprintf("The TLS certificate served by %s has expired and fails standard x509 validation.", report.Target.Raw),
				},
			}
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("# Renew or replace expired TLS certificate on endpoint %s", report.Target.Host),
				PermanentConfig: "Configure cert-manager or automated ACME cert renewal.",
				VerificationCmd: fmt.Sprintf("openssl s_client -connect %s:%d -servername %s 2>/dev/null | openssl x509 -noout -dates", report.Target.Host, report.Target.Port, report.Target.Host),
				Explanation:     fmt.Sprintf("The TLS certificate served by %s has expired and must be renewed on the server endpoint.", report.Target.Host),
			}
		case "hostname_mismatch":
			result.Summary = fmt.Sprintf("TLS certificate hostname mismatch for %s. TCP connection succeeded, but the certificate does not match requested host: %s.", report.Target.Raw, errStr)
			result.Hypotheses = []DiagnosticHypothesis{
				{
					Title:        "Certificate Subject Alternative Name (SAN) Mismatch",
					SupportLevel: "strong",
					Rationale:    fmt.Sprintf("The certificate presented by the server does not cover hostname %q.", report.Target.Host),
				},
			}
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("openssl s_client -connect %s:%d -servername %s", report.Target.Host, report.Target.Port, report.Target.Host),
				PermanentConfig: "Re-issue certificate with Subject Alternative Name (SAN) including " + report.Target.Host,
				VerificationCmd: fmt.Sprintf("openssl s_client -connect %s:%d -servername %s < /dev/null", report.Target.Host, report.Target.Port, report.Target.Host),
				Explanation:     "Update server certificate SAN to match the connecting domain name.",
			}
		default:
			result.Summary = fmt.Sprintf("TLS handshake failure for %s. Bidirectional TCP transport succeeded, but TLS negotiation failed: %s.", report.Target.Raw, errStr)
			result.Hypotheses = []DiagnosticHypothesis{
				{
					Title:        "TLS Protocol Version or Cipher Suite Mismatch",
					SupportLevel: "strong",
					Rationale:    fmt.Sprintf("Client and server failed to negotiate a mutually supported TLS version or cipher suite: %s.", errStr),
				},
			}
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("openssl s_client -connect %s:%d -servername %s -tls1_3", report.Target.Host, report.Target.Port, report.Target.Host),
				PermanentConfig: "Ensure TLS 1.2 and TLS 1.3 ciphers are enabled in the client application configuration.",
				VerificationCmd: fmt.Sprintf("openssl s_client -connect %s:%d -servername %s < /dev/null", report.Target.Host, report.Target.Port, report.Target.Host),
				Explanation:     "Check TLS handshake parameters and cipher suite compatibility between client and server.",
			}
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DIRECT_IP",
			Parameter: report.Target.Host,
			Reason:    "Validate direct IP reachability without TLS to isolate application transport from encryption handshake.",
		}

	case "TCP":
		if primary.Field == "retransmits" {
			result.Summary = fmt.Sprintf("Kernel socket telemetry detected packet retransmissions on the failing host (%s). Bidirectional TCP transport was established, but packets are dropping along the network path.", primary.FailingValue)
			result.Hypotheses = []DiagnosticHypothesis{
				{
					Title:        "Intermediate Network Congestion or Packet Loss",
					SupportLevel: "strong",
					Rationale:    fmt.Sprintf("Kernel socket telemetry tracked %s on the failing connection. This indicates link buffer overruns, flaky switches, or intermediate firewall state table drops.", primary.FailingValue),
				},
				{
					Title:        "Asymmetric Routing or Path MTU Issues",
					SupportLevel: "moderate",
					Rationale:    "Path MTU black holes or asymmetric return path drops can trigger repeated packet retransmissions.",
				},
			}
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("sudo ethtool -S %s | grep -E 'drop|error|miss|discard'", failingIface),
				PermanentConfig: "Check intermediate switch interfaces for CRC errors or path MTU blackholes.",
				VerificationCmd: fmt.Sprintf("ss -ti dst %s", report.Target.Host),
				Explanation:     fmt.Sprintf("Monitors interface driver drop counters to isolate physical or buffer overruns on %s.", failingIface),
			}
			result.NextBestProbe = &DiagnosticProbeChoice{
				ProbeName: "TEST_DIRECT_IP",
				Parameter: report.Target.Host,
				Reason:    "Test direct ICMP reachability and loss to isolate transport loss from higher layer protocols.",
			}
		} else {
			result.Summary = fmt.Sprintf("TCP connection failure: working was %s while failing encountered %s.", primary.WorkingValue, primary.FailingValue)
			result.Hypotheses = []DiagnosticHypothesis{
				{
					Title:        "TCP Port Unreachable or Refused",
					SupportLevel: "strong",
					Rationale:    primary.Rationale,
				},
			}
			result.Remediation = &RemediationPlan{
				ImmediateBash:   fmt.Sprintf("nc -zv %s %d", report.Target.Host, report.Target.Port),
				PermanentConfig: fmt.Sprintf("Check remote firewall security groups allowing inbound traffic on port %d.", report.Target.Port),
				VerificationCmd: fmt.Sprintf("netdiff check %s", report.Target.Raw),
				Explanation:     fmt.Sprintf("Test TCP transport reachability directly to destination %s.", report.Target.Raw),
			}
			result.NextBestProbe = &DiagnosticProbeChoice{
				ProbeName: "TEST_DIRECT_IP",
				Parameter: report.Target.Host,
				Reason:    "Validate direct IP reachability to isolate transport layer drops.",
			}
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

		result.Remediation = &RemediationPlan{
			ImmediateBash:   fmt.Sprintf("ip route get %s && ping -c 2 %s", report.Target.Host, report.Target.Host),
			PermanentConfig: "Align network configuration with working baseline host.",
			VerificationCmd: fmt.Sprintf("netdiff check %s", report.Target.Raw),
			Explanation:     fmt.Sprintf("Validate basic reachability and route path towards %s.", report.Target.Raw),
		}

		result.NextBestProbe = &DiagnosticProbeChoice{
			ProbeName: "TEST_DIRECT_IP",
			Parameter: report.Target.Host,
			Reason:    "Validates direct IP reachability to isolate transport layer drops from higher layer configurations.",
		}
	}

	return finalizeHypotheses(result), nil
}

func finalizeHypotheses(result *ExplanationReport) *ExplanationReport {
	if result == nil {
		return nil
	}
	for i := range result.Hypotheses {
		if result.Hypotheses[i].ConfidencePct == 0 {
			result.Hypotheses[i].ConfidencePct = supportToConfidence(result.Hypotheses[i].SupportLevel)
		}
	}
	return result
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
			"responseSchema": map[string]interface{}{
				"type": "OBJECT",
				"properties": map[string]interface{}{
					"summary": map[string]interface{}{
						"type": "STRING",
					},
					"hypotheses": map[string]interface{}{
						"type": "ARRAY",
						"items": map[string]interface{}{
							"type": "OBJECT",
							"properties": map[string]interface{}{
								"title": map[string]interface{}{
									"type": "STRING",
								},
								"support_level": map[string]interface{}{
									"type": "STRING",
									"enum": []string{"strong", "moderate", "weak"},
								},
								"rationale": map[string]interface{}{
									"type": "STRING",
								},
								"confidence_pct": map[string]interface{}{
									"type": "INTEGER",
								},
							},
							"required": []string{"title", "support_level", "rationale"},
						},
					},
					"remediation": map[string]interface{}{
						"type": "OBJECT",
						"properties": map[string]interface{}{
							"immediate_bash": map[string]interface{}{
								"type": "STRING",
							},
							"permanent_config": map[string]interface{}{
								"type": "STRING",
							},
							"verification_cmd": map[string]interface{}{
								"type": "STRING",
							},
							"explanation": map[string]interface{}{
								"type": "STRING",
							},
						},
						"required": []string{"immediate_bash", "explanation"},
					},
					"next_best_probe": map[string]interface{}{
						"type": "OBJECT",
						"properties": map[string]interface{}{
							"probe_name": map[string]interface{}{
								"type": "STRING",
								"enum": []string{
									"TEST_TCP_BIND_INTERFACE",
									"TEST_TCP_BIND_SOURCE",
									"TEST_DNS_WITH_RESOLVER",
									"TEST_PROXY_DISABLED",
									"TEST_DIRECT_IP",
									"TEST_INTERFACE_STATE",
								},
							},
							"parameter": map[string]interface{}{
								"type": "STRING",
							},
							"reason": map[string]interface{}{
								"type": "STRING",
							},
						},
						"required": []string{"probe_name", "reason"},
					},
				},
				"required": []string{"summary", "hypotheses"},
			},
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

	finalizeHypotheses(&explanation)

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
3. Provide an actionable remediation plan for the failing host:
   - immediate_bash: An exact, safe, copy-pasteable bash command to resolve or work around the issue.
   - permanent_config: Permanent config snippet (e.g. Netplan YAML, systemd-networkd, or iptables-save).
   - verification_cmd: Exact command to verify the fix succeeded.
   - explanation: 1 sentence explaining why this resolves the divergence.
4. Recommend ONE next_best_probe selected strictly from this safe fixed catalog:
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
  "remediation": {
    "immediate_bash": "...",
    "permanent_config": "...",
    "verification_cmd": "...",
    "explanation": "..."
  },
  "next_best_probe": {
    "probe_name": "TEST_TCP_BIND_INTERFACE",
    "parameter": "tun0",
    "reason": "..."
  }
}`, report.Target.Raw, report.WorkingHost, wTCP, report.FailingHost, fTCP, report.EarliestDivergence, strings.Join(diffSummary, "\n"))
}

// Ask answers an operator's natural language debugging question grounded strictly in snapshot evidence.
func (r *Reasoner) Ask(ctx context.Context, report *model.ComparisonReport, question string) (string, error) {
	if r.APIKey != "" {
		ans, err := r.callGeminiAsk(ctx, report, question)
		if err == nil && strings.TrimSpace(ans) != "" {
			return ans, nil
		}
	}
	return r.askDeterministic(report, question), nil
}

// callGeminiAsk queries Gemini with the comparison evidence and operator question.
func (r *Reasoner) callGeminiAsk(ctx context.Context, report *model.ComparisonReport, question string) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", r.Model, r.APIKey)

	prompt := r.buildAskPrompt(report, question)

	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]interface{}{
					{"text": prompt},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal ask request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create ask request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("gemini ask http request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read ask response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini api returned status %d: %s", resp.StatusCode, string(respBytes))
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
		return "", fmt.Errorf("unmarshal gemini ask response: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty candidates returned by gemini")
	}

	return strings.TrimSpace(geminiResp.Candidates[0].Content.Parts[0].Text), nil
}

func (r *Reasoner) buildAskPrompt(report *model.ComparisonReport, question string) string {
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
		fTCP = fmt.Sprintf("status=%s latency=%dms error=%s", report.FailingSnapshot.TCP.Status, report.FailingSnapshot.TCP.LatencyMs, report.FailingSnapshot.TCP.Error)
	}

	return fmt.Sprintf(`You are NetDiff's senior network reliability engineering assistant.
The operator is investigating a network connection failure by comparing two snapshot captures (.ndiff).

Connection Target: %s (Port: %d, Protocol: %s)
Working Host: %s (Outcome: %s)
Failing Host: %s (Outcome: %s)
Earliest Root Cause in DAG: %s

Differences Found:
%s

Operator Question:
"%s"

CRITICAL INSTRUCTIONS:
1. Answer the question strictly using the empirical snapshot evidence provided above.
2. If the snapshot evidence contains the answer, explain it clearly with exact values (interfaces, IP rules, routes, etc.).
3. If the snapshot does not contain sufficient data to answer definitively, explicitly state what is missing and provide the exact Linux command (e.g. ss, ip, iptables, tcpdump) or NetDiff probe to check.
4. Keep the answer direct, concise, and technically rigorous.
5. Format cleanly for terminal viewing (use bullet points or indented bash blocks if providing commands).`,
		report.Target.Raw, report.Target.Port, report.Target.Protocol,
		report.WorkingHost, wTCP,
		report.FailingHost, fTCP,
		report.EarliestDivergence,
		strings.Join(diffSummary, "\n"),
		question,
	)
}

func (r *Reasoner) askDeterministic(report *model.ComparisonReport, question string) string {
	q := strings.ToLower(question)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Based on NetDiff snapshot comparison for %s:\n\n", report.Target.Raw))

	if report.EarliestDivergence != "" {
		sb.WriteString(fmt.Sprintf("● Root Cause (Earliest Divergence): %s\n", report.EarliestDivergence))
	}

	wTCP := "unknown"
	fTCP := "unknown"
	if report.WorkingSnapshot.TCP != nil {
		wTCP = string(report.WorkingSnapshot.TCP.Status)
	}
	if report.FailingSnapshot.TCP != nil {
		fTCP = string(report.FailingSnapshot.TCP.Status)
	}
	sb.WriteString(fmt.Sprintf("● Outcomes: Working=%s (%s), Failing=%s (%s)\n\n", report.WorkingHost, wTCP, report.FailingHost, fTCP))

	// Search for relevant differences matching question keywords
	matchedDiffs := 0
	for _, d := range report.Differences {
		cat := strings.ToLower(d.Category)
		field := strings.ToLower(d.Field)
		if strings.Contains(q, cat) || strings.Contains(q, field) ||
			(strings.Contains(q, "firewall") && cat == "firewall") ||
			(strings.Contains(q, "rule") && cat == "policy") ||
			(strings.Contains(q, "route") && cat == "route") ||
			(strings.Contains(q, "interface") && cat == "interface") ||
			(strings.Contains(q, "arp") && cat == "neighbor") ||
			(strings.Contains(q, "cert") && cat == "tls") ||
			(strings.Contains(q, "dns") && cat == "dns") {
			sb.WriteString(fmt.Sprintf("- [%s] %s: working=%q, failing=%q\n  %s\n", d.Category, d.Field, d.WorkingValue, d.FailingValue, d.Rationale))
			matchedDiffs++
		}
	}

	if matchedDiffs == 0 {
		for _, d := range report.Differences {
			if d.Relevance == model.RelevanceHigh {
				sb.WriteString(fmt.Sprintf("- [%s] %s: working=%q, failing=%q\n  %s\n", d.Category, d.Field, d.WorkingValue, d.FailingValue, d.Rationale))
				matchedDiffs++
			}
		}
	}

	if strings.Contains(q, "fix") || strings.Contains(q, "remediat") || strings.Contains(q, "how to") {
		exp, _ := r.explainDeterministic(report)
		if exp != nil && exp.Remediation != nil {
			sb.WriteString("\nRecommended Remediation:\n")
			sb.WriteString(fmt.Sprintf("  $ %s\n", exp.Remediation.ImmediateBash))
			if exp.Remediation.VerificationCmd != "" {
				sb.WriteString(fmt.Sprintf("  Verify: $ %s\n", exp.Remediation.VerificationCmd))
			}
		}
	}

	if r.APIKey == "" {
		sb.WriteString("\n(Note: Set GEMINI_API_KEY environment variable to enable open-ended natural language reasoning).")
	}

	return sb.String()
}

// DumpJSON returns pretty JSON representation of the explanation
func (e *ExplanationReport) DumpJSON() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return string(b)
}
