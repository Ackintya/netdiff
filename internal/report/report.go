package report

import (
	"fmt"
	"strings"
	"time"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

// GenerateMarkdown generates a structured incident markdown report suitable for
// Slack, Jira, GitHub issues, or network escalation.
func GenerateMarkdown(comp *model.ComparisonReport, exp *ai.ExplanationReport) string {
	var sb strings.Builder

	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	sb.WriteString(fmt.Sprintf("# NetDiff Incident Report: %s\n\n", comp.Target.Raw))
	sb.WriteString(fmt.Sprintf("- **Generated:** %s\n", now))
	sb.WriteString(fmt.Sprintf("- **Target:** `%s` (Port: %d, Protocol: %s)\n", comp.Target.Raw, comp.Target.Port, comp.Target.Protocol))
	sb.WriteString(fmt.Sprintf("- **Working Host:** `%s` (%s)\n", comp.WorkingHost, comp.WorkingSnapshot.Metadata.OS))
	sb.WriteString(fmt.Sprintf("- **Failing Host:** `%s` (%s)\n\n", comp.FailingHost, comp.FailingSnapshot.Metadata.OS))

	sb.WriteString("## 1. Executive Summary\n\n")
	if exp != nil && exp.Summary != "" {
		sb.WriteString(exp.Summary + "\n\n")
	} else if comp.Summary != "" {
		sb.WriteString(comp.Summary + "\n\n")
	} else {
		sb.WriteString("Network path analysis completed between working and failing environments.\n\n")
	}

	sb.WriteString("## 2. Root Cause & Earliest Divergence\n\n")
	if comp.EarliestDivergence != "" {
		sb.WriteString(fmt.Sprintf("> **Root Cause Identified (Earliest Divergence):** `%s`\n\n", comp.EarliestDivergence))
		sb.WriteString("The dependency graph determined that this divergence occurred earliest in the network path, propagating downstream into the observed connection failure.\n\n")
	} else {
		sb.WriteString("No upstream divergence identified in the dependency graph.\n\n")
	}

	sb.WriteString("## 3. Network Path Comparison\n\n")
	sb.WriteString("| Component | Working (" + comp.WorkingHost + ") | Failing (" + comp.FailingHost + ") | Status |\n")
	sb.WriteString("|:---|:---|:---|:---:|\n")

	// DNS
	if comp.WorkingSnapshot.DNS != nil || comp.FailingSnapshot.DNS != nil {
		wDNS := formatDNS(comp.WorkingSnapshot.DNS)
		fDNS := formatDNS(comp.FailingSnapshot.DNS)
		status := "✓ Same"
		if wDNS != fDNS {
			status = "⚠ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **DNS Resolution** | `%s` | `%s` | %s |\n", wDNS, fDNS, status))
	}

	// Policy Rule
	wRule := "default (main)"
	if comp.WorkingSnapshot.Route != nil && comp.WorkingSnapshot.Route.PolicyRule != "" {
		wRule = comp.WorkingSnapshot.Route.PolicyRule
	}
	fRule := "default (main)"
	if comp.FailingSnapshot.Route != nil && comp.FailingSnapshot.Route.PolicyRule != "" {
		fRule = comp.FailingSnapshot.Route.PolicyRule
	}
	if wRule != "default (main)" || fRule != "default (main)" {
		status := "✓ Same"
		if wRule != fRule {
			status = "⚠ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **Policy Routing Rule** | `%s` | `%s` | %s |\n", wRule, fRule, status))
	}

	// Route Lookup Outcome
	if comp.WorkingSnapshot.Route != nil && comp.FailingSnapshot.Route != nil {
		wR := comp.WorkingSnapshot.Route
		fR := comp.FailingSnapshot.Route

		wLookupStr := formatRouteLookup(wR)
		fLookupStr := formatRouteLookup(fR)
		statusLookup := "✓ Same"
		if wLookupStr != fLookupStr {
			statusLookup = "⚠ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **Route Lookup** | `%s` | `%s` | %s |\n", wLookupStr, fLookupStr, statusLookup))

		wRouteStr := fmt.Sprintf("%s (table %d)", wR.EgressInterface, wR.Table)
		if wLookupStr != "success" {
			wRouteStr = fmt.Sprintf("none (%s)", wLookupStr)
		}
		fRouteStr := fmt.Sprintf("%s (table %d)", fR.EgressInterface, fR.Table)
		if fLookupStr != "success" {
			fRouteStr = fmt.Sprintf("none (%s)", fLookupStr)
		}
		status := "✓ Same"
		if wRouteStr != fRouteStr {
			status = "⚠ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **Route Egress** | `%s` | `%s` | %s |\n", wRouteStr, fRouteStr, status))

		if wR.Gateway != "" || fR.Gateway != "" {
			wGw := wR.Gateway
			if wGw == "" {
				wGw = "on-link"
			}
			fGw := fR.Gateway
			if fGw == "" {
				fGw = "on-link"
			}
			statusGw := "✓ Same"
			if wGw != fGw {
				statusGw = "⚠ Divergent"
			}
			sb.WriteString(fmt.Sprintf("| **Next-Hop Gateway** | `%s` | `%s` | %s |\n", wGw, fGw, statusGw))
		}

		if wR.PreferredSource != "" || fR.PreferredSource != "" {
			wSrc := wR.PreferredSource
			fSrc := fR.PreferredSource
			statusSrc := "✓ Same"
			if wSrc != fSrc {
				statusSrc = "⚠ Divergent"
			}
			sb.WriteString(fmt.Sprintf("| **Source Address** | `%s` | `%s` | %s |\n", wSrc, fSrc, statusSrc))
		}
	}

	// Interface Link State
	if comp.WorkingSnapshot.Interface != nil || comp.FailingSnapshot.Interface != nil {
		wIface := "unavailable"
		if comp.WorkingSnapshot.Interface != nil {
			wIface = fmt.Sprintf("%s (%s, operstate: %s)", comp.WorkingSnapshot.Interface.Name, strings.Join(comp.WorkingSnapshot.Interface.Flags, "|"), comp.WorkingSnapshot.Interface.OperState)
		}
		fIface := "unavailable"
		if comp.FailingSnapshot.Interface != nil {
			fIface = fmt.Sprintf("%s (%s, operstate: %s)", comp.FailingSnapshot.Interface.Name, strings.Join(comp.FailingSnapshot.Interface.Flags, "|"), comp.FailingSnapshot.Interface.OperState)
		}
		statusIface := "✓ Same"
		if wIface != fIface {
			statusIface = "⚠ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **Interface Link** | `%s` | `%s` | %s |\n", wIface, fIface, statusIface))
	}

	// Neighbor Table / ARP
	if comp.WorkingSnapshot.Neighbor != nil || comp.FailingSnapshot.Neighbor != nil {
		wNeigh := "none"
		if comp.WorkingSnapshot.Neighbor != nil && comp.WorkingSnapshot.Neighbor.IP != "" {
			wNeigh = fmt.Sprintf("%s → %s (%s)", comp.WorkingSnapshot.Neighbor.IP, comp.WorkingSnapshot.Neighbor.MAC, comp.WorkingSnapshot.Neighbor.State)
		}
		fNeigh := "none"
		if comp.FailingSnapshot.Neighbor != nil && comp.FailingSnapshot.Neighbor.IP != "" {
			fNeigh = fmt.Sprintf("%s → %s (%s)", comp.FailingSnapshot.Neighbor.IP, comp.FailingSnapshot.Neighbor.MAC, comp.FailingSnapshot.Neighbor.State)
		}
		statusNeigh := "✓ Same"
		if wNeigh != fNeigh {
			statusNeigh = "⚠ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **Neighbor ARP/NDP** | `%s` | `%s` | %s |\n", wNeigh, fNeigh, statusNeigh))
	}

	// Firewall Filtering
	if (comp.WorkingSnapshot.Firewall != nil && comp.WorkingSnapshot.Firewall.Active) ||
		(comp.FailingSnapshot.Firewall != nil && comp.FailingSnapshot.Firewall.Active) {
		wFw := "inactive"
		if comp.WorkingSnapshot.Firewall != nil && comp.WorkingSnapshot.Firewall.Active {
			wFw = fmt.Sprintf("active (%s)", comp.WorkingSnapshot.Firewall.Backend)
		}
		fFw := "inactive"
		if comp.FailingSnapshot.Firewall != nil && comp.FailingSnapshot.Firewall.Active {
			fFw = fmt.Sprintf("active (%s)", comp.FailingSnapshot.Firewall.Backend)
		}
		statusFw := "✓ Same"
		if wFw != fFw {
			statusFw = "⚠ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **Host Firewall** | `%s` | `%s` | %s |\n", wFw, fFw, statusFw))
	}

	// TCP
	if comp.WorkingSnapshot.TCP != nil && comp.FailingSnapshot.TCP != nil {
		wTCP := comp.WorkingSnapshot.TCP
		fTCP := comp.FailingSnapshot.TCP
		wStatus := fmt.Sprintf("%s (%dms)", wTCP.Status, wTCP.LatencyMs)
		if wTCP.SocketInfo != nil && wTCP.SocketInfo.TotalRetrans > 0 {
			wStatus += fmt.Sprintf(" [%d retrans]", wTCP.SocketInfo.TotalRetrans)
		}
		fStatus := string(fTCP.Status)
		if fTCP.LatencyMs > 0 {
			fStatus = fmt.Sprintf("%s (%dms)", fTCP.Status, fTCP.LatencyMs)
		}
		if fTCP.SocketInfo != nil && fTCP.SocketInfo.TotalRetrans > 0 {
			fStatus += fmt.Sprintf(" [%d retrans]", fTCP.SocketInfo.TotalRetrans)
		}
		statusTCP := "✓ Same"
		if wStatus != fStatus {
			statusTCP = "✗ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **TCP Connection** | `%s` | `%s` | %s |\n", wStatus, fStatus, statusTCP))
	}

	// TLS Handshake
	if comp.WorkingSnapshot.TLS != nil || comp.FailingSnapshot.TLS != nil {
		wTLS := "none"
		if comp.WorkingSnapshot.TLS != nil {
			if comp.WorkingSnapshot.TLS.HandshakeSuccess {
				wTLS = fmt.Sprintf("success (%s, %s)", comp.WorkingSnapshot.TLS.Version, comp.WorkingSnapshot.TLS.CipherSuite)
			} else {
				wTLS = fmt.Sprintf("failed: %s", comp.WorkingSnapshot.TLS.Error)
			}
		}
		fTLS := "none"
		if comp.FailingSnapshot.TLS != nil {
			if comp.FailingSnapshot.TLS.HandshakeSuccess {
				fTLS = fmt.Sprintf("success (%s, %s)", comp.FailingSnapshot.TLS.Version, comp.FailingSnapshot.TLS.CipherSuite)
			} else {
				fTLS = fmt.Sprintf("failed: %s", comp.FailingSnapshot.TLS.Error)
			}
		}
		statusTLS := "✓ Same"
		if wTLS != fTLS {
			statusTLS = "✗ Divergent"
		}
		sb.WriteString(fmt.Sprintf("| **TLS Handshake** | `%s` | `%s` | %s |\n", wTLS, fTLS, statusTLS))
	}

	sb.WriteString("\n## 4. Ranked Key Differences\n\n")
	hasDiffs := false
	for _, d := range comp.Differences {
		if d.Relevance == model.RelevanceHigh || d.Relevance == model.RelevanceMedium {
			hasDiffs = true
			badge := "HIGH"
			if d.Relevance == model.RelevanceMedium {
				badge = "MEDIUM"
			}
			sb.WriteString(fmt.Sprintf("- **[%s] %s**: %s\n", badge, d.Category, d.Rationale))
			sb.WriteString(fmt.Sprintf("  - *Working:* `%s`\n", d.WorkingValue))
			sb.WriteString(fmt.Sprintf("  - *Failing:* `%s`\n\n", d.FailingValue))
		}
	}
	if !hasDiffs {
		sb.WriteString("No high or medium relevance differences identified.\n\n")
	}

	if exp != nil && len(exp.Hypotheses) > 0 {
		sb.WriteString("## 5. Diagnostic Hypotheses\n\n")
		for i, h := range exp.Hypotheses {
			sb.WriteString(fmt.Sprintf("%d. **%s** (`%s` confidence)\n   %s\n\n", i+1, h.Title, strings.ToUpper(h.SupportLevel), h.Rationale))
		}
	}

	if exp != nil && exp.NextBestProbe != nil {
		sb.WriteString("## 6. Recommended Validation & Remediation\n\n")
		sb.WriteString(fmt.Sprintf("- **Validation Probe:** `%s(%s)`\n", exp.NextBestProbe.ProbeName, exp.NextBestProbe.Parameter))
		sb.WriteString(fmt.Sprintf("- **Rationale:** %s\n\n", exp.NextBestProbe.Reason))
		sb.WriteString("To execute this safe diagnostic probe immediately:\n")
		if exp.NextBestProbe.ProbeName == "TEST_INTERFACE_STATE" {
			sb.WriteString(fmt.Sprintf("```bash\nnetdiff probe %s %s\n```\n\n", exp.NextBestProbe.ProbeName, exp.NextBestProbe.Parameter))
		} else {
			sb.WriteString(fmt.Sprintf("```bash\nnetdiff probe %s %s -t %s\n```\n\n", exp.NextBestProbe.ProbeName, exp.NextBestProbe.Parameter, comp.Target.Raw))
		}
	}

	if exp != nil && exp.Remediation != nil {
		sb.WriteString("## 7. Actionable Remediation Playbook\n\n")
		if exp.Remediation.ImmediateBash != "" {
			sb.WriteString("**Immediate Fix (Failing Host):**\n```bash\n" + exp.Remediation.ImmediateBash + "\n```\n\n")
		}
		if exp.Remediation.PermanentConfig != "" {
			sb.WriteString("**Permanent Configuration:**\n```yaml\n" + exp.Remediation.PermanentConfig + "\n```\n\n")
		}
		if exp.Remediation.VerificationCmd != "" {
			sb.WriteString("**Verification Command:**\n```bash\n" + exp.Remediation.VerificationCmd + "\n```\n\n")
		}
		if exp.Remediation.Explanation != "" {
			sb.WriteString(fmt.Sprintf("> **Why this resolves the divergence:** %s\n\n", exp.Remediation.Explanation))
		}
	}

	return sb.String()
}

func formatDNS(dns *model.DNSReport) string {
	if dns == nil {
		return "none"
	}
	if !dns.Success {
		return fmt.Sprintf("failed (%s)", dns.Error)
	}
	if len(dns.ARecords) > 0 {
		return strings.Join(dns.ARecords, ", ")
	}
	return "resolved"
}

func formatRouteLookup(r *model.RouteReport) string {
	if r == nil {
		return "unknown"
	}
	if r.Success {
		return "success"
	}
	if r.Error != "" {
		return "failed: " + r.Error
	}
	if r.EgressInterface != "" {
		return "success"
	}
	return "failed"
}
