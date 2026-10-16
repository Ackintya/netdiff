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
		sb.WriteString(fmt.Sprintf("> **Root Cause Identified:** `%s`\n\n", comp.EarliestDivergence))
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

	// Routing Table & Gateway
	if comp.WorkingSnapshot.Route != nil && comp.FailingSnapshot.Route != nil {
		wR := comp.WorkingSnapshot.Route
		fR := comp.FailingSnapshot.Route
		wRouteStr := fmt.Sprintf("%s (table %d)", wR.EgressInterface, wR.Table)
		fRouteStr := fmt.Sprintf("%s (table %d)", fR.EgressInterface, fR.Table)
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

	// TCP
	if comp.WorkingSnapshot.TCP != nil && comp.FailingSnapshot.TCP != nil {
		wTCP := comp.WorkingSnapshot.TCP
		fTCP := comp.FailingSnapshot.TCP
		wStatus := fmt.Sprintf("%s (%dms)", wTCP.Status, wTCP.LatencyMs)
		fStatus := string(fTCP.Status)
		if fTCP.LatencyMs > 0 {
			fStatus = fmt.Sprintf("%s (%dms)", fTCP.Status, fTCP.LatencyMs)
		}
		sb.WriteString(fmt.Sprintf("| **TCP Connection** | `%s` | `%s` | ✗ Divergent |\n", wStatus, fStatus))
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
		sb.WriteString(fmt.Sprintf("```bash\nnetdiff probe %s %s -t %s\n```\n\n", exp.NextBestProbe.ProbeName, exp.NextBestProbe.Parameter, comp.Target.Raw))
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
