package printer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"netdiff/pkg/model"
)

// Terminal formatting characters
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan    = "\033[36m"
	ColorMagenta = "\033[35m"
	ColorBold    = "\033[1m"
)

type Printer struct {
	Out io.Writer
}

func New() *Printer {
	return &Printer{Out: os.Stdout}
}

// PrintComparison renders the human-readable diff or JSON based on options.
func (p *Printer) PrintComparison(report *model.ComparisonReport, asJSON, verbose bool) error {
	if asJSON {
		enc := json.NewEncoder(p.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	w := report.WorkingSnapshot
	f := report.FailingSnapshot

	fmt.Fprintf(p.Out, "\n%s%s=== NetDiff Target Analysis ===%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Fprintf(p.Out, "Target: %s%s%s\n\n", ColorBold, report.Target.Raw, ColorReset)

	wHost := report.WorkingHost
	if wHost == "" {
		wHost = "Working Environment"
	}
	fHost := report.FailingHost
	if fHost == "" {
		fHost = "Failing Environment"
	}

	fmt.Fprintf(p.Out, "%-24s %-24s\n", ColorBold+strings.ToUpper(wHost)+ColorReset, ColorBold+strings.ToUpper(fHost)+ColorReset)
	fmt.Fprintf(p.Out, "%s\n", strings.Repeat("-", 60))

	// DNS
	p.printSectionHeader("DNS")
	wDNS := formatDNS(w.DNS)
	fDNS := formatDNS(f.DNS)
	fmt.Fprintf(p.Out, "%-24s %-24s\n", wDNS, fDNS)
	if wDNS == fDNS {
		fmt.Fprintf(p.Out, "%s✓ same%s\n\n", ColorGreen, ColorReset)
	} else {
		fmt.Fprintf(p.Out, "%s⚠ different%s\n\n", ColorYellow, ColorReset)
	}

	// Policy Rule
	if (w.Route != nil && w.Route.PolicyRule != "") || (f.Route != nil && f.Route.PolicyRule != "") {
		p.printSectionHeader("Policy Rule")
		wRule := formatRule(w.Route)
		fRule := formatRule(f.Route)
		fmt.Fprintf(p.Out, "%-24s %-24s\n", wRule, fRule)
		if wRule == fRule {
			fmt.Fprintf(p.Out, "%s✓ same%s\n\n", ColorGreen, ColorReset)
		} else {
			fmt.Fprintf(p.Out, "%s⚠ different%s\n\n", ColorYellow, ColorReset)
		}
	}

	// Route
	p.printSectionHeader("Route Table & Egress")
	wRoute := formatRoute(w.Route)
	fRoute := formatRoute(f.Route)
	fmt.Fprintf(p.Out, "%-24s %-24s\n", wRoute, fRoute)
	if wRoute == fRoute {
		fmt.Fprintf(p.Out, "%s✓ same%s\n\n", ColorGreen, ColorReset)
	} else {
		fmt.Fprintf(p.Out, "%s⚠ different%s\n\n", ColorYellow, ColorReset)
	}

	// Source Address
	p.printSectionHeader("Source Address")
	wSrc := formatSource(w.Route)
	fSrc := formatSource(f.Route)
	fmt.Fprintf(p.Out, "%-24s %-24s\n", wSrc, fSrc)
	if wSrc == fSrc {
		fmt.Fprintf(p.Out, "%s✓ same%s\n\n", ColorGreen, ColorReset)
	} else {
		fmt.Fprintf(p.Out, "%s⚠ different%s\n\n", ColorYellow, ColorReset)
	}

	// TCP
	p.printSectionHeader("TCP Connection")
	wTCP := formatTCP(w.TCP)
	fTCP := formatTCP(f.TCP)
	fmt.Fprintf(p.Out, "%-24s %-24s\n", wTCP, fTCP)
	if wTCP == fTCP {
		fmt.Fprintf(p.Out, "%s✓ same%s\n\n", ColorGreen, ColorReset)
	} else {
		fmt.Fprintf(p.Out, "%s✗ different%s\n\n", ColorRed, ColorReset)
	}

	// High Relevance Explanations
	var highDiffs []model.Difference
	var medDiffs []model.Difference
	for _, d := range report.Differences {
		if d.Category == "TCP" {
			continue // TCP is the observed symptom
		}
		if d.Relevance == model.RelevanceHigh {
			highDiffs = append(highDiffs, d)
		} else if d.Relevance == model.RelevanceMedium {
			medDiffs = append(medDiffs, d)
		}
	}

	if report.EarliestDivergence != "" {
		fmt.Fprintf(p.Out, "%s%s>>> ROOT CAUSE: EARLIEST PATH DIVERGENCE <<<%s\n", ColorBold, ColorYellow, ColorReset)
		fmt.Fprintf(p.Out, "%s%s%s\n\n", ColorBold, report.EarliestDivergence, ColorReset)
	}

	if len(highDiffs) > 0 {
		fmt.Fprintf(p.Out, "%s%s=== HIGH-RELEVANCE DIFFERENCE ===%s\n", ColorBold, ColorYellow, ColorReset)
		for _, d := range highDiffs {
			fmt.Fprintf(p.Out, "%s[%s]%s %s\n", ColorBold, d.Category, ColorReset, d.Rationale)
			fmt.Fprintf(p.Out, "  Working: %s\n", d.WorkingValue)
			fmt.Fprintf(p.Out, "  Failing: %s\n\n", d.FailingValue)
		}
	}

	if verbose && len(medDiffs) > 0 {
		fmt.Fprintf(p.Out, "%s%s=== MEDIUM-RELEVANCE DIFFERENCE ===%s\n", ColorBold, ColorCyan, ColorReset)
		for _, d := range medDiffs {
			fmt.Fprintf(p.Out, "%s[%s]%s %s\n", ColorBold, d.Category, ColorReset, d.Rationale)
			fmt.Fprintf(p.Out, "  Working: %s\n", d.WorkingValue)
			fmt.Fprintf(p.Out, "  Failing: %s\n\n", d.FailingValue)
		}
	}

	return nil
}

func (p *Printer) printSectionHeader(title string) {
	fmt.Fprintf(p.Out, "%s%s%s\n", ColorBold, title, ColorReset)
}

func formatDNS(d *model.DNSReport) string {
	if d == nil {
		return "none"
	}
	if !d.Success {
		return "FAILED"
	}
	if len(d.ARecords) > 0 {
		return d.ARecords[0]
	}
	if len(d.AAAARecords) > 0 {
		return d.AAAARecords[0]
	}
	return "resolved"
}

func formatRoute(r *model.RouteReport) string {
	if r == nil {
		return "unknown"
	}
	tbl := r.TableName
	if tbl == "" {
		tbl = fmt.Sprintf("tbl %d", r.Table)
	}
	if r.EgressInterface != "" {
		return fmt.Sprintf("%s (%s)", r.EgressInterface, tbl)
	}
	return tbl
}

func formatSource(r *model.RouteReport) string {
	if r == nil || r.PreferredSource == "" {
		return "auto"
	}
	return r.PreferredSource
}

func formatTCP(t *model.TCPReport) string {
	if t == nil {
		return "unknown"
	}
	if t.Status == model.TCPStatusConnected {
		return fmt.Sprintf("connected (%dms)", t.LatencyMs)
	}
	return string(t.Status)
}

func formatRule(r *model.RouteReport) string {
	if r == nil || r.PolicyRule == "" {
		return "main"
	}
	return r.PolicyRule
}
