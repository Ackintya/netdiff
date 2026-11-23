package printer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"netdiff/internal/ai"
	"netdiff/internal/remediation"
	"netdiff/pkg/model"
)

// Terminal formatting characters
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorCyan    = "\033[36m"
	ColorMagenta = "\033[35m"
	ColorBold    = "\033[1m"
	ColorMuted   = "\033[2m"
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
		fmt.Fprintf(p.Out, "%s%s>>> EARLIEST OBSERVED PATH DIVERGENCE <<<%s\n", ColorBold, ColorYellow, ColorReset)
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

func isInterfaceUp(iface *model.InterfaceReport) bool {
	if iface == nil {
		return false
	}
	for _, f := range iface.Flags {
		if strings.ToUpper(f) == "UP" {
			return true
		}
	}
	return strings.ToLower(iface.OperState) == "up"
}

// PrintCapturePath renders a layered network path card for a single capture snapshot.
func (p *Printer) PrintCapturePath(snap *model.Snapshot) {
	if snap == nil {
		fmt.Fprintln(p.Out, "No snapshot data to display.")
		return
	}

	host := "localhost"
	if snap.Metadata.Hostname != "" {
		host = snap.Metadata.Hostname
	}
	timestamp := "unknown time"
	if !snap.Metadata.CapturedAt.IsZero() {
		timestamp = snap.Metadata.CapturedAt.UTC().Format("2006-01-02 15:04 UTC")
	}

	fmt.Fprintf(p.Out, "\n  ┌──────────────────────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(p.Out, "  │  %-68s│\n", fmt.Sprintf("Captured: %s", snap.Target.Raw))
	fmt.Fprintf(p.Out, "  │  %-68s│\n", fmt.Sprintf("Host: %s  @  %s", host, timestamp))
	fmt.Fprintf(p.Out, "  └──────────────────────────────────────────────────────────────────────┘\n\n")

	// DNS Layer
	if snap.DNS == nil {
		if snap.Target.IsIP {
			p.printPathRow("DNS", ColorGreen, "●", "(IP target — resolution skipped)")
		} else {
			p.printPathRow("DNS", ColorMuted, "●", "not collected")
		}
	} else if !snap.DNS.Success {
		p.printPathRow("DNS", ColorRed, "✗", fmt.Sprintf("resolution failed: %s", snap.DNS.Error))
	} else {
		var records []string
		records = append(records, snap.DNS.ARecords...)
		records = append(records, snap.DNS.AAAARecords...)
		recStr := strings.Join(records, ", ")
		if recStr == "" {
			recStr = "resolved"
		}
		p.printPathRow("DNS", ColorGreen, "●", fmt.Sprintf("✓ %s  (%dms)", recStr, snap.DNS.ResolutionMs))
	}

	// Route Layer
	if snap.Route == nil {
		p.printPathRow("Route", ColorMuted, "●", "not collected")
	} else if !snap.Route.Success {
		p.printPathRow("Route", ColorRed, "✗", fmt.Sprintf("lookup failed: %s", snap.Route.Error))
	} else {
		tbl := snap.Route.TableName
		if tbl == "" && snap.Route.Table != 0 {
			tbl = fmt.Sprintf("tbl %d", snap.Route.Table)
		}
		if tbl == "" {
			tbl = "main"
		}
		gw := ""
		if snap.Route.Gateway != "" {
			gw = fmt.Sprintf(" gw %s", snap.Route.Gateway)
		}
		src := snap.Route.PreferredSource
		if src == "" {
			src = "auto"
		}
		detail := fmt.Sprintf("→ %s  dev %s%s  src %s  (%s)", snap.Target.Host, snap.Route.EgressInterface, gw, src, tbl)
		p.printPathRow("Route", ColorGreen, "●", detail)
	}

	// Interface Layer
	if snap.Interface != nil && snap.Interface.Name != "" {
		if isInterfaceUp(snap.Interface) {
			flags := strings.Join(snap.Interface.Flags, " ")
			oper := snap.Interface.OperState
			if oper == "" {
				oper = "up"
			}
			detail := fmt.Sprintf("→ %s  %s  MTU %d  operstate %s", snap.Interface.Name, flags, snap.Interface.MTU, oper)
			p.printPathRow("Interface", ColorGreen, "●", detail)
		} else {
			detail := fmt.Sprintf("✗ %s is administratively DOWN", snap.Interface.Name)
			p.printPathRow("Interface", ColorRed, "✗", detail)
		}
	}

	// ARP / Neighbor Layer
	if snap.Neighbor != nil && snap.Neighbor.IP != "" {
		state := snap.Neighbor.State
		if state == "" {
			state = "REACHABLE"
		}
		detail := fmt.Sprintf("→ %s  %s  %s", snap.Neighbor.IP, snap.Neighbor.MAC, state)
		p.printPathRow("ARP", ColorGreen, "●", detail)
	}

	// Firewall Layer
	if snap.Firewall != nil && snap.Firewall.Active {
		backend := snap.Firewall.Backend
		if backend == "" {
			backend = "packet filter"
		}
		p.printPathRow("Firewall", ColorYellow, "⚠", fmt.Sprintf("active filtering detected (%s)", backend))
	}

	// Proxy Layer
	if snap.Proxy != nil && (snap.Proxy.HTTPProxy != "" || snap.Proxy.HTTPSProxy != "") {
		pVal := snap.Proxy.HTTPProxy
		if pVal == "" {
			pVal = snap.Proxy.HTTPSProxy
		}
		p.printPathRow("Proxy", ColorYellow, "⚠", fmt.Sprintf("proxy configured (%s)", pVal))
	}

	// TCP Layer
	if snap.TCP == nil {
		p.printPathRow("TCP", ColorMuted, "●", "not collected")
	} else if snap.TCP.Status == model.TCPStatusConnected {
		remote := snap.Target.Raw
		if snap.TCP.RemoteIP != "" {
			remote = fmt.Sprintf("%s:%d", snap.TCP.RemoteIP, snap.TCP.RemotePort)
		}
		local := snap.TCP.LocalAddr
		if local == "" {
			local = "client"
		}
		detail := fmt.Sprintf("✓ connected  %s→%s  (%dms)", local, remote, snap.TCP.LatencyMs)
		if snap.TCP.SocketInfo != nil {
			var extras []string
			if snap.TCP.SocketInfo.RTTUs > 0 {
				extras = append(extras, fmt.Sprintf("kernel RTT: %.2fms", float64(snap.TCP.SocketInfo.RTTUs)/1000.0))
			}
			if snap.TCP.SocketInfo.Retransmits > 0 || snap.TCP.SocketInfo.TotalRetrans > 0 {
				extras = append(extras, fmt.Sprintf("retrans: %d", snap.TCP.SocketInfo.TotalRetrans))
			}
			if snap.TCP.SocketInfo.SndCwnd > 0 {
				extras = append(extras, fmt.Sprintf("cwnd: %d", snap.TCP.SocketInfo.SndCwnd))
			}
			if snap.TCP.SocketInfo.Pmtu > 0 {
				extras = append(extras, fmt.Sprintf("pmtu: %d", snap.TCP.SocketInfo.Pmtu))
			}
			if len(extras) > 0 {
				detail += fmt.Sprintf(" [%s]", strings.Join(extras, ", "))
			}
		}
		p.printPathRow("TCP", ColorGreen, "●", detail)
	} else if snap.TCP.Status == model.TCPStatusRefused {
		p.printPathRow("TCP", ColorRed, "✗", fmt.Sprintf("connection refused on port %d", snap.Target.Port))
	} else if snap.TCP.Status == model.TCPStatusTimeout {
		p.printPathRow("TCP", ColorRed, "✗", fmt.Sprintf("connection timed out after %dms", snap.TCP.LatencyMs))
	} else {
		errStr := snap.TCP.Error
		if errStr == "" {
			errStr = string(snap.TCP.Status)
		}
		p.printPathRow("TCP", ColorRed, "✗", fmt.Sprintf("%s (%s)", snap.TCP.Status, errStr))
	}

	// TLS Layer (if target is TLS-enabled or TLS collected)
	if snap.TLS != nil {
		if snap.TLS.HandshakeSuccess {
			expiryStr := ""
			if snap.TLS.DaysUntilExpiry != 0 {
				expiryStr = fmt.Sprintf(", expires in %dd", snap.TLS.DaysUntilExpiry)
			}
			detail := fmt.Sprintf("✓ %s  %s  (issuer: %s%s)", snap.TLS.Version, snap.TLS.CipherSuite, snap.TLS.Issuer, expiryStr)
			p.printPathRow("TLS", ColorGreen, "●", detail)
		} else {
			p.printPathRow("TLS", ColorRed, "✗", fmt.Sprintf("handshake failed: %s", snap.TLS.Error))
		}
	} else if snap.Target.IsTLS() {
		p.printPathRow("TLS", ColorMuted, "●", "not completed (TCP did not connect)")
	}

	if len(snap.CollectionErrors) > 0 {
		fmt.Fprintf(p.Out, "\n  %sWarnings:%s\n", ColorYellow, ColorReset)
		for _, w := range snap.CollectionErrors {
			fmt.Fprintf(p.Out, "    - %s\n", w)
		}
	}
	fmt.Fprintln(p.Out)
}

func (p *Printer) printPathRow(label, color, symbol, detail string) {
	fmt.Fprintf(p.Out, "  %s%s%s %-12s ── %s\n", color, symbol, ColorReset, label, detail)
}

// PrintDiagnosis renders a rich terminal diagnostic card with confidence bars, root cause, and next probe.
func (p *Printer) PrintDiagnosis(comp *model.ComparisonReport, exp *ai.ExplanationReport) {
	if comp == nil || exp == nil {
		return
	}

	target := comp.Target.Raw
	wHost := comp.WorkingHost
	if wHost == "" {
		wHost = "baseline"
	}
	fHost := comp.FailingHost
	if fHost == "" {
		fHost = "current"
	}

	wTime := ""
	if comp.WorkingSnapshot != nil && !comp.WorkingSnapshot.Metadata.CapturedAt.IsZero() {
		wTime = comp.WorkingSnapshot.Metadata.CapturedAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	fTime := ""
	if comp.FailingSnapshot != nil && !comp.FailingSnapshot.Metadata.CapturedAt.IsZero() {
		fTime = comp.FailingSnapshot.Metadata.CapturedAt.UTC().Format("2006-01-02 15:04 UTC")
	}

	fmt.Fprintf(p.Out, "\n  %s╔══════════════════════════════════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	titleText := fmt.Sprintf("NETDIFF DIAGNOSIS  ·  %s", target)
	fmt.Fprintf(p.Out, "  %s║%s  %-68s%s║%s\n", ColorCyan, ColorBold, titleText, ColorCyan, ColorReset)
	fmt.Fprintf(p.Out, "  %s╚══════════════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	if wTime != "" {
		fmt.Fprintf(p.Out, "  %-10s %-16s %s\n", "Baseline", wHost, wTime)
	}
	if fTime != "" {
		fmt.Fprintf(p.Out, "  %-10s %-16s %s\n", "Current", fHost, fTime)
	}
	fmt.Fprintln(p.Out)

	p.printPathChain(comp)

	if comp.EarliestDivergence != "" {
		fmt.Fprintf(p.Out, "  %sROOT CAUSE (DAG earliest divergence):%s\n", ColorBold, ColorReset)
		fmt.Fprintf(p.Out, "  %s%s%s\n\n", ColorRed, comp.EarliestDivergence, ColorReset)
	}

	if exp.Notice != "" {
		fmt.Fprintf(p.Out, "  %s%s%s\n\n", ColorYellow, exp.Notice, ColorReset)
	}

	if exp.Summary != "" {
		wrapped := wrapText(exp.Summary, 70, "  ")
		fmt.Fprintf(p.Out, "  %s\n\n", wrapped)
	}

	if len(exp.Hypotheses) > 0 {
		fmt.Fprintf(p.Out, "  %sHYPOTHESES:%s\n\n", ColorBold, ColorReset)
		for i, h := range exp.Hypotheses {
			pct := h.ConfidencePct
			if pct == 0 {
				switch strings.ToLower(h.SupportLevel) {
				case "strong":
					pct = 85
				case "moderate":
					pct = 45
				default:
					pct = 15
				}
			}
			bar := confidenceBar(pct)
			lvlColor := ColorGreen
			if strings.ToLower(h.SupportLevel) == "moderate" {
				lvlColor = ColorYellow
			} else if strings.ToLower(h.SupportLevel) == "weak" {
				lvlColor = ColorMuted
			}

			fmt.Fprintf(p.Out, "  %d  %s%s%s  %3d%%  [%s%-8s%s]  %s%s%s\n",
				i+1, ColorCyan, bar, ColorReset, pct, lvlColor, strings.ToUpper(h.SupportLevel), ColorReset, ColorBold, h.Title, ColorReset)
			if h.Rationale != "" {
				wrapped := wrapText(h.Rationale, 68, "     ")
				fmt.Fprintf(p.Out, "     %s\n\n", wrapped)
			}
		}
	}

	if exp.NextBestProbe != nil {
		fmt.Fprintf(p.Out, "  %sNEXT PROBE:%s\n", ColorBold, ColorReset)
		probeCmd := fmt.Sprintf("$ netdiff probe %s", exp.NextBestProbe.ProbeName)
		if exp.NextBestProbe.Parameter != "" {
			probeCmd += " " + exp.NextBestProbe.Parameter
		}
		if exp.NextBestProbe.ProbeName != "TEST_INTERFACE_STATE" && comp.Target.Raw != "" {
			probeCmd += " -t " + comp.Target.Raw
		}
		fmt.Fprintf(p.Out, "  %s%s%s\n", ColorBold+ColorGreen, probeCmd, ColorReset)
		if exp.NextBestProbe.Reason != "" {
			fmt.Fprintf(p.Out, "  Why: %s\n", exp.NextBestProbe.Reason)
		}
		fmt.Fprintln(p.Out)
	}

	if exp.Remediation != nil {
		fmt.Fprintf(p.Out, "  %s%s╔══════════════════════════════════════════════════════════════════════╗%s\n", ColorBold, ColorGreen, ColorReset)
		fmt.Fprintf(p.Out, "  %s║  REMEDIATION PLAYBOOK (Actionable Fix)                               ║%s\n", ColorBold, ColorReset)
		fmt.Fprintf(p.Out, "  %s%s╚══════════════════════════════════════════════════════════════════════╝%s\n\n", ColorBold, ColorGreen, ColorReset)

		if exp.Remediation.ImmediateBash != "" {
			fmt.Fprintf(p.Out, "  %sImmediate Fix (copy-pasteable):%s\n", ColorBold, ColorReset)
			fmt.Fprintf(p.Out, "  %s$ %s%s\n\n", ColorBold+ColorCyan, exp.Remediation.ImmediateBash, ColorReset)
		}
		if exp.Remediation.RollbackBash != "" && !strings.HasPrefix(exp.Remediation.RollbackBash, "#") {
			fmt.Fprintf(p.Out, "  %sRollback Guard:%s\n", ColorBold, ColorReset)
			fmt.Fprintf(p.Out, "  %s$ %s%s\n\n", ColorYellow, exp.Remediation.RollbackBash, ColorReset)
		}
		if exp.Remediation.PermanentConfig != "" {
			fmt.Fprintf(p.Out, "  %sPermanent Configuration:%s\n", ColorBold, ColorReset)
			cfgLines := strings.Split(exp.Remediation.PermanentConfig, "\n")
			for _, line := range cfgLines {
				fmt.Fprintf(p.Out, "    %s%s%s\n", ColorMuted, line, ColorReset)
			}
			fmt.Fprintln(p.Out)
		}
		if exp.Remediation.VerificationCmd != "" {
			fmt.Fprintf(p.Out, "  %sVerification:%s\n", ColorBold, ColorReset)
			fmt.Fprintf(p.Out, "  %s$ %s%s\n\n", ColorBold+ColorGreen, exp.Remediation.VerificationCmd, ColorReset)
		}
		if exp.Remediation.Explanation != "" {
			wrapped := wrapText(exp.Remediation.Explanation, 68, "  ")
			fmt.Fprintf(p.Out, "  %sWhy: %s%s\n\n", ColorBold, ColorReset, wrapped)
		}
		fmt.Fprintf(p.Out, "  %sGuarded Auto-Fix:%s\n", ColorBold, ColorReset)
		fmt.Fprintf(p.Out, "  %s$ netdiff fix <good> <bad> --apply%s\n\n", ColorBold+ColorGreen, ColorReset)
	}

	fmt.Fprintf(p.Out, "  %sDiagnosis provided by: %s%s\n\n", ColorMuted, exp.Provider, ColorReset)
}

// PrintAsk renders a grounded conversational Q&A card in the terminal.
func (p *Printer) PrintAsk(target, question, answer string) {
	fmt.Fprintf(p.Out, "\n  %s╔══════════════════════════════════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	titleText := fmt.Sprintf("NETDIFF INVESTIGATION  ·  %s", target)
	fmt.Fprintf(p.Out, "  %s║%s  %-68s%s║%s\n", ColorCyan, ColorBold, titleText, ColorCyan, ColorReset)
	fmt.Fprintf(p.Out, "  %s╚══════════════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	fmt.Fprintf(p.Out, "  %sQuestion:%s %q\n\n", ColorBold, ColorReset, question)
	fmt.Fprintf(p.Out, "  %sEvidence-Grounded Answer:%s\n", ColorBold+ColorGreen, ColorReset)
	for _, line := range strings.Split(answer, "\n") {
		fmt.Fprintf(p.Out, "  %s\n", line)
	}
	fmt.Fprintln(p.Out)
}

func (p *Printer) printPathChain(comp *model.ComparisonReport) {
	dnsStatus := "DNS"
	routeStatus := "Route"
	ifaceStatus := "Interface"
	arpStatus := "ARP"
	tcpStatus := "TCP"
	tlsStatus := "TLS"

	isTLS := comp.Target.IsTLS() || (comp.WorkingSnapshot != nil && comp.WorkingSnapshot.TLS != nil) || (comp.FailingSnapshot != nil && comp.FailingSnapshot.TLS != nil)

	f := comp.FailingSnapshot
	if f != nil {
		if f.DNS != nil && !f.DNS.Success {
			dnsStatus = "DNS✗"
		}
		if f.Route != nil && !f.Route.Success {
			routeStatus = "Route✗"
		}
		if f.Interface != nil && !isInterfaceUp(f.Interface) {
			ifaceStatus = "Interface✗"
		}
		if f.Neighbor != nil && (!f.Neighbor.Present || strings.EqualFold(f.Neighbor.State, "INCOMPLETE") || strings.EqualFold(f.Neighbor.State, "FAILED")) {
			arpStatus = "ARP✗"
		}
		if f.TCP != nil && f.TCP.Status != model.TCPStatusConnected {
			tcpStatus = "TCP✗"
		}
		if f.TLS != nil && !f.TLS.HandshakeSuccess {
			tlsStatus = "TLS✗"
		}
	}

	for _, d := range comp.Differences {
		if d.Relevance == model.RelevanceHigh {
			switch d.Category {
			case "DNS":
				dnsStatus = "DNS✗"
			case "Route", "Policy":
				routeStatus = "Route✗"
			case "Interface":
				ifaceStatus = "Interface✗"
			case "Neighbor":
				arpStatus = "ARP✗"
			case "TCP":
				tcpStatus = "TCP✗"
			case "TLS":
				tlsStatus = "TLS✗"
			}
		}
	}

	colorize := func(label string) string {
		if strings.HasSuffix(label, "✗") {
			return ColorBold + ColorRed + label + ColorReset
		}
		return ColorGreen + label + ColorReset
	}

	if isTLS {
		fmt.Fprintf(p.Out, "  %sPATH CHAIN:%s  %s → %s → %s → %s → %s → %s\n\n",
			ColorBold, ColorReset,
			colorize(dnsStatus),
			colorize(routeStatus),
			colorize(ifaceStatus),
			colorize(arpStatus),
			colorize(tcpStatus),
			colorize(tlsStatus),
		)
	} else {
		fmt.Fprintf(p.Out, "  %sPATH CHAIN:%s  %s → %s → %s → %s → %s\n\n",
			ColorBold, ColorReset,
			colorize(dnsStatus),
			colorize(routeStatus),
			colorize(ifaceStatus),
			colorize(arpStatus),
			colorize(tcpStatus),
		)
	}
}

// PrintCheck renders a single-line reachability summary.
func (p *Printer) PrintCheck(snap *model.Snapshot) {
	if snap == nil {
		fmt.Fprintf(p.Out, "%s✗%s  unknown (no snapshot)\n", ColorRed, ColorReset)
		return
	}
	tgt := snap.Target.Raw

	// Check TLS failure first if target is TLS
	if snap.TLS != nil && !snap.TLS.HandshakeSuccess {
		fmt.Fprintf(p.Out, "%s✗%s  %-22s tls_failed   (%s)\n",
			ColorRed, ColorReset, tgt, snap.TLS.Error)
		return
	}

	if snap.TCP != nil && snap.TCP.Status == model.TCPStatusConnected {
		egress := "unknown"
		if snap.Route != nil && snap.Route.EgressInterface != "" {
			egress = snap.Route.EgressInterface
		}
		local := snap.TCP.LocalAddr
		if local == "" && snap.Route != nil && snap.Route.PreferredSource != "" {
			local = snap.Route.PreferredSource
		}
		if local == "" {
			local = "client"
		}
		remote := snap.Target.Raw
		if snap.TCP.RemoteIP != "" {
			remote = fmt.Sprintf("%s:%d", snap.TCP.RemoteIP, snap.TCP.RemotePort)
		}
		connLabel := "connected"
		if snap.TLS != nil && snap.TLS.HandshakeSuccess {
			connLabel = fmt.Sprintf("connected [%s]", snap.TLS.Version)
		}
		fmt.Fprintf(p.Out, "%s✓%s  %-22s %-16s %s→%s  via %s  (%dms)\n",
			ColorGreen, ColorReset, tgt, connLabel, local, remote, egress, snap.TCP.LatencyMs)
		return
	}

	if snap.TCP != nil && snap.TCP.Status == model.TCPStatusRefused {
		fmt.Fprintf(p.Out, "%s✗%s  %-22s refused      (host reachable, port %d closed or service not listening)\n",
			ColorRed, ColorReset, tgt, snap.Target.Port)
		return
	}

	if snap.TCP != nil && snap.TCP.Status == model.TCPStatusTimeout {
		fmt.Fprintf(p.Out, "%s✗%s  %-22s timeout      (no response, possible firewall drop or silent packet loss)\n",
			ColorRed, ColorReset, tgt)
		return
	}

	if snap.Route != nil && !snap.Route.Success {
		errStr := snap.Route.Error
		if errStr == "" {
			errStr = "Network is unreachable"
		}
		fmt.Fprintf(p.Out, "%s✗%s  %-22s unreachable  (route lookup failed: %s)\n",
			ColorRed, ColorReset, tgt, errStr)
		return
	}

	if snap.DNS != nil && !snap.DNS.Success {
		errStr := snap.DNS.Error
		if errStr == "" {
			errStr = "NXDOMAIN"
		}
		fmt.Fprintf(p.Out, "%s✗%s  %-22s dns_failed   (%s)\n",
			ColorRed, ColorReset, tgt, errStr)
		return
	}

	status := "failed"
	reason := "connection failed"
	if snap.TCP != nil {
		status = string(snap.TCP.Status)
		if snap.TCP.Error != "" {
			reason = snap.TCP.Error
		}
	}
	fmt.Fprintf(p.Out, "%s✗%s  %-22s %-12s (%s)\n",
		ColorRed, ColorReset, tgt, status, reason)
}

func confidenceBar(pct int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := (pct * 20) / 100
	empty := 20 - filled
	return strings.Repeat("█", filled) + strings.Repeat("░", empty)
}

func wrapText(text string, width int, prefix string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	current := words[0]
	for _, w := range words[1:] {
		if len(current)+1+len(w) > width {
			lines = append(lines, current)
			current = prefix + w
		} else {
			current += " " + w
		}
	}
	lines = append(lines, current)
	return strings.Join(lines, "\n")
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
	if !r.Success {
		if r.Error != "" {
			return fmt.Sprintf("FAILED (%s)", r.Error)
		}
		return "FAILED"
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
		res := fmt.Sprintf("connected (%dms)", t.LatencyMs)
		if t.SocketInfo != nil {
			if t.SocketInfo.TotalRetrans > 0 {
				res += fmt.Sprintf(" [%d retrans]", t.SocketInfo.TotalRetrans)
			} else if t.SocketInfo.RTTUs > 0 {
				res += fmt.Sprintf(" [RTT %.1fms]", float64(t.SocketInfo.RTTUs)/1000.0)
			}
		}
		return res
	}
	return string(t.Status)
}

func formatRule(r *model.RouteReport) string {
	if r == nil || r.PolicyRule == "" {
		return "main"
	}
	return r.PolicyRule
}

// PrintFixResult renders the structured report of a netdiff fix execution.
func (p *Printer) PrintFixResult(res *remediation.FixResult) {
	fmt.Fprintf(p.Out, "\n  %s╔══════════════════════════════════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	titleText := fmt.Sprintf("NETDIFF GUARDED REMEDIATION  ·  %s", res.Target.Raw)
	fmt.Fprintf(p.Out, "  %s║%s  %-68s%s║%s\n", ColorCyan, ColorBold, titleText, ColorCyan, ColorReset)
	fmt.Fprintf(p.Out, "  %s╚══════════════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	switch res.Status {
	case remediation.FixStatusDryRun:
		fmt.Fprintf(p.Out, "  %sMODE: DRY RUN (No system changes applied)%s\n\n", ColorBold+ColorYellow, ColorReset)
		if res.Plan != nil {
			if res.Plan.ImmediateBash != "" {
				fmt.Fprintf(p.Out, "  %sRemediation Command:%s\n", ColorBold, ColorReset)
				fmt.Fprintf(p.Out, "    $ %s%s%s\n\n", ColorBold+ColorCyan, res.Plan.ImmediateBash, ColorReset)
			}
			if res.Plan.RollbackBash != "" && !strings.HasPrefix(res.Plan.RollbackBash, "#") {
				fmt.Fprintf(p.Out, "  %sSafety Rollback Guard:%s\n", ColorBold, ColorReset)
				fmt.Fprintf(p.Out, "    $ %s%s%s\n\n", ColorYellow, res.Plan.RollbackBash, ColorReset)
			}
			if res.Plan.VerificationCmd != "" {
				fmt.Fprintf(p.Out, "  %sCanary Verification Probe:%s\n", ColorBold, ColorReset)
				fmt.Fprintf(p.Out, "    $ %s%s%s\n\n", ColorGreen, res.Plan.VerificationCmd, ColorReset)
			}
			if res.Plan.Explanation != "" {
				fmt.Fprintf(p.Out, "  %sRationale:%s %s\n\n", ColorBold, ColorReset, res.Plan.Explanation)
			}
		}
		fmt.Fprintf(p.Out, "  %sTo apply this verified fix with automated rollback protection, run:%s\n", ColorBold, ColorReset)
		if res.Target.Raw != "" && !strings.Contains(res.Target.Raw, ".ndiff") {
			fmt.Fprintf(p.Out, "    %snetdiff fix %s --apply%s\n\n", ColorBold+ColorGreen, res.Target.Raw, ColorReset)
		} else {
			fmt.Fprintf(p.Out, "    %snetdiff fix <good> <bad> --apply%s\n\n", ColorBold+ColorGreen, ColorReset)
		}

	case remediation.FixStatusAppliedVerified:
		fmt.Fprintf(p.Out, "  %s✓ REMEDIATION APPLIED & VERIFIED SUCCESSFULLY%s\n\n", ColorBold+ColorGreen, ColorReset)
		if res.Plan != nil && res.Plan.ImmediateBash != "" {
			fmt.Fprintf(p.Out, "  %sApplied Fix:%s\n    $ %s%s%s\n\n", ColorBold, ColorReset, ColorCyan, res.Plan.ImmediateBash, ColorReset)
		}
		if res.CanaryOutput != "" {
			fmt.Fprintf(p.Out, "  %sCanary Probe:%s\n    %s\n\n", ColorBold, ColorReset, res.CanaryOutput)
		}
		if res.Plan != nil && res.Plan.PermanentConfig != "" {
			fmt.Fprintf(p.Out, "  %sPermanent Configuration (to persist across reboots):%s\n", ColorBold, ColorReset)
			for _, line := range strings.Split(res.Plan.PermanentConfig, "\n") {
				fmt.Fprintf(p.Out, "    %s%s%s\n", ColorMuted, line, ColorReset)
			}
			fmt.Fprintln(p.Out)
		}

	case remediation.FixStatusCanaryFailedRolledBack:
		fmt.Fprintf(p.Out, "  %s⚠ CANARY FAILED - AUTOMATIC ROLLBACK TRIGGERED%s\n\n", ColorBold+ColorRed, ColorReset)
		if res.Plan != nil {
			fmt.Fprintf(p.Out, "  %sAttempted Fix:%s\n    $ %s%s%s\n", ColorBold, ColorReset, ColorMuted, res.Plan.ImmediateBash, ColorReset)
			if res.CanaryError != nil {
				fmt.Fprintf(p.Out, "  %sCanary Check:%s   %s✗ %v%s\n", ColorBold, ColorReset, ColorRed, res.CanaryError, ColorReset)
			}
			fmt.Fprintf(p.Out, "  %sExecuted Rollback:%s\n    $ %s%s%s\n\n", ColorBold, ColorReset, ColorYellow, res.Plan.RollbackBash, ColorReset)
		}
		fmt.Fprintf(p.Out, "  %sSystem state safely restored to pre-fix baseline.%s\n\n", ColorGreen, ColorReset)

	case remediation.FixStatusApplyFailed:
		fmt.Fprintf(p.Out, "  %s✗ REMEDIATION COMMAND FAILED%s\n\n", ColorBold+ColorRed, ColorReset)
		if res.ImmediateError != nil {
			fmt.Fprintf(p.Out, "  %sError:%s  %v\n", ColorBold, ColorReset, res.ImmediateError)
		}
		if res.ImmediateOutput != "" {
			fmt.Fprintf(p.Out, "  %sOutput:%s %s\n", ColorBold, ColorReset, res.ImmediateOutput)
		}
		fmt.Fprintln(p.Out)

	case remediation.FixStatusRollbackFailed:
		fmt.Fprintf(p.Out, "  %sCRITICAL: ROLLBACK COMMAND FAILED%s\n\n", ColorBold+ColorRed, ColorReset)
		if res.RollbackError != nil {
			fmt.Fprintf(p.Out, "  %sRollback Error:%s  %v\n", ColorBold, ColorReset, res.RollbackError)
		}
		fmt.Fprintln(p.Out)

	default:
		for _, s := range res.Steps {
			fmt.Fprintf(p.Out, "  %s\n", s)
		}
		fmt.Fprintln(p.Out)
	}
}
