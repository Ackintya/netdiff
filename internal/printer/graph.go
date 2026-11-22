package printer

import (
	"fmt"
	"strings"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

// PrintGraph renders an ASCII/Unicode causal dependency graph tree showing the network path
// from hostname to application transport, highlighting matching vs divergent nodes and
// pointing directly to the earliest root cause divergence.
func (p *Printer) PrintGraph(comp *model.ComparisonReport, exp *ai.ExplanationReport) {
	if comp == nil {
		return
	}

	w := comp.WorkingSnapshot
	f := comp.FailingSnapshot
	target := comp.Target.Raw
	earliest := comp.EarliestDivergence

	wHost := comp.WorkingHost
	if wHost == "" {
		wHost = "Working Host"
	}
	fHost := comp.FailingHost
	if fHost == "" {
		fHost = "Failing Host"
	}

	// 1. Header
	fmt.Fprintf(p.Out, "\n%s%s=== NetDiff Causal Dependency Graph ===%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Fprintf(p.Out, "Target: %s%s%s (port: %d, proto: %s)\n", ColorBold, target, ColorReset, comp.Target.Port, comp.Target.Protocol)
	fmt.Fprintf(p.Out, "Path:   %s[WORKING] %s%s  vs  %s[FAILING] %s%s\n",
		ColorGreen, strings.ToUpper(wHost), ColorReset,
		ColorRed, strings.ToUpper(fHost), ColorReset)
	fmt.Fprintf(p.Out, "%sLegend: %s● Match   %s✗ Divergent   %s%s◄── Earliest Divergence (Root Cause)%s\n",
		ColorMuted, ColorGreen, ColorRed, ColorBold, ColorYellow, ColorReset)
	fmt.Fprintf(p.Out, "%s%s%s\n", ColorMuted, strings.Repeat("─", 74), ColorReset)

	// Helper for checking earliest divergence
	isEarliest := func(names ...string) bool {
		if earliest == "" {
			return false
		}
		for _, name := range names {
			if strings.Contains(strings.ToLower(earliest), strings.ToLower(name)) {
				return true
			}
		}
		return false
	}

	// Helper for root cause pointer
	rootCauseMarker := func(names ...string) string {
		if isEarliest(names...) {
			return fmt.Sprintf(" %s%s◄── ROOT CAUSE (Earliest Divergence)%s", ColorBold, ColorYellow, ColorReset)
		}
		return ""
	}

	// Helper for printing a top-level stage
	printStage := func(num int, name string, same bool, valStr string, marker string) {
		statusSymbol := fmt.Sprintf("%s●%s", ColorGreen, ColorReset)
		statusBadge := fmt.Sprintf("%s[MATCH]%s", ColorGreen, ColorReset)
		if !same {
			statusSymbol = fmt.Sprintf("%s✗%s", ColorRed, ColorReset)
			statusBadge = fmt.Sprintf("%s[DIVERGENT]%s", ColorRed, ColorReset)
		}
		fmt.Fprintf(p.Out, "\n%s %-26s %s %s%s\n",
			statusSymbol,
			fmt.Sprintf("[%d] %s", num, name),
			statusBadge,
			valStr,
			marker,
		)
	}

	// Helper for printing a connecting arrow to next stage
	printConnector := func() {
		fmt.Fprintf(p.Out, "  %s│%s\n", ColorMuted, ColorReset)
		fmt.Fprintf(p.Out, "  %s▼%s\n", ColorMuted, ColorReset)
	}

	// Helper for printing a sub-branch of a stage
	printBranch := func(name string, same bool, valStr string, isLast bool, marker string) {
		branchChar := "├──"
		if isLast {
			branchChar = "└──"
		}
		statusSymbol := fmt.Sprintf("%s●%s", ColorGreen, ColorReset)
		if !same {
			statusSymbol = fmt.Sprintf("%s✗%s", ColorRed, ColorReset)
		}
		fmt.Fprintf(p.Out, "  %s│  %s%s %s %-20s %s%s\n",
			ColorMuted, branchChar, ColorReset,
			statusSymbol,
			name,
			valStr,
			marker,
		)
	}

	stageNum := 1

	// Stage 1: Hostname
	wHostVal := comp.Target.Host
	fHostVal := comp.Target.Host
	hostSame := (wHostVal == fHostVal)
	hostVal := wHostVal
	if !hostSame {
		hostVal = fmt.Sprintf("%s ≠ %s", wHostVal, fHostVal)
	}
	printStage(stageNum, "Target Hostname", hostSame, hostVal, rootCauseMarker("Hostname"))
	printConnector()
	stageNum++

	// Stage 2: DNS Resolution
	wDNSStr := formatDNS(w.DNS)
	fDNSStr := formatDNS(f.DNS)
	dnsSame := (wDNSStr == fDNSStr)
	dnsVal := wDNSStr
	if !dnsSame {
		dnsVal = fmt.Sprintf("%s ≠ %s", wDNSStr, fDNSStr)
	}
	printStage(stageNum, "DNS Resolution", dnsSame, dnsVal, rootCauseMarker("DNS"))
	printConnector()
	stageNum++

	// Stage 3: Destination IP
	wDestIP := comp.Target.Host
	if w.Route != nil && w.Route.DestinationIP != "" {
		wDestIP = w.Route.DestinationIP
	}
	fDestIP := comp.Target.Host
	if f.Route != nil && f.Route.DestinationIP != "" {
		fDestIP = f.Route.DestinationIP
	}
	destSame := (wDestIP == fDestIP)
	destVal := wDestIP
	if !destSame {
		destVal = fmt.Sprintf("%s ≠ %s", wDestIP, fDestIP)
	}
	printStage(stageNum, "Destination IP", destSame, destVal, rootCauseMarker("Destination"))
	printConnector()
	stageNum++

	// Stage 4: Policy Routing Rule & Routing Tree
	wRule := formatRule(w.Route)
	fRule := formatRule(f.Route)
	ruleSame := (wRule == fRule)
	ruleVal := wRule
	if !ruleSame {
		ruleVal = fmt.Sprintf("%s ≠ %s", wRule, fRule)
	}
	printStage(stageNum, "Policy Routing (ip rule)", ruleSame, ruleVal, rootCauseMarker("Policy"))

	// Sub-branches under Routing
	// Table
	wTbl := formatRouteTable(w.Route)
	fTbl := formatRouteTable(f.Route)
	tblSame := (wTbl == fTbl)
	tblVal := wTbl
	if !tblSame {
		tblVal = fmt.Sprintf("%s ≠ %s", wTbl, fTbl)
	}
	printBranch("Routing Table", tblSame, tblVal, false, rootCauseMarker("Route Table"))

	// Route Lookup Outcome
	wLookup := formatRouteOutcome(w.Route)
	fLookup := formatRouteOutcome(f.Route)
	lookupSame := (wLookup == fLookup)
	lookupVal := wLookup
	if !lookupSame {
		lookupVal = fmt.Sprintf("%s ≠ %s", wLookup, fLookup)
	}
	printBranch("FIB Route Lookup", lookupSame, lookupVal, false, rootCauseMarker("Route Lookup"))

	// Egress Interface
	wIface := "none"
	if w.Route != nil && w.Route.EgressInterface != "" {
		wIface = w.Route.EgressInterface
	}
	fIface := "none"
	if f.Route != nil && f.Route.EgressInterface != "" {
		fIface = f.Route.EgressInterface
	}
	ifaceSame := (wIface == fIface)
	ifaceVal := wIface
	if !ifaceSame {
		ifaceVal = fmt.Sprintf("%s ≠ %s", wIface, fIface)
	}
	printBranch("Egress Interface", ifaceSame, ifaceVal, false, rootCauseMarker("Egress Interface", "Interface"))

	// Next-Hop Gateway
	wGw := "direct on-link"
	if w.Route != nil && w.Route.Gateway != "" {
		wGw = w.Route.Gateway
	}
	fGw := "direct on-link"
	if f.Route != nil && f.Route.Gateway != "" {
		fGw = f.Route.Gateway
	}
	gwSame := (wGw == fGw)
	gwVal := wGw
	if !gwSame {
		gwVal = fmt.Sprintf("%s ≠ %s", wGw, fGw)
	}
	printBranch("Next-Hop Gateway", gwSame, gwVal, false, rootCauseMarker("Gateway"))

	// Source Address
	wSrc := "auto"
	if w.Route != nil && w.Route.PreferredSource != "" {
		wSrc = w.Route.PreferredSource
	}
	fSrc := "auto"
	if f.Route != nil && f.Route.PreferredSource != "" {
		fSrc = f.Route.PreferredSource
	}
	srcSame := (wSrc == fSrc)
	srcVal := wSrc
	if !srcSame {
		srcVal = fmt.Sprintf("%s ≠ %s", wSrc, fSrc)
	}
	printBranch("Source IP Selected", srcSame, srcVal, true, rootCauseMarker("Source"))

	printConnector()
	stageNum++

	// Stage 5: Neighbor ARP / NDP
	wNeigh := formatNeighborStr(w.Neighbor)
	fNeigh := formatNeighborStr(f.Neighbor)
	neighSame := (wNeigh == fNeigh)
	neighVal := wNeigh
	if !neighSame {
		neighVal = fmt.Sprintf("%s ≠ %s", wNeigh, fNeigh)
	}
	printStage(stageNum, "Neighbor ARP/NDP", neighSame, neighVal, rootCauseMarker("Neighbor", "ARP"))
	printConnector()
	stageNum++

	// Stage 6: Interface MTU & Link Flags
	wMTU := formatMTUStr(w.Interface)
	fMTU := formatMTUStr(f.Interface)
	mtuSame := (wMTU == fMTU)
	mtuVal := wMTU
	if !mtuSame {
		mtuVal = fmt.Sprintf("%s ≠ %s", wMTU, fMTU)
	}
	printStage(stageNum, "Interface MTU & Link", mtuSame, mtuVal, rootCauseMarker("MTU"))
	printConnector()
	stageNum++

	// Stage 7: Host Firewall Packet Filtering (if active on either host)
	wFwActive := w.Firewall != nil && w.Firewall.Active
	fFwActive := f.Firewall != nil && f.Firewall.Active
	if wFwActive || fFwActive {
		wFwStr := "inactive"
		if wFwActive {
			wFwStr = fmt.Sprintf("active (%s)", w.Firewall.Backend)
		}
		fFwStr := "inactive"
		if fFwActive {
			fFwStr = fmt.Sprintf("active (%s)", f.Firewall.Backend)
		}
		fwSame := (wFwStr == fFwStr)
		fwVal := wFwStr
		if !fwSame {
			fwVal = fmt.Sprintf("%s ≠ %s", wFwStr, fFwStr)
		}
		printStage(stageNum, "Host Packet Filtering", fwSame, fwVal, rootCauseMarker("Firewall"))
		printConnector()
		stageNum++
	}

	// Stage 8: TCP Dial & Kernel Socket Telemetry
	wTCPStr := formatTCPDetail(w.TCP)
	fTCPStr := formatTCPDetail(f.TCP)
	tcpSame := (w.TCP != nil && f.TCP != nil && w.TCP.Status == f.TCP.Status)
	if f.TCP != nil && f.TCP.SocketInfo != nil && f.TCP.SocketInfo.TotalRetrans > 0 {
		tcpSame = false
	}
	tcpVal := wTCPStr
	if !tcpSame {
		tcpVal = fmt.Sprintf("%s ≠ %s", wTCPStr, fTCPStr)
	}
	printStage(stageNum, "TCP Connection", tcpSame, tcpVal, rootCauseMarker("TCP"))

	// Sub-branch for Kernel Socket Telemetry
	hasSocketInfo := (w.TCP != nil && w.TCP.SocketInfo != nil) || (f.TCP != nil && f.TCP.SocketInfo != nil)
	if hasSocketInfo {
		wSock := formatSocketTelemetry(w.TCP)
		fSock := formatSocketTelemetry(f.TCP)
		sockSame := (wSock == fSock)
		sockVal := wSock
		if !sockSame {
			sockVal = fmt.Sprintf("%s ≠ %s", wSock, fSock)
		}
		printBranch("Kernel Socket Stats", sockSame, sockVal, true, rootCauseMarker("retransmits", "kernel_rtt"))
	}

	// Stage 9: TLS Handshake (if TLS collected or target is TLS and connected)
	if w.TLS != nil || f.TLS != nil || (comp.Target.IsTLS() && w.TCP != nil && w.TCP.Status == model.TCPStatusConnected) {
		printConnector()
		stageNum++

		wTLSStr := formatTLSDetail(w.TLS)
		fTLSStr := formatTLSDetail(f.TLS)
		tlsSame := (wTLSStr == fTLSStr)
		if w.TLS != nil && f.TLS != nil {
			tlsSame = (w.TLS.HandshakeSuccess == f.TLS.HandshakeSuccess)
		}
		tlsVal := wTLSStr
		if !tlsSame {
			tlsVal = fmt.Sprintf("%s ≠ %s", wTLSStr, fTLSStr)
		}
		printStage(stageNum, "TLS Handshake", tlsSame, tlsVal, rootCauseMarker("TLS"))
	}

	fmt.Fprintf(p.Out, "\n%s%s%s\n", ColorMuted, strings.Repeat("─", 74), ColorReset)

	// Root Cause Summary Box
	if comp.EarliestDivergence != "" {
		fmt.Fprintf(p.Out, "\n%s%s╭─────────────────────────────────────────────────────────────────────────────╮%s\n", ColorBold, ColorYellow, ColorReset)
		fmt.Fprintf(p.Out, "%s%s│ ROOT CAUSE (Earliest Divergence):%s\n", ColorBold, ColorYellow, ColorReset)
		fmt.Fprintf(p.Out, "%s%s│   %s%s\n", ColorBold, ColorYellow, comp.EarliestDivergence, ColorReset)
		if exp != nil && exp.Summary != "" {
			fmt.Fprintf(p.Out, "%s│%s\n", ColorYellow, ColorReset)
			wrapped := wrapText(exp.Summary, 72, "")
			for _, line := range strings.Split(wrapped, "\n") {
				fmt.Fprintf(p.Out, "%s│%s  %-72s\n", ColorYellow, ColorReset, line)
			}
		}
		fmt.Fprintf(p.Out, "%s%s╰─────────────────────────────────────────────────────────────────────────────╯%s\n", ColorBold, ColorYellow, ColorReset)
	}

	// Recommended Validation Probe
	if exp != nil && exp.NextBestProbe != nil {
		probeCmd := ""
		if exp.NextBestProbe.ProbeName == "TEST_INTERFACE_STATE" {
			probeCmd = fmt.Sprintf("netdiff probe %s %s", exp.NextBestProbe.ProbeName, exp.NextBestProbe.Parameter)
		} else {
			probeCmd = fmt.Sprintf("netdiff probe %s %s -t %s", exp.NextBestProbe.ProbeName, exp.NextBestProbe.Parameter, target)
		}
		fmt.Fprintf(p.Out, "\n%sRecommended Validation Probe:%s\n", ColorBold, ColorReset)
		fmt.Fprintf(p.Out, "  %s%s%s\n", ColorGreen, probeCmd, ColorReset)
		if exp.NextBestProbe.Reason != "" {
			fmt.Fprintf(p.Out, "  %sRationale: %s%s\n", ColorMuted, exp.NextBestProbe.Reason, ColorReset)
		}
		fmt.Fprintln(p.Out)
	}
}

func formatRouteTable(r *model.RouteReport) string {
	if r == nil {
		return "none"
	}
	if r.TableName != "" {
		return fmt.Sprintf("table %d (%s)", r.Table, r.TableName)
	}
	return fmt.Sprintf("table %d", r.Table)
}

func formatRouteOutcome(r *model.RouteReport) string {
	if r == nil {
		return "unknown"
	}
	if r.Success {
		return "success (route found)"
	}
	if r.Error != "" {
		return fmt.Sprintf("failed (%s)", r.Error)
	}
	return "failed"
}

func formatNeighborStr(n *model.NeighborReport) string {
	if n == nil || n.IP == "" {
		return "none"
	}
	mac := n.MAC
	if mac == "" {
		mac = "no-mac"
	}
	state := n.State
	if state == "" {
		state = "REACHABLE"
	}
	return fmt.Sprintf("%s → %s (%s)", n.IP, mac, state)
}

func formatMTUStr(i *model.InterfaceReport) string {
	if i == nil {
		return "1500 bytes"
	}
	mtu := i.MTU
	if mtu == 0 {
		mtu = 1500
	}
	oper := i.OperState
	if oper == "" {
		oper = "up"
	}
	return fmt.Sprintf("%d bytes (oper: %s)", mtu, oper)
}

func formatTCPDetail(t *model.TCPReport) string {
	if t == nil {
		return "not collected"
	}
	if t.Status == model.TCPStatusConnected {
		return fmt.Sprintf("connected (%dms)", t.LatencyMs)
	}
	if t.Error != "" {
		return fmt.Sprintf("%s (%s)", t.Status, t.Error)
	}
	return string(t.Status)
}

func formatSocketTelemetry(t *model.TCPReport) string {
	if t == nil || t.SocketInfo == nil {
		return "none"
	}
	s := t.SocketInfo
	var parts []string
	if s.RTTUs > 0 {
		parts = append(parts, fmt.Sprintf("RTT: %.2fms", float64(s.RTTUs)/1000.0))
	}
	if s.TotalRetrans > 0 {
		parts = append(parts, fmt.Sprintf("retrans: %d", s.TotalRetrans))
	} else {
		parts = append(parts, "retrans: 0")
	}
	if s.SndCwnd > 0 {
		parts = append(parts, fmt.Sprintf("cwnd: %d", s.SndCwnd))
	}
	if s.Pmtu > 0 {
		parts = append(parts, fmt.Sprintf("pmtu: %d", s.Pmtu))
	}
	return strings.Join(parts, ", ")
}

func formatTLSDetail(tls *model.TLSReport) string {
	if tls == nil {
		return "not performed"
	}
	if tls.HandshakeSuccess {
		extra := ""
		if tls.Issuer != "" {
			extra = fmt.Sprintf(" (%s)", tls.Issuer)
		}
		return fmt.Sprintf("success %s%s", tls.Version, extra)
	}
	errStr := tls.Error
	if errStr == "" {
		errStr = "handshake failed"
	}
	cat := ""
	if tls.ErrorCategory != "" {
		cat = fmt.Sprintf(" [%s]", tls.ErrorCategory)
	}
	return fmt.Sprintf("failed: %s%s", errStr, cat)
}
