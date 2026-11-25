package printer

import (
	"fmt"
	"html"
	"strings"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

// RenderSVG produces a standalone, clean GitHub Primer Dark vector SVG graphic of the Causal DAG.
// Designed for sharing in Slack, Jira, GitHub PRs, and incident reports without visual noise.
func RenderSVG(comp *model.ComparisonReport, exp *ai.ExplanationReport) string {
	if comp == nil {
		return ""
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

	type svgStage struct {
		Number   int
		Title    string
		Same     bool
		WVal     string
		FVal     string
		Earliest bool
		Branches []svgStage
	}

	var stages []svgStage
	stageNum := 1

	// 1. Hostname
	wHostVal := comp.Target.Host
	fHostVal := comp.Target.Host
	stages = append(stages, svgStage{
		Number:   stageNum,
		Title:    "Target Hostname",
		Same:     wHostVal == fHostVal,
		WVal:     wHostVal,
		FVal:     fHostVal,
		Earliest: isEarliest("Hostname"),
	})
	stageNum++

	// 2. DNS
	wDNSStr := formatDNS(w.DNS)
	fDNSStr := formatDNS(f.DNS)
	stages = append(stages, svgStage{
		Number:   stageNum,
		Title:    "DNS Resolution",
		Same:     wDNSStr == fDNSStr,
		WVal:     wDNSStr,
		FVal:     fDNSStr,
		Earliest: isEarliest("DNS"),
	})
	stageNum++

	// 3. Dest IP
	wDestIP := comp.Target.Host
	if w.Route != nil && w.Route.DestinationIP != "" {
		wDestIP = w.Route.DestinationIP
	}
	fDestIP := comp.Target.Host
	if f.Route != nil && f.Route.DestinationIP != "" {
		fDestIP = f.Route.DestinationIP
	}
	stages = append(stages, svgStage{
		Number:   stageNum,
		Title:    "Destination IP",
		Same:     wDestIP == fDestIP,
		WVal:     wDestIP,
		FVal:     fDestIP,
		Earliest: isEarliest("Destination"),
	})
	stageNum++

	// 4. Policy Routing & branches
	wRule := formatRule(w.Route)
	fRule := formatRule(f.Route)
	routeStage := svgStage{
		Number:   stageNum,
		Title:    "Policy Routing (ip rule)",
		Same:     wRule == fRule,
		WVal:     wRule,
		FVal:     fRule,
		Earliest: isEarliest("Policy"),
	}

	wTbl := formatRouteTable(w.Route)
	fTbl := formatRouteTable(f.Route)
	routeStage.Branches = append(routeStage.Branches, svgStage{
		Title:    "Routing Table",
		Same:     wTbl == fTbl,
		WVal:     wTbl,
		FVal:     fTbl,
		Earliest: isEarliest("Route Table"),
	})

	wLookup := formatRouteOutcome(w.Route)
	fLookup := formatRouteOutcome(f.Route)
	routeStage.Branches = append(routeStage.Branches, svgStage{
		Title:    "FIB Route Lookup",
		Same:     wLookup == fLookup,
		WVal:     wLookup,
		FVal:     fLookup,
		Earliest: isEarliest("Route Lookup"),
	})

	wDev := formatDev(w.Route)
	fDev := formatDev(f.Route)
	routeStage.Branches = append(routeStage.Branches, svgStage{
		Title:    "Egress Interface",
		Same:     wDev == fDev,
		WVal:     wDev,
		FVal:     fDev,
		Earliest: isEarliest("Egress", "Interface"),
	})

	wGw := formatGateway(w.Route)
	fGw := formatGateway(f.Route)
	routeStage.Branches = append(routeStage.Branches, svgStage{
		Title:    "Next-Hop Gateway",
		Same:     wGw == fGw,
		WVal:     wGw,
		FVal:     fGw,
		Earliest: isEarliest("Gateway"),
	})

	wSrc := formatSource(w.Route)
	fSrc := formatSource(f.Route)
	routeStage.Branches = append(routeStage.Branches, svgStage{
		Title:    "Source IP Selected",
		Same:     wSrc == fSrc,
		WVal:     wSrc,
		FVal:     fSrc,
		Earliest: isEarliest("Source"),
	})

	stages = append(stages, routeStage)
	stageNum++

	// 5. Neighbor
	wNeigh := formatNeighborStr(w.Neighbor)
	fNeigh := formatNeighborStr(f.Neighbor)
	stages = append(stages, svgStage{
		Number:   stageNum,
		Title:    "Neighbor ARP / NDP",
		Same:     wNeigh == fNeigh,
		WVal:     wNeigh,
		FVal:     fNeigh,
		Earliest: isEarliest("Neighbor", "ARP", "NDP"),
	})
	stageNum++

	// 6. MTU & Link
	wMTU := formatMTUStr(w.Interface)
	fMTU := formatMTUStr(f.Interface)
	stages = append(stages, svgStage{
		Number:   stageNum,
		Title:    "Interface MTU & Link",
		Same:     wMTU == fMTU,
		WVal:     wMTU,
		FVal:     fMTU,
		Earliest: isEarliest("MTU", "OperState"),
	})
	stageNum++

	// 7. Firewall (if active)
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
		stages = append(stages, svgStage{
			Number:   stageNum,
			Title:    "Host Packet Filter",
			Same:     wFwStr == fFwStr,
			WVal:     wFwStr,
			FVal:     fFwStr,
			Earliest: isEarliest("Firewall"),
		})
		stageNum++
	}

	// 8. TCP Handshake
	wTCP := formatTCPDetail(w.TCP)
	fTCP := formatTCPDetail(f.TCP)
	stages = append(stages, svgStage{
		Number:   stageNum,
		Title:    "TCP Connection",
		Same:     wTCP == fTCP,
		WVal:     wTCP,
		FVal:     fTCP,
		Earliest: isEarliest("TCP"),
	})
	stageNum++

	// 9. TLS Handshake (if applicable)
	if w.TLS != nil || f.TLS != nil || comp.Target.Port == 443 || comp.Target.Protocol == "https" {
		wTLS := formatTLSDetail(w.TLS)
		fTLS := formatTLSDetail(f.TLS)
		stages = append(stages, svgStage{
			Number:   stageNum,
			Title:    "TLS Handshake",
			Same:     wTLS == fTLS,
			WVal:     wTLS,
			FVal:     fTLS,
			Earliest: isEarliest("TLS"),
		})
		stageNum++
	}

	// Layout calculations
	cardWidth := 980
	startY := 142
	stageHeight := 48
	branchHeight := 30
	connectorHeight := 16

	curY := startY
	type renderedRow struct {
		y        int
		height   int
		stage    svgStage
		isBranch bool
	}
	var rows []renderedRow

	for _, s := range stages {
		rows = append(rows, renderedRow{y: curY, height: stageHeight, stage: s, isBranch: false})
		curY += stageHeight

		for _, b := range s.Branches {
			rows = append(rows, renderedRow{y: curY, height: branchHeight, stage: b, isBranch: true})
			curY += branchHeight
		}
		curY += connectorHeight
	}

	// Root Cause Box
	rootCauseY := curY + 8
	rootCauseHeight := 92
	curY = rootCauseY + rootCauseHeight + 14

	// Remediation Box
	remY := curY
	remHeight := 116
	if exp != nil && exp.Remediation != nil && exp.Remediation.ImmediateBash != "" {
		curY = remY + remHeight + 16
	} else {
		remHeight = 0
	}

	totalHeight := curY + 24

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">`+"\n", cardWidth, totalHeight, cardWidth, totalHeight))
	sb.WriteString(`  <defs>
    <style>
      .text-title { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 17px; font-weight: 700; fill: #e6edf3; }
      .text-sub { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 12px; fill: #8b949e; }
      .text-mono { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 12px; }
      .text-label { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 11px; font-weight: 600; letter-spacing: 0.3px; }
      .text-badge { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 10px; font-weight: 700; letter-spacing: 0.4px; }
    </style>
  </defs>
`)

	// Primer Dark Canvas Background
	sb.WriteString(fmt.Sprintf(`  <rect x="1" y="1" width="%d" height="%d" rx="10" fill="#0d1117" stroke="#30363d" stroke-width="1.5"/>`+"\n", cardWidth-2, totalHeight-2))

	// Header Panel
	sb.WriteString(`  <!-- Header -->
  <g transform="translate(32, 28)">
    <rect x="0" y="0" width="68" height="22" rx="6" fill="#21262d" stroke="#30363d" stroke-width="1"/>
    <text x="34" y="15" text-anchor="middle" class="text-badge" fill="#e6edf3">NETDIFF</text>
    
    <text x="80" y="17" class="text-title">Causal Dependency Graph</text>
    <text x="80" y="36" class="text-sub">Target-scoped network differential &amp; root cause trace</text>

    <!-- Target Badge -->
    <rect x="656" y="0" width="260" height="28" rx="6" fill="#161b22" stroke="#30363d" stroke-width="1"/>
    <circle cx="672" cy="14" r="3.5" fill="#58a6ff"/>
`)
	sb.WriteString(fmt.Sprintf(`    <text x="684" y="18" class="text-mono" fill="#e6edf3" font-weight="600">%s</text>`+"\n", html.EscapeString(target)))
	sb.WriteString(fmt.Sprintf(`    <text x="0" y="72" class="text-sub" font-size="12.5px">Path: <tspan fill="#3fb950" font-weight="600">[WORKING] %s</tspan>  vs  <tspan fill="#f85149" font-weight="600">[FAILING] %s</tspan></text>`+"\n", html.EscapeString(strings.ToUpper(wHost)), html.EscapeString(strings.ToUpper(fHost))))
	sb.WriteString(`    <text x="586" y="72" class="text-sub" font-size="11px"><tspan fill="#3fb950">● Match</tspan>   <tspan fill="#f85149">✗ Divergent</tspan>   <tspan fill="#d29922" font-weight="600">■ Root Cause</tspan></text>
    <line x1="0" y1="88" x2="916" y2="88" stroke="#30363d" stroke-width="1"/>
  </g>
`)

	// Render Tiers
	for _, row := range rows {
		st := row.stage
		y := row.y
		h := row.height

		if !row.isBranch {
			fillBg := "#161b22"
			strokeCol := "#30363d"
			if st.Earliest {
				fillBg = "#1b1710"
				strokeCol = "#d29922"
			} else if !st.Same {
				strokeCol = "#f85149"
			}

			// Left: Working Box
			sb.WriteString(fmt.Sprintf(`  <g transform="translate(32, %d)">
    <rect x="0" y="0" width="354" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="1"/>
    <text x="12" y="18" class="text-label" fill="#3fb950">WORKING</text>
    <text x="12" y="36" class="text-mono" fill="#e6edf3">%s</text>
  </g>
`, y, h, fillBg, strokeCol, html.EscapeString(truncateString(st.WVal, 40))))

			// Center: Connector Stage Pill
			sb.WriteString(fmt.Sprintf(`  <g transform="translate(402, %d)">
    <rect x="0" y="6" width="176" height="36" rx="6" fill="#0d1117" stroke="%s" stroke-width="1"/>
    <text x="88" y="25" text-anchor="middle" class="text-label" fill="%s">%s</text>
`, y, strokeCol, func() string {
				if st.Earliest {
					return "#d29922"
				}
				if !st.Same {
					return "#f85149"
				}
				return "#e6edf3"
			}(), html.EscapeString(st.Title)))

			if st.Earliest {
				sb.WriteString(`    <text x="88" y="37" text-anchor="middle" class="text-badge" fill="#d29922">ROOT CAUSE</text>` + "\n")
			}
			sb.WriteString("  </g>\n")

			// Right: Failing Box
			fStatusText := "MATCH"
			fStatusColor := "#3fb950"
			if !st.Same {
				fStatusText = "DIVERGENT"
				fStatusColor = "#f85149"
			}
			if st.Earliest {
				fStatusText = "ROOT CAUSE"
				fStatusColor = "#d29922"
			}
			sb.WriteString(fmt.Sprintf(`  <g transform="translate(594, %d)">
    <rect x="0" y="0" width="354" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="1"/>
    <text x="12" y="18" class="text-label" fill="%s">%s</text>
    <text x="342" y="18" text-anchor="end" class="text-badge" fill="%s">%s</text>
    <text x="12" y="36" class="text-mono" fill="#e6edf3">%s</text>
  </g>
`, y, h, fillBg, strokeCol, fStatusColor, func() string {
				if st.Earliest {
					return "FAILING (ROOT CAUSE)"
				}
				return "FAILING"
			}(), fStatusColor, fStatusText, html.EscapeString(truncateString(st.FVal, 40))))

		} else {
			bBg := "#0d1117"
			bStroke := "#21262d"
			if st.Earliest {
				bStroke = "#d29922"
				bBg = "#1b1710"
			} else if !st.Same {
				bStroke = "#f85149"
			}

			sb.WriteString(fmt.Sprintf(`  <!-- Branch: %s -->
  <g transform="translate(60, %d)">
    <rect x="0" y="0" width="326" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="1"/>
    <text x="10" y="19" class="text-sub" font-size="11px">%s: <tspan fill="#e6edf3" font-family="'SFMono-Regular', Consolas, monospace">%s</tspan></text>
  </g>
  <g transform="translate(594, %d)">
    <rect x="0" y="0" width="354" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="1"/>
    <text x="10" y="19" class="text-sub" font-size="11px">%s: <tspan fill="%s" font-family="'SFMono-Regular', Consolas, monospace">%s</tspan></text>
  </g>
`, html.EscapeString(st.Title), y, h, bBg, bStroke, html.EscapeString(st.Title), html.EscapeString(truncateString(st.WVal, 26)), y, h, bBg, bStroke, html.EscapeString(st.Title), func() string {
				if !st.Same {
					return "#f85149"
				}
				return "#e6edf3"
			}(), html.EscapeString(truncateString(st.FVal, 30))))
		}
	}

	// Root Cause Summary Box
	sb.WriteString(fmt.Sprintf(`  <!-- Root Cause Box -->
  <g transform="translate(32, %d)">
    <rect width="916" height="%d" rx="8" fill="#161b22" stroke="#d29922" stroke-width="1.2"/>
    <text x="20" y="26" class="text-label" fill="#d29922">ROOT CAUSE (EARLIEST DIVERGENCE ISOLATED)</text>
    <text x="20" y="50" class="text-title" font-size="15px">%s</text>
    <text x="20" y="72" class="text-sub" font-size="12px">%s</text>
  </g>
`, rootCauseY, rootCauseHeight, html.EscapeString(truncateString(earliest, 95)), func() string {
		if exp != nil && exp.Summary != "" {
			return html.EscapeString(truncateString(exp.Summary, 120))
		}
		return "Upstream causal path diverged at this node; downstream failures are cascade symptoms."
	}()))

	// Remediation Box (if present)
	if remHeight > 0 {
		rem := exp.Remediation
		sb.WriteString(fmt.Sprintf(`  <!-- Remediation Playbook -->
  <g transform="translate(32, %d)">
    <rect width="916" height="%d" rx="8" fill="#161b22" stroke="#30363d" stroke-width="1"/>
    <text x="20" y="26" class="text-label" fill="#3fb950">ACTIONABLE REMEDIATION PLAYBOOK</text>
    
    <rect x="20" y="40" width="876" height="30" rx="6" fill="#0d1117" stroke="#30363d"/>
    <text x="32" y="60" class="text-mono" fill="#e6edf3" font-weight="600">$ %s</text>

    <text x="20" y="94" class="text-sub" font-size="11.5px">Verify: <tspan fill="#58a6ff" font-family="'SFMono-Regular', Consolas, monospace">%s</tspan>  ·  %s</text>
  </g>
`, remY, remHeight, html.EscapeString(rem.ImmediateBash), html.EscapeString(rem.VerificationCmd), html.EscapeString(truncateString(rem.Explanation, 70))))
	}

	sb.WriteString("</svg>\n")
	return sb.String()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatDev(r *model.RouteReport) string {
	if r != nil && r.EgressInterface != "" {
		return r.EgressInterface
	}
	return "none"
}

func formatGateway(r *model.RouteReport) string {
	if r != nil && r.Gateway != "" {
		return r.Gateway
	}
	return "direct on-link"
}
