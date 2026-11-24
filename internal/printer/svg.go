package printer

import (
	"fmt"
	"html"
	"strings"

	"netdiff/internal/ai"
	"netdiff/pkg/model"
)

// RenderSVG produces a standalone, resolution-independent vector SVG graphic of the Causal DAG.
// It is designed for embedding or sharing in Slack, Jira, GitHub PRs, and incident reports.
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
	cardWidth := 1020
	startY := 160
	stageHeight := 52
	branchHeight := 34
	connectorHeight := 24

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
	rootCauseY := curY + 10
	rootCauseHeight := 105
	curY = rootCauseY + rootCauseHeight + 16

	// Remediation Box
	remY := curY
	remHeight := 130
	if exp != nil && exp.Remediation != nil && exp.Remediation.ImmediateBash != "" {
		curY = remY + remHeight + 20
	} else {
		remHeight = 0
	}

	totalHeight := curY + 40

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">`+"\n", cardWidth, totalHeight, cardWidth, totalHeight))
	sb.WriteString(`  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#090d16"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#00e5ff"/>
      <stop offset="100%" stop-color="#7c4dff"/>
    </linearGradient>
    <linearGradient id="amberGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#ffd600"/>
      <stop offset="100%" stop-color="#ff9100"/>
    </linearGradient>
    <filter id="glowCyan" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="6" result="blur"/>
      <feComposite in="SourceGraphic" in2="blur" operator="over"/>
    </filter>
    <style>
      .text-title { font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 19px; font-weight: 700; fill: #ffffff; }
      .text-sub { font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 12px; fill: #8899b8; }
      .text-mono { font-family: 'JetBrains Mono', monospace, Consolas; font-size: 12px; }
      .text-label { font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
      .text-badge { font-family: 'Inter', system-ui, -apple-system, sans-serif; font-size: 10px; font-weight: 800; letter-spacing: 0.5px; }
    </style>
  </defs>
`)

	// Card Background
	sb.WriteString(fmt.Sprintf(`  <rect width="%d" height="%d" rx="16" fill="url(#bgGrad)" stroke="#1e293b" stroke-width="1.5"/>`+"\n", cardWidth, totalHeight))

	// Header Panel
	sb.WriteString(`  <!-- Header -->
  <g transform="translate(36, 32)">
    <!-- Logo Badge -->
    <rect x="0" y="0" width="76" height="24" rx="6" fill="url(#headerGrad)"/>
    <text x="38" y="16" text-anchor="middle" class="text-badge" fill="#000000">NETDIFF</text>
    
    <text x="88" y="18" class="text-title">Causal Dependency Graph</text>
    <text x="88" y="38" class="text-sub">Differential Network Path Analysis &amp; Earliest Divergence Isolation</text>

    <!-- Target Badge -->
    <rect x="670" y="2" width="280" height="30" rx="15" fill="#141e33" stroke="#00e5ff" stroke-width="1.2"/>
    <circle cx="686" cy="17" r="4" fill="#00e5ff"/>
`)
	sb.WriteString(fmt.Sprintf(`    <text x="700" y="21" class="text-mono" fill="#00e5ff" font-weight="600">%s</text>`+"\n", html.EscapeString(target)))
	sb.WriteString(fmt.Sprintf(`    <text x="0" y="78" class="text-sub" font-size="13px">Path: <tspan fill="#00e676" font-weight="700">[WORKING] %s</tspan>  vs  <tspan fill="#ff1744" font-weight="700">[FAILING] %s</tspan></text>`+"\n", html.EscapeString(strings.ToUpper(wHost)), html.EscapeString(strings.ToUpper(fHost))))
	sb.WriteString(`    <text x="590" y="78" class="text-sub" font-size="11px">Legend: <tspan fill="#00e676">● Match</tspan>   <tspan fill="#ff1744">✗ Divergent</tspan>   <tspan fill="#ffd600" font-weight="700">◄── Earliest Divergence (Root Cause)</tspan></text>
    <line x1="0" y1="94" x2="948" y2="94" stroke="#1e293b" stroke-width="1"/>
  </g>
`)

	// Render Tiers
	for _, row := range rows {
		st := row.stage
		y := row.y
		h := row.height

		if !row.isBranch {
			// Stage Card
			fillBg := "#121a2d"
			strokeCol := "#24324f"
			if st.Earliest {
				fillBg = "#262010"
				strokeCol = "#ffd600"
			} else if !st.Same {
				strokeCol = "rgba(255, 23, 68, 0.5)"
			}

			// Left: Working Box
			sb.WriteString(fmt.Sprintf(`  <g transform="translate(36, %d)">
    <rect x="0" y="0" width="370" height="%d" rx="8" fill="%s" stroke="%s" stroke-width="1.2"/>
    <text x="14" y="20" class="text-label" fill="#00e676">WORKING</text>
    <text x="14" y="40" class="text-mono" fill="#f0f4fc">%s</text>
  </g>
`, y, h, fillBg, strokeCol, html.EscapeString(truncateString(st.WVal, 42))))

			// Center: Connector Stage Pill
			sb.WriteString(fmt.Sprintf(`  <g transform="translate(422, %d)">
    <rect x="0" y="6" width="176" height="38" rx="19" fill="#0c121e" stroke="%s" stroke-width="1.5"/>
    <text x="88" y="26" text-anchor="middle" class="text-label" fill="%s">%s</text>
`, y, strokeCol, func() string {
				if st.Earliest {
					return "#ffd600"
				}
				if !st.Same {
					return "#ff8a80"
				}
				return "#ffffff"
			}(), html.EscapeString(st.Title)))

			if st.Earliest {
				sb.WriteString(`    <text x="88" y="38" text-anchor="middle" class="text-badge" fill="#ffd600">ROOT CAUSE</text>` + "\n")
			}
			sb.WriteString("  </g>\n")

			// Right: Failing Box
			fStatusText := "✓ MATCH"
			fStatusColor := "#00e676"
			if !st.Same {
				fStatusText = "✗ DIVERGENT"
				fStatusColor = "#ff1744"
			}
			sb.WriteString(fmt.Sprintf(`  <g transform="translate(614, %d)">
    <rect x="0" y="0" width="370" height="%d" rx="8" fill="%s" stroke="%s" stroke-width="1.2"/>
    <text x="14" y="20" class="text-label" fill="%s">%s</text>
    <text x="356" y="20" text-anchor="end" class="text-badge" fill="%s">%s</text>
    <text x="14" y="40" class="text-mono" fill="#f0f4fc">%s</text>
  </g>
`, y, h, fillBg, strokeCol, fStatusColor, func() string {
				if st.Earliest {
					return "FAILING (ROOT CAUSE)"
				}
				return "FAILING"
			}(), fStatusColor, fStatusText, html.EscapeString(truncateString(st.FVal, 42))))

		} else {
			// Sub-Branch Row
			bBg := "#0d1424"
			bStroke := "#1e293b"
			if st.Earliest {
				bStroke = "#ffd600"
				bBg = "#1f1b0c"
			} else if !st.Same {
				bStroke = "rgba(255, 23, 68, 0.3)"
			}

			sb.WriteString(fmt.Sprintf(`  <!-- Branch: %s -->
  <g transform="translate(70, %d)">
    <rect x="0" y="0" width="336" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="1"/>
    <text x="12" y="21" class="text-sub" font-size="11px">%s: <tspan fill="#f0f4fc" font-family="'JetBrains Mono', monospace">%s</tspan></text>
  </g>
  <g transform="translate(614, %d)">
    <rect x="0" y="0" width="370" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="1"/>
    <text x="12" y="21" class="text-sub" font-size="11px">%s: <tspan fill="%s" font-family="'JetBrains Mono', monospace">%s</tspan></text>
  </g>
`, html.EscapeString(st.Title), y, h, bBg, bStroke, html.EscapeString(st.Title), html.EscapeString(truncateString(st.WVal, 28)), y, h, bBg, bStroke, html.EscapeString(st.Title), func() string {
				if !st.Same {
					return "#ff8a80"
				}
				return "#f0f4fc"
			}(), html.EscapeString(truncateString(st.FVal, 32))))
		}
	}

	// Root Cause Summary Box
	sb.WriteString(fmt.Sprintf(`  <!-- Root Cause Box -->
  <g transform="translate(36, %d)">
    <rect width="948" height="%d" rx="12" fill="#1b1708" stroke="#ffd600" stroke-width="1.5"/>
    <circle cx="28" cy="30" r="12" fill="rgba(255, 214, 0, 0.2)"/>
    <text x="28" y="34" text-anchor="middle" font-family="'Inter', sans-serif" font-weight="900" fill="#ffd600" font-size="13">!</text>
    <text x="50" y="28" class="text-label" fill="#ffd600">ROOT CAUSE (Earliest Divergence Isolated)</text>
    <text x="50" y="52" class="text-title" font-size="15px" fill="#ffffff">%s</text>
    <text x="50" y="78" class="text-sub" font-size="12px" fill="#cbd5e1">%s</text>
  </g>
`, rootCauseY, rootCauseHeight, html.EscapeString(truncateString(earliest, 95)), func() string {
		if exp != nil && exp.Summary != "" {
			return html.EscapeString(truncateString(exp.Summary, 125))
		}
		return "Upstream causal path diverged at this node; all downstream failures are cascade symptoms."
	}()))

	// Remediation Box (if present)
	if remHeight > 0 {
		rem := exp.Remediation
		sb.WriteString(fmt.Sprintf(`  <!-- Remediation Playbook -->
  <g transform="translate(36, %d)">
    <rect width="948" height="%d" rx="12" fill="#0c1815" stroke="#00e676" stroke-width="1.5"/>
    <text x="24" y="28" class="text-label" fill="#00e676">ACTIONABLE REMEDIATION PLAYBOOK</text>
    
    <text x="24" y="54" class="text-sub" font-size="12px" fill="#94a3b8">Immediate Bash Fix:</text>
    <rect x="24" y="62" width="900" height="28" rx="6" fill="#050b09" stroke="rgba(0, 230, 118, 0.3)"/>
    <text x="36" y="81" class="text-mono" fill="#00e676" font-weight="700">$ %s</text>

    <text x="24" y="110" class="text-sub" font-size="11px">Verification: <tspan fill="#00e5ff" font-family="'JetBrains Mono', monospace">%s</tspan>  |  <tspan fill="#cbd5e1">%s</tspan></text>
  </g>
`, remY, remHeight, html.EscapeString(rem.ImmediateBash), html.EscapeString(rem.VerificationCmd), html.EscapeString(truncateString(rem.Explanation, 75))))
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
