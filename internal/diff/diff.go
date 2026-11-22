package diff

import (
	"fmt"
	"strings"

	"netdiff/internal/dag"
	"netdiff/internal/normalize"
	"netdiff/pkg/model"
)

// Compare analyzes a working and failing snapshot, producing a list of categorized differences.
func Compare(workingRaw, failingRaw *model.Snapshot) *model.ComparisonReport {
	working := normalize.Snapshot(workingRaw)
	failing := normalize.Snapshot(failingRaw)

	d := dag.BuildDAG(working, failing)
	earliest := ""
	if d != nil && d.EarliestDivergence != nil {
		earliest = fmt.Sprintf("%s: %s != %s", d.EarliestDivergence.Type, d.EarliestDivergence.WorkingVal, d.EarliestDivergence.FailingVal)
	}

	report := &model.ComparisonReport{
		WorkingSnapshot:    working,
		FailingSnapshot:    failing,
		WorkingHost:        working.Metadata.Hostname,
		FailingHost:        failing.Metadata.Hostname,
		Target:             working.Target,
		EarliestDivergence: earliest,
	}

	var diffs []model.Difference

	// 1. TCP Symptom Diff & Socket Telemetry
	tcpDiffs := diffTCP(working.TCP, failing.TCP)
	diffs = append(diffs, tcpDiffs...)

	// 2. DNS Resolution Diff
	dnsDiffs := diffDNS(working.DNS, failing.DNS)
	diffs = append(diffs, dnsDiffs...)

	// 3. Proxy Configuration Diff
	proxyDiffs := diffProxy(working.Proxy, failing.Proxy)
	diffs = append(diffs, proxyDiffs...)

	// 4. Route Selection Diff
	routeDiffs := diffRoute(working.Route, failing.Route)
	diffs = append(diffs, routeDiffs...)

	// 5. Interface Link Diff
	ifaceDiffs := diffInterface(working.Interface, failing.Interface)
	diffs = append(diffs, ifaceDiffs...)

	// 6. Neighbor Table Diff
	neighDiffs := diffNeighbor(working.Neighbor, failing.Neighbor)
	diffs = append(diffs, neighDiffs...)

	// 7. Firewall Diff
	fwDiffs := diffFirewall(working.Firewall, failing.Firewall)
	diffs = append(diffs, fwDiffs...)

	// 8. TLS Handshake Diff
	tlsDiffs := diffTLS(working.TLS, failing.TLS)
	diffs = append(diffs, tlsDiffs...)

	// Score and refine relevance based on the observed TCP symptom and causal graph
	report.Differences = evaluateRelevance(diffs, working, failing)
	report.Summary = generateSummary(report)

	return report
}

func diffTCP(w, f *model.TCPReport) []model.Difference {
	var diffs []model.Difference
	if w == nil || f == nil {
		return diffs
	}

	if w.Status != f.Status {
		diffs = append(diffs, model.Difference{
			Category:       "TCP",
			Field:          "status",
			WorkingValue:   string(w.Status),
			FailingValue:   string(f.Status),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "TCP",
			Rationale:      fmt.Sprintf("Working environment %s while failing environment encountered %s.", w.Status, f.Status),
		})
	}

	// Socket Telemetry: Packet Retransmissions
	if f.SocketInfo != nil && (f.SocketInfo.TotalRetrans > 0 || f.SocketInfo.Retransmits > 0) {
		wRetrans := uint32(0)
		if w.SocketInfo != nil {
			wRetrans = w.SocketInfo.TotalRetrans
		}
		if f.SocketInfo.TotalRetrans > wRetrans || f.SocketInfo.Retransmits > 0 {
			diffs = append(diffs, model.Difference{
				Category:       "TCP",
				Field:          "retransmits",
				WorkingValue:   fmt.Sprintf("%d retransmits", wRetrans),
				FailingValue:   fmt.Sprintf("%d retransmits", f.SocketInfo.TotalRetrans),
				Relevance:      model.RelevanceHigh,
				DependencyNode: "TCP",
				Rationale:      fmt.Sprintf("Kernel socket telemetry reports %d packet retransmissions on failing connection, indicating network segment loss.", f.SocketInfo.TotalRetrans),
			})
		}
	}

	// Socket Telemetry: RTT Divergence
	if w.SocketInfo != nil && f.SocketInfo != nil && w.SocketInfo.RTTUs > 0 && f.SocketInfo.RTTUs > 0 {
		if f.SocketInfo.RTTUs >= 3*w.SocketInfo.RTTUs && f.SocketInfo.RTTUs > 50000 {
			diffs = append(diffs, model.Difference{
				Category:       "TCP",
				Field:          "kernel_rtt",
				WorkingValue:   fmt.Sprintf("%.2fms", float64(w.SocketInfo.RTTUs)/1000.0),
				FailingValue:   fmt.Sprintf("%.2fms", float64(f.SocketInfo.RTTUs)/1000.0),
				Relevance:      model.RelevanceMedium,
				DependencyNode: "TCP",
				Rationale:      fmt.Sprintf("Kernel socket RTT is significantly higher on failing connection (%.2fms vs %.2fms).", float64(f.SocketInfo.RTTUs)/1000.0, float64(w.SocketInfo.RTTUs)/1000.0),
			})
		}
	}

	// Socket Telemetry: Path MTU
	if w.SocketInfo != nil && f.SocketInfo != nil && w.SocketInfo.Pmtu > 0 && f.SocketInfo.Pmtu > 0 && w.SocketInfo.Pmtu != f.SocketInfo.Pmtu {
		diffs = append(diffs, model.Difference{
			Category:       "TCP",
			Field:          "socket_pmtu",
			WorkingValue:   fmt.Sprintf("%d bytes", w.SocketInfo.Pmtu),
			FailingValue:   fmt.Sprintf("%d bytes", f.SocketInfo.Pmtu),
			Relevance:      model.RelevanceMedium,
			DependencyNode: "MTU",
			Rationale:      fmt.Sprintf("Kernel socket Path MTU differs (working: %d bytes, failing: %d bytes).", w.SocketInfo.Pmtu, f.SocketInfo.Pmtu),
		})
	}

	return diffs
}

func diffDNS(w, f *model.DNSReport) []model.Difference {
	var diffs []model.Difference
	if w == nil || f == nil {
		return diffs
	}

	if w.Success != f.Success {
		diffs = append(diffs, model.Difference{
			Category:       "DNS",
			Field:          "resolution_success",
			WorkingValue:   fmt.Sprintf("%v", w.Success),
			FailingValue:   fmt.Sprintf("%v (%s)", f.Success, f.Error),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "DNS",
			Rationale:      "DNS resolution failed in the failing environment before routing could occur.",
		})
		return diffs
	}

	wA := strings.Join(w.ARecords, ", ")
	fA := strings.Join(f.ARecords, ", ")
	if wA != fA && (len(w.ARecords) > 0 || len(f.ARecords) > 0) {
		diffs = append(diffs, model.Difference{
			Category:       "DNS",
			Field:          "a_records",
			WorkingValue:   wA,
			FailingValue:   fA,
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Destination",
			Rationale:      "Hostname resolved to different destination IP addresses.",
		})
	}

	return diffs
}

func diffProxy(w, f *model.ProxyReport) []model.Difference {
	var diffs []model.Difference
	if w == nil || f == nil {
		return diffs
	}

	if w.Active != f.Active || w.HTTPProxy != f.HTTPProxy || w.HTTPSProxy != f.HTTPSProxy {
		wStr := "none"
		if w.Active {
			wStr = firstNonEmpty(w.HTTPSProxy, w.HTTPProxy)
		}
		fStr := "none"
		if f.Active {
			fStr = firstNonEmpty(f.HTTPSProxy, f.HTTPProxy)
		}

		diffs = append(diffs, model.Difference{
			Category:       "Proxy",
			Field:          "proxy_configuration",
			WorkingValue:   wStr,
			FailingValue:   fStr,
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Proxy",
			Rationale:      "Proxy configuration alters traffic routing and egress path.",
		})
	}
	return diffs
}

func diffRoute(w, f *model.RouteReport) []model.Difference {
	var diffs []model.Difference
	if w == nil || f == nil {
		return diffs
	}

	if w.Success != f.Success {
		diffs = append(diffs, model.Difference{
			Category:       "Route",
			Field:          "route_lookup_success",
			WorkingValue:   fmt.Sprintf("%t", w.Success),
			FailingValue:   fmt.Sprintf("%t", f.Success),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Route",
			Rationale: fmt.Sprintf(
				"Route lookup outcome changed. Working: %t; failing: %t. Failure evidence: %s",
				w.Success,
				f.Success,
				f.Error,
			),
		})
	}

	if w.PolicyRule != f.PolicyRule && (w.PolicyRule != "" || f.PolicyRule != "") {
		diffs = append(diffs, model.Difference{
			Category:       "Policy",
			Field:          "policy_rule",
			WorkingValue:   firstNonEmpty(w.PolicyRule, "lookup main"),
			FailingValue:   firstNonEmpty(f.PolicyRule, "missing / lookup main"),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Policy Rule",
			Rationale:      "Policy routing rules diverge before route table lookup occurs.",
		})
	}

	if w.Table != f.Table {
		diffs = append(diffs, model.Difference{
			Category:       "Route",
			Field:          "routing_table",
			WorkingValue:   fmt.Sprintf("table %d (%s)", w.Table, w.TableName),
			FailingValue:   fmt.Sprintf("table %d (%s)", f.Table, f.TableName),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Route",
			Rationale:      "Failing host uses a different routing table (policy routing divergence).",
		})
	}

	if w.EgressInterface != f.EgressInterface && w.EgressInterface != "" && f.EgressInterface != "" {
		diffs = append(diffs, model.Difference{
			Category:       "Route",
			Field:          "egress_interface",
			WorkingValue:   w.EgressInterface,
			FailingValue:   f.EgressInterface,
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Interface",
			Rationale:      fmt.Sprintf("Failing environment routes destination out %s instead of %s.", f.EgressInterface, w.EgressInterface),
		})
	}

	if w.Gateway != f.Gateway && (w.Gateway != "" || f.Gateway != "") {
		diffs = append(diffs, model.Difference{
			Category:       "Route",
			Field:          "gateway",
			WorkingValue:   firstNonEmpty(w.Gateway, "direct/none"),
			FailingValue:   firstNonEmpty(f.Gateway, "direct/none"),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Route",
			Rationale:      "Next-hop gateway differs between environments.",
		})
	}

	if w.PreferredSource != f.PreferredSource && (w.PreferredSource != "" || f.PreferredSource != "") {
		diffs = append(diffs, model.Difference{
			Category:       "Source",
			Field:          "source_address",
			WorkingValue:   firstNonEmpty(w.PreferredSource, "auto"),
			FailingValue:   firstNonEmpty(f.PreferredSource, "auto"),
			Relevance:      model.RelevanceMedium,
			DependencyNode: "Source",
			Rationale:      "Source IP address selected for packets diverges.",
		})
	}

	return diffs
}

func diffInterface(w, f *model.InterfaceReport) []model.Difference {
	var diffs []model.Difference
	if w == nil && f == nil {
		return diffs
	}

	if w != nil && f == nil {
		diffs = append(diffs, model.Difference{
			Category:       "Interface",
			Field:          "interface_collected",
			WorkingValue:   w.Name,
			FailingValue:   "not_collected / unavailable",
			Relevance:      model.RelevanceMedium,
			DependencyNode: "Interface",
			Rationale:      "Egress interface link details were collected for working environment but unavailable in failing environment (e.g. unrouted).",
		})
		return diffs
	}

	if w == nil && f != nil {
		return diffs
	}

	// Interface presence / errors
	if (w.Error == "") != (f.Error == "") {
		wVal := "present"
		if w.Error != "" {
			wVal = "error: " + w.Error
		}
		fVal := "present"
		if f.Error != "" {
			fVal = "error: " + f.Error
		}
		diffs = append(diffs, model.Difference{
			Category:       "Interface",
			Field:          "interface_presence",
			WorkingValue:   wVal,
			FailingValue:   fVal,
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Interface",
			Rationale:      "Interface presence differs between environments.",
		})
	}

	// Administrative state (UP flag)
	wUp := hasFlag(w.Flags, "UP")
	fUp := hasFlag(f.Flags, "UP")
	if wUp != fUp {
		diffs = append(diffs, model.Difference{
			Category:       "Interface",
			Field:          "admin_state",
			WorkingValue:   flagAdminStr(wUp),
			FailingValue:   flagAdminStr(fUp),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Interface",
			Rationale:      fmt.Sprintf("Interface administrative state differs: working is %s while failing is %s.", flagAdminStr(wUp), flagAdminStr(fUp)),
		})
	}

	// Operational state
	if w.OperState != f.OperState && w.OperState != "" && f.OperState != "" {
		diffs = append(diffs, model.Difference{
			Category:       "Interface",
			Field:          "oper_state",
			WorkingValue:   w.OperState,
			FailingValue:   f.OperState,
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Interface",
			Rationale:      fmt.Sprintf("Interface operational state differs: working is %s while failing is %s.", w.OperState, f.OperState),
		})
	}

	if w.Role != f.Role && w.Role != "" && f.Role != "" {
		diffs = append(diffs, model.Difference{
			Category:       "Interface",
			Field:          "interface_role",
			WorkingValue:   w.Role,
			FailingValue:   f.Role,
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Interface",
			Rationale:      fmt.Sprintf("Working uses a %s interface while failing uses a %s interface.", w.Role, f.Role),
		})
	}

	if w.MTU != f.MTU && w.MTU > 0 && f.MTU > 0 {
		diffs = append(diffs, model.Difference{
			Category:       "Interface",
			Field:          "mtu",
			WorkingValue:   fmt.Sprintf("%d", w.MTU),
			FailingValue:   fmt.Sprintf("%d", f.MTU),
			Relevance:      model.RelevanceMedium,
			DependencyNode: "MTU",
			Rationale:      "MTU size difference may impact large packet traversal.",
		})
	}

	return diffs
}

func hasFlag(flags []string, target string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, target) {
			return true
		}
	}
	return false
}

func flagAdminStr(up bool) string {
	if up {
		return "UP"
	}
	return "DOWN"
}

func diffNeighbor(w, f *model.NeighborReport) []model.Difference {
	var diffs []model.Difference
	if w == nil || f == nil {
		return diffs
	}

	if w.Present != f.Present {
		diffs = append(diffs, model.Difference{
			Category:       "Neighbor",
			Field:          "arp_resolution",
			WorkingValue:   fmt.Sprintf("present=%t (mac=%s)", w.Present, w.MAC),
			FailingValue:   fmt.Sprintf("present=%t (mac=%s)", f.Present, f.MAC),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Neighbor ARP",
			Rationale:      "Next-hop Layer 2 neighbor entry presence differs.",
		})
	}

	if w.State != f.State && (w.State != "" || f.State != "") {
		diffs = append(diffs, model.Difference{
			Category:       "Neighbor",
			Field:          "arp_state",
			WorkingValue:   firstNonEmpty(w.State, "none"),
			FailingValue:   firstNonEmpty(f.State, "none"),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "Neighbor ARP",
			Rationale:      "Neighbor ARP/NDP resolution state diverges.",
		})
	}

	if w.MAC != f.MAC && w.MAC != "" && f.MAC != "" {
		diffs = append(diffs, model.Difference{
			Category:       "Neighbor",
			Field:          "arp_mac",
			WorkingValue:   w.MAC,
			FailingValue:   f.MAC,
			Relevance:      model.RelevanceMedium,
			DependencyNode: "Neighbor ARP",
			Rationale:      "Next-hop MAC address diverges between environments.",
		})
	}

	return diffs
}

func evaluateRelevance(diffs []model.Difference, working, failing *model.Snapshot) []model.Difference {
	isRefused := failing.TCP != nil && failing.TCP.Status == model.TCPStatusRefused
	isTimeout := failing.TCP != nil && failing.TCP.Status == model.TCPStatusTimeout
	isUnreachable := failing.TCP != nil && (failing.TCP.Status == model.TCPStatusUnreachable || failing.TCP.Status == model.TCPStatusFailed)
	routeLookupFailed := failing.Route != nil && !failing.Route.Success

	for i := range diffs {
		d := &diffs[i]

		// When connection is refused, the network reached the remote host
		if isRefused && d.Category != "TCP" {
			if d.Relevance == model.RelevanceHigh {
				d.Relevance = model.RelevanceMedium
				d.Rationale += " Note: Connection was actively refused, confirming path reachability."
			}
		}

		// When route lookup failed, downstream source address and interface differences are downstream consequences
		if routeLookupFailed && (d.Field == "source_address" || d.Field == "egress_interface") {
			d.Relevance = model.RelevanceMedium
		}

		// When TCP timed out and failing environment has active firewall filtering, promote firewall
		if isTimeout && d.Category == "Firewall" && failing.Firewall != nil && failing.Firewall.Active {
			d.Relevance = model.RelevanceHigh
			d.Rationale = "Host packet filtering (iptables/nftables) is active while connection timed out, suggesting packets may be silently dropped."
		}

		// When TCP timed out, unreachable, or failed, and failing neighbor resolution is INCOMPLETE or FAILED or not present
		if (isTimeout || isUnreachable || failing.TCP == nil) &&
			failing.Neighbor != nil &&
			(strings.EqualFold(failing.Neighbor.State, "INCOMPLETE") || strings.EqualFold(failing.Neighbor.State, "FAILED") || !failing.Neighbor.Present) &&
			d.Category == "Neighbor" {
			d.Relevance = model.RelevanceHigh
			d.Rationale = fmt.Sprintf("Next-hop ARP/neighbor resolution failed on failing host (state: %s, MAC: %q). Packets cannot be encapsulated at Layer 2.", failing.Neighbor.State, failing.Neighbor.MAC)
		}
	}

	return diffs
}

func generateSummary(r *model.ComparisonReport) string {
	var highPathDiffs []model.Difference
	var tcpDiff *model.Difference

	for _, d := range r.Differences {
		if d.Category == "TCP" {
			tcpDiff = &d
			continue
		}
		if d.Relevance == model.RelevanceHigh {
			highPathDiffs = append(highPathDiffs, d)
		}
	}

	if len(highPathDiffs) == 0 {
		if tcpDiff != nil && r.FailingSnapshot.TCP != nil && r.FailingSnapshot.TCP.Status == model.TCPStatusRefused {
			return fmt.Sprintf("Network path to %s is fully reachable, but connection was actively refused by the destination host (port %d closed or service not listening).", r.Target.Raw, r.Target.Port)
		}
		if tcpDiff != nil {
			return fmt.Sprintf("No high-relevance network path divergence detected. %s", tcpDiff.Rationale)
		}
		return "No high-relevance path differences detected between environments."
	}

	var highNames []string
	for _, d := range highPathDiffs {
		highNames = append(highNames, fmt.Sprintf("%s (%s != %s)", d.Field, d.WorkingValue, d.FailingValue))
	}

	primary := highPathDiffs[0]
	return fmt.Sprintf("Primary divergence detected in: %s. %s", strings.Join(highNames, ", "), primary.Rationale)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func diffFirewall(w, f *model.FirewallReport) []model.Difference {
	var diffs []model.Difference
	if w == nil || f == nil {
		return diffs
	}

	if w.Active != f.Active {
		wStr := "inactive"
		if w.Active {
			wStr = w.Backend
		}
		fStr := "inactive"
		if f.Active {
			fStr = f.Backend
		}
		diffs = append(diffs, model.Difference{
			Category:       "Firewall",
			Field:          "filtering_backend",
			WorkingValue:   wStr,
			FailingValue:   fStr,
			Relevance:      model.RelevanceMedium,
			DependencyNode: "Firewall",
			Rationale:      "Host firewall packet filtering is active on one environment and may drop connection attempts.",
		})
	}
	return diffs
}

func diffTLS(w, f *model.TLSReport) []model.Difference {
	var diffs []model.Difference
	if w == nil && f == nil {
		return diffs
	}

	if w != nil && f == nil {
		diffs = append(diffs, model.Difference{
			Category:       "TLS",
			Field:          "tls_handshake",
			WorkingValue:   fmt.Sprintf("success (%s)", w.Version),
			FailingValue:   "not_performed",
			Relevance:      model.RelevanceHigh,
			DependencyNode: "TLS Handshake",
			Rationale:      "TLS handshake was successful in working environment but not completed in failing environment.",
		})
		return diffs
	}

	if w == nil && f != nil {
		return diffs
	}

	if w.HandshakeSuccess != f.HandshakeSuccess {
		wVal := fmt.Sprintf("success (%s)", w.Version)
		if !w.HandshakeSuccess {
			wVal = fmt.Sprintf("failed (%s)", w.Error)
		}
		fVal := fmt.Sprintf("success (%s)", f.Version)
		if !f.HandshakeSuccess {
			fVal = fmt.Sprintf("failed (%s)", f.Error)
		}

		rationale := "TLS handshake succeeded on working environment but failed on failing environment."
		if f.ErrorCategory == "untrusted_root" {
			rationale = fmt.Sprintf("TLS certificate authority is untrusted on failing host (%s). Missing root CA in system trust store.", f.Error)
		} else if f.ErrorCategory == "expired" {
			rationale = fmt.Sprintf("TLS certificate expired on failing host (%s).", f.Error)
		} else if f.ErrorCategory == "hostname_mismatch" {
			rationale = fmt.Sprintf("TLS certificate Subject/SAN does not match hostname on failing host (%s).", f.Error)
		} else if f.Error != "" {
			rationale = fmt.Sprintf("TLS handshake failed: %s.", f.Error)
		}

		diffs = append(diffs, model.Difference{
			Category:       "TLS",
			Field:          "tls_handshake",
			WorkingValue:   wVal,
			FailingValue:   fVal,
			Relevance:      model.RelevanceHigh,
			DependencyNode: "TLS Handshake",
			Rationale:      rationale,
		})
		return diffs
	}

	if w.Version != f.Version && w.Version != "" && f.Version != "" {
		diffs = append(diffs, model.Difference{
			Category:       "TLS",
			Field:          "tls_version",
			WorkingValue:   w.Version,
			FailingValue:   f.Version,
			Relevance:      model.RelevanceMedium,
			DependencyNode: "TLS Handshake",
			Rationale:      "Negotiated TLS protocol version differs.",
		})
	}

	if w.CipherSuite != f.CipherSuite && w.CipherSuite != "" && f.CipherSuite != "" {
		diffs = append(diffs, model.Difference{
			Category:       "TLS",
			Field:          "cipher_suite",
			WorkingValue:   w.CipherSuite,
			FailingValue:   f.CipherSuite,
			Relevance:      model.RelevanceMedium,
			DependencyNode: "TLS Handshake",
			Rationale:      "Negotiated TLS cipher suite differs.",
		})
	}

	return diffs
}
