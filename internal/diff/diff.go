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

	// 1. TCP Symptom Diff (The observed outcome)
	tcpDiff := diffTCP(working.TCP, failing.TCP)
	if tcpDiff != nil {
		diffs = append(diffs, *tcpDiff)
	}

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

	// Score and refine relevance based on the observed TCP symptom and causal graph
	report.Differences = evaluateRelevance(diffs, working, failing)
	report.Summary = generateSummary(report)

	return report
}

func diffTCP(w, f *model.TCPReport) *model.Difference {
	if w == nil || f == nil {
		return nil
	}
	if w.Status != f.Status {
		return &model.Difference{
			Category:       "TCP",
			Field:          "status",
			WorkingValue:   string(w.Status),
			FailingValue:   string(f.Status),
			Relevance:      model.RelevanceHigh,
			DependencyNode: "TCP",
			Rationale:      fmt.Sprintf("Working environment %s while failing environment encountered %s.", w.Status, f.Status),
		}
	}
	return nil
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
	if w == nil || f == nil {
		return diffs
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

func diffNeighbor(w, f *model.NeighborReport) []model.Difference {
	var diffs []model.Difference
	if w == nil || f == nil {
		return diffs
	}

	if w.State != f.State && (w.State != "" || f.State != "") {
		diffs = append(diffs, model.Difference{
			Category:       "Neighbor",
			Field:          "arp_state",
			WorkingValue:   firstNonEmpty(w.State, "none"),
			FailingValue:   firstNonEmpty(f.State, "none"),
			Relevance:      model.RelevanceMedium,
			DependencyNode: "Neighbor",
			Rationale:      "Neighbor ARP/NDP resolution state diverges.",
		})
	}

	return diffs
}

func evaluateRelevance(diffs []model.Difference, working, failing *model.Snapshot) []model.Difference {
	// If TCP failed with Connection Refused, route/VPN are working, service is down
	isRefused := failing.TCP != nil && failing.TCP.Status == model.TCPStatusRefused

	for i := range diffs {
		d := &diffs[i]
		if isRefused && d.Category != "TCP" {
			// When connection is refused, the network reached the remote host
			if d.Relevance == model.RelevanceHigh {
				d.Relevance = model.RelevanceMedium
				d.Rationale += " Note: Connection was actively refused, confirming path reachability."
			}
		}
	}

	return diffs
}

func generateSummary(r *model.ComparisonReport) string {
	var highDiffs []string
	for _, d := range r.Differences {
		if d.Relevance == model.RelevanceHigh && d.Category != "TCP" {
			highDiffs = append(highDiffs, fmt.Sprintf("%s (%s != %s)", d.Field, d.WorkingValue, d.FailingValue))
		}
	}

	if len(highDiffs) == 0 {
		return "No high-relevance path differences detected between environments."
	}

	return fmt.Sprintf("Primary divergence detected in: %s. %s", strings.Join(highDiffs, ", "), r.Differences[0].Rationale)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
