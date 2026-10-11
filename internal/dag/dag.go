package dag

import (
	"fmt"
	"strings"

	"netdiff/pkg/model"
)

type NodeType string

const (
	NodeHostname        NodeType = "Hostname"
	NodeDNS             NodeType = "DNS"
	NodeDestinationIP   NodeType = "Destination IP"
	NodePolicyRule      NodeType = "Policy Rule"
	NodeRouteTable      NodeType = "Route Table"
	NodeGateway         NodeType = "Gateway"
	NodeSourceAddress   NodeType = "Source Address"
	NodeEgressInterface NodeType = "Egress Interface"
	NodeMTU             NodeType = "MTU"
	NodeNeighbor        NodeType = "Neighbor ARP"
	NodeTCP             NodeType = "TCP Connection"
)

// Node represents a point in the network dependency chain.
type Node struct {
	Type         NodeType `json:"type"`
	WorkingVal   string   `json:"working_val"`
	FailingVal   string   `json:"failing_val"`
	IsDivergent  bool     `json:"is_divergent"`
	Children     []*Node  `json:"-"`
}

// DAG represents the evaluated dependency graph for a target connection.
type DAG struct {
	Root               *Node   `json:"root"`
	Nodes              []*Node `json:"nodes"`
	EarliestDivergence *Node   `json:"earliest_divergence,omitempty"`
}

// BuildDAG constructs and evaluates the dependency path between working and failing snapshots.
func BuildDAG(working, failing *model.Snapshot) *DAG {
	if working == nil || failing == nil {
		return nil
	}

	d := &DAG{}

	// 1. Hostname
	wHost := working.Target.Host
	fHost := failing.Target.Host
	nHostname := &Node{
		Type:        NodeHostname,
		WorkingVal:  wHost,
		FailingVal:  fHost,
		IsDivergent: wHost != fHost,
	}

	// 2. DNS
	wDNS := formatDNS(working.DNS)
	fDNS := formatDNS(failing.DNS)
	nDNS := &Node{
		Type:        NodeDNS,
		WorkingVal:  wDNS,
		FailingVal:  fDNS,
		IsDivergent: wDNS != fDNS,
	}

	// 3. Destination IP
	wDest := formatDestIP(working)
	fDest := formatDestIP(failing)
	nDest := &Node{
		Type:        NodeDestinationIP,
		WorkingVal:  wDest,
		FailingVal:  fDest,
		IsDivergent: wDest != fDest,
	}

	// 4. Policy Rule
	wRule := formatRule(working.Route)
	fRule := formatRule(failing.Route)
	nRule := &Node{
		Type:        NodePolicyRule,
		WorkingVal:  wRule,
		FailingVal:  fRule,
		IsDivergent: wRule != fRule,
	}

	// 5. Route Table
	wTable := formatTable(working.Route)
	fTable := formatTable(failing.Route)
	nTable := &Node{
		Type:        NodeRouteTable,
		WorkingVal:  wTable,
		FailingVal:  fTable,
		IsDivergent: wTable != fTable,
	}

	// 6. Gateway
	wGw := formatGw(working.Route)
	fGw := formatGw(failing.Route)
	nGw := &Node{
		Type:        NodeGateway,
		WorkingVal:  wGw,
		FailingVal:  fGw,
		IsDivergent: wGw != fGw,
	}

	// 7. Source Address
	wSrc := formatSrc(working.Route)
	fSrc := formatSrc(failing.Route)
	nSrc := &Node{
		Type:        NodeSourceAddress,
		WorkingVal:  wSrc,
		FailingVal:  fSrc,
		IsDivergent: wSrc != fSrc,
	}

	// 8. Egress Interface
	wIface := formatIface(working.Route, working.Interface)
	fIface := formatIface(failing.Route, failing.Interface)
	nIface := &Node{
		Type:        NodeEgressInterface,
		WorkingVal:  wIface,
		FailingVal:  fIface,
		IsDivergent: wIface != fIface,
	}

	// 9. MTU
	wMTU := formatMTU(working.Interface)
	fMTU := formatMTU(failing.Interface)
	nMTU := &Node{
		Type:        NodeMTU,
		WorkingVal:  wMTU,
		FailingVal:  fMTU,
		IsDivergent: wMTU != fMTU,
	}

	// 10. TCP
	wTCP := formatTCP(working.TCP)
	fTCP := formatTCP(failing.TCP)
	nTCP := &Node{
		Type:        NodeTCP,
		WorkingVal:  wTCP,
		FailingVal:  fTCP,
		IsDivergent: wTCP != fTCP,
	}

	// Connect chain
	nHostname.Children = []*Node{nDNS}
	nDNS.Children = []*Node{nDest}
	nDest.Children = []*Node{nRule}
	nRule.Children = []*Node{nTable}
	nTable.Children = []*Node{nGw, nSrc, nIface}
	nIface.Children = []*Node{nMTU}
	nMTU.Children = []*Node{nTCP}

	d.Root = nHostname
	d.Nodes = []*Node{nHostname, nDNS, nDest, nRule, nTable, nGw, nSrc, nIface, nMTU, nTCP}

	// Find the earliest divergent node in order of propagation
	for _, n := range d.Nodes {
		if n.IsDivergent && n.Type != NodeHostname && n.Type != NodeTCP {
			d.EarliestDivergence = n
			break
		}
	}

	return d
}

func formatDNS(d *model.DNSReport) string {
	if d == nil {
		return "none"
	}
	if !d.Success {
		return "failed"
	}
	if len(d.ARecords) > 0 {
		return strings.Join(d.ARecords, ",")
	}
	return "resolved"
}

func formatDestIP(s *model.Snapshot) string {
	if s.Target.IsIP {
		return s.Target.Host
	}
	if s.Route != nil && s.Route.DestinationIP != "" {
		return s.Route.DestinationIP
	}
	if s.DNS != nil && len(s.DNS.ARecords) > 0 {
		return s.DNS.ARecords[0]
	}
	return "unknown"
}

func formatRule(r *model.RouteReport) string {
	if r == nil || r.PolicyRule == "" {
		return "default main"
	}
	return r.PolicyRule
}

func formatTable(r *model.RouteReport) string {
	if r == nil {
		return "main"
	}
	if r.TableName != "" {
		return r.TableName
	}
	return fmt.Sprintf("table %d", r.Table)
}

func formatGw(r *model.RouteReport) string {
	if r == nil || r.Gateway == "" {
		return "direct/none"
	}
	return r.Gateway
}

func formatSrc(r *model.RouteReport) string {
	if r == nil || r.PreferredSource == "" {
		return "auto"
	}
	return r.PreferredSource
}

func formatIface(r *model.RouteReport, i *model.InterfaceReport) string {
	name := "unknown"
	if r != nil && r.EgressInterface != "" {
		name = r.EgressInterface
	}
	if i != nil && i.Role != "" {
		return fmt.Sprintf("%s (%s)", name, i.Role)
	}
	return name
}

func formatMTU(i *model.InterfaceReport) string {
	if i == nil || i.MTU <= 0 {
		return "1500"
	}
	return fmt.Sprintf("%d", i.MTU)
}

func formatTCP(t *model.TCPReport) string {
	if t == nil {
		return "unknown"
	}
	return string(t.Status)
}
