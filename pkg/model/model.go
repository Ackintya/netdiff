package model

import (
	"time"
)

// Target represents the network endpoint being diagnosed.
type Target struct {
	Raw      string `json:"raw"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" (default for v1)
	IsIP     bool   `json:"is_ip"`
}

// DNSReport captures resolution metrics and output for the target hostname.
type DNSReport struct {
	Hostname     string   `json:"hostname"`
	Nameservers  []string `json:"nameservers,omitempty"`
	ARecords     []string `json:"a_records,omitempty"`
	AAAARecords  []string `json:"aaaa_records,omitempty"`
	ResolutionMs int64    `json:"resolution_ms"`
	Success      bool     `json:"success"`
	Error        string   `json:"error,omitempty"`
}

// RouteReport captures route selection details to destination.
type RouteReport struct {
	DestinationIP   string `json:"destination_ip"`
	Table           int    `json:"table"`
	TableName       string `json:"table_name,omitempty"`
	Gateway         string `json:"gateway,omitempty"`
	EgressInterface string `json:"egress_interface"`
	PreferredSource string `json:"preferred_source,omitempty"`
	Metric          int    `json:"metric"`
	PolicyRule      string `json:"policy_rule,omitempty"`
	Success         bool   `json:"success"`
	Error           string `json:"error,omitempty"`
}

// InterfaceReport captures link details for the egress interface.
type InterfaceReport struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	Addresses []string `json:"addresses,omitempty"`
	MTU       int      `json:"mtu"`
	Flags     []string `json:"flags,omitempty"`
	OperState string   `json:"oper_state"`
	IsTunnel  bool     `json:"is_tunnel"` // Identified as tun/tap/wireguard/vpn
	Role      string   `json:"role,omitempty"` // "tunnel", "physical", "loopback", "virtual"
	Error     string   `json:"error,omitempty"`
}

// NeighborReport captures ARP/NDP neighbor entry for the gateway/next-hop.
type NeighborReport struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state,omitempty"` // REACHABLE, STALE, FAILED, etc.
	Interface string `json:"interface,omitempty"`
	Present   bool   `json:"present"`
	Error     string `json:"error,omitempty"`
}

// TCPStatus describes the exact outcome of a TCP connect probe.
type TCPStatus string

const (
	TCPStatusConnected   TCPStatus = "connected"
	TCPStatusRefused     TCPStatus = "refused"
	TCPStatusTimeout     TCPStatus = "timeout"
	TCPStatusReset       TCPStatus = "reset"
	TCPStatusUnreachable TCPStatus = "unreachable"
	TCPStatusFailed      TCPStatus = "failed"
)

// TCPReport captures the connection attempt outcome.
type TCPReport struct {
	Status    TCPStatus `json:"status"`
	LatencyMs int64     `json:"latency_ms"`
	LocalAddr string    `json:"local_addr,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
	RemotePort int      `json:"remote_port"`
	Error     string    `json:"error,omitempty"`
}

// ProxyReport captures environment proxy variables that could alter traffic flow.
type ProxyReport struct {
	HTTPProxy  string `json:"http_proxy,omitempty"`
	HTTPSProxy string `json:"https_proxy,omitempty"`
	NoProxy    string `json:"no_proxy,omitempty"`
	Active     bool   `json:"active"`
}

// SnapshotMetadata contains provenance and system context for the capture.
type SnapshotMetadata struct {
	NetDiffVersion string    `json:"netdiff_version"`
	CapturedAt     time.Time `json:"captured_at"`
	Hostname       string    `json:"hostname"`
	OS             string    `json:"os"`
	Kernel         string    `json:"kernel,omitempty"`
}

// FirewallReport captures active host firewall filtering systems.
type FirewallReport struct {
	Backend string `json:"backend,omitempty"` // "nftables", "iptables", "none"
	Active  bool   `json:"active"`
}

// Snapshot is the portable .ndiff file structure containing all relevant network state.
type Snapshot struct {
	SchemaVersion    string            `json:"schema_version"`
	Metadata         SnapshotMetadata  `json:"metadata"`
	Target           Target            `json:"target"`
	DNS              *DNSReport        `json:"dns,omitempty"`
	Route            *RouteReport      `json:"route,omitempty"`
	Interface        *InterfaceReport  `json:"interface,omitempty"`
	Neighbor         *NeighborReport   `json:"neighbor,omitempty"`
	TCP              *TCPReport        `json:"tcp,omitempty"`
	Proxy            *ProxyReport      `json:"proxy,omitempty"`
	Firewall         *FirewallReport   `json:"firewall,omitempty"`
	CollectionErrors []string          `json:"collection_errors,omitempty"`
}

// RelevanceLevel ranks the causal importance of a difference.
type RelevanceLevel string

const (
	RelevanceHigh    RelevanceLevel = "HIGH"
	RelevanceMedium  RelevanceLevel = "MEDIUM"
	RelevanceLow     RelevanceLevel = "LOW"
	RelevanceIgnored RelevanceLevel = "IGNORED"
)

// Difference describes a single divergence between good and bad environments.
type Difference struct {
	Category        string         `json:"category"` // "DNS", "Route", "Interface", "Source", "TCP", "Proxy"
	Field           string         `json:"field"`
	WorkingValue    string         `json:"working_value"`
	FailingValue    string         `json:"failing_value"`
	Relevance       RelevanceLevel `json:"relevance"`
	Rationale       string         `json:"rationale"`
	DependencyNode  string         `json:"dependency_node"`
}

// ComparisonReport is the evaluated output comparing two snapshots.
type ComparisonReport struct {
	Target             Target         `json:"target"`
	WorkingHost        string         `json:"working_host"`
	FailingHost        string         `json:"failing_host"`
	WorkingSnapshot    *Snapshot      `json:"working_snapshot"`
	FailingSnapshot    *Snapshot      `json:"failing_snapshot"`
	Differences        []Difference   `json:"differences"`
	EarliestDivergence string         `json:"earliest_divergence,omitempty"`
	Summary            string         `json:"summary"`
}
