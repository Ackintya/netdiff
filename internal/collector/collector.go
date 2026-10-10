package collector

import (
	"context"
	"netdiff/pkg/model"
)

// DNSCollector resolves the target hostname and records nameservers, IPs, and duration.
type DNSCollector interface {
	Collect(ctx context.Context, target model.Target) (*model.DNSReport, error)
}

// TCPCollector attempts a TCP connection to the target and captures detailed status and latency.
type TCPCollector interface {
	Collect(ctx context.Context, target model.Target, resolvedIP string) (*model.TCPReport, error)
}

// ProxyCollector inspects environment variables related to HTTP/HTTPS proxies.
type ProxyCollector interface {
	Collect(ctx context.Context, target model.Target) (*model.ProxyReport, error)
}

// RouteCollector looks up the routing decision for the destination IP.
type RouteCollector interface {
	Collect(ctx context.Context, destIP string) (*model.RouteReport, error)
}

// InterfaceCollector inspects the egress interface identified by routing.
type InterfaceCollector interface {
	Collect(ctx context.Context, ifaceName string) (*model.InterfaceReport, error)
}

// NeighborCollector inspects ARP/NDP neighbor table for the gateway/next-hop.
type NeighborCollector interface {
	Collect(ctx context.Context, gatewayIP, ifaceName string) (*model.NeighborReport, error)
}
