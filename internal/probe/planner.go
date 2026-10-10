package probe

import (
	"context"
	"os"
	"runtime"
	"time"

	"netdiff/internal/collector/dns"
	"netdiff/internal/collector/iface"
	"netdiff/internal/collector/neighbor"
	"netdiff/internal/collector/proxy"
	"netdiff/internal/collector/route"
	"netdiff/internal/collector/tcp"
	"netdiff/pkg/model"
)

const (
	CurrentSchemaVersion = "ndiff/v1"
	CurrentVersion       = "0.1.0"
)

type Engine struct {
	dnsCollector      *dns.Collector
	routeCollector    route.Collector
	ifaceCollector    iface.Collector
	neighborCollector neighbor.Collector
	tcpCollector      *tcp.Collector
	proxyCollector    *proxy.Collector
}

func NewEngine() *Engine {
	return &Engine{
		dnsCollector:      dns.New(),
		routeCollector:    route.New(),
		ifaceCollector:    iface.New(),
		neighborCollector: neighbor.New(),
		tcpCollector:      tcp.New(5 * time.Second),
		proxyCollector:    proxy.New(),
	}
}

// Capture executes the probe plan for the target and compiles a model.Snapshot.
func (e *Engine) Capture(ctx context.Context, target model.Target) (*model.Snapshot, error) {
	hostname, _ := os.Hostname()
	snapshot := &model.Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Metadata: model.SnapshotMetadata{
			NetDiffVersion: CurrentVersion,
			CapturedAt:     time.Now().UTC(),
			Hostname:       hostname,
			OS:             runtime.GOOS,
		},
		Target: target,
	}

	// 1. Proxy Collection
	if pReport, err := e.proxyCollector.Collect(ctx, target); err == nil {
		snapshot.Proxy = pReport
	} else {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "proxy: "+err.Error())
	}

	// 2. DNS Resolution
	dnsReport, err := e.dnsCollector.Collect(ctx, target)
	if err != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "dns: "+err.Error())
	} else {
		snapshot.DNS = dnsReport
	}

	// Determine destination IP to query route and TCP
	var destIP string
	if target.IsIP {
		destIP = target.Host
	} else if dnsReport != nil && len(dnsReport.ARecords) > 0 {
		destIP = dnsReport.ARecords[0]
	} else if dnsReport != nil && len(dnsReport.AAAARecords) > 0 {
		destIP = dnsReport.AAAARecords[0]
	}

	// 3. Route Lookup (if destination IP resolved)
	var egressIface string
	var gatewayIP string
	if destIP != "" {
		rReport, err := e.routeCollector.Collect(ctx, destIP)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "route: "+err.Error())
		} else {
			snapshot.Route = rReport
			egressIface = rReport.EgressInterface
			gatewayIP = rReport.Gateway
		}
	}

	// 4. Interface Inspection
	if egressIface != "" {
		iReport, err := e.ifaceCollector.Collect(ctx, egressIface)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "interface: "+err.Error())
		} else {
			snapshot.Interface = iReport
		}
	}

	// 5. Neighbor / Next-Hop Inspection
	if gatewayIP != "" {
		nReport, err := e.neighborCollector.Collect(ctx, gatewayIP, egressIface)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "neighbor: "+err.Error())
		} else {
			snapshot.Neighbor = nReport
		}
	}

	// 6. TCP Probe
	tReport, err := e.tcpCollector.Collect(ctx, target, destIP)
	if err != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "tcp: "+err.Error())
	} else {
		snapshot.TCP = tReport
	}

	return snapshot, nil
}
