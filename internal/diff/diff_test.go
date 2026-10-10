package diff

import (
	"testing"
	"time"

	"netdiff/pkg/model"
)

func TestRoutingDivergenceScenario(t *testing.T) {
	tgt := model.Target{
		Raw:      "api.internal:443",
		Host:     "api.internal",
		Port:     443,
		Protocol: "tcp",
	}

	goodSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Metadata: model.SnapshotMetadata{
			NetDiffVersion: "0.1.0",
			CapturedAt:     time.Now(),
			Hostname:       "host-working",
		},
		Target: tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			ARecords: []string{"10.40.8.21"},
			Success:  true,
		},
		Route: &model.RouteReport{
			DestinationIP:   "10.40.8.21",
			Table:           200,
			TableName:       "200",
			EgressInterface: "tun0",
			PreferredSource: "10.8.0.14",
			Success:         true,
		},
		Interface: &model.InterfaceReport{
			Name:     "tun0",
			Role:     "tunnel",
			IsTunnel: true,
			MTU:      1420,
		},
		TCP: &model.TCPReport{
			Status:    model.TCPStatusConnected,
			LatencyMs: 25,
		},
	}

	badSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Metadata: model.SnapshotMetadata{
			NetDiffVersion: "0.1.0",
			CapturedAt:     time.Now(),
			Hostname:       "host-failing",
		},
		Target: tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			ARecords: []string{"10.40.8.21"},
			Success:  true,
		},
		Route: &model.RouteReport{
			DestinationIP:   "10.40.8.21",
			Table:           254,
			TableName:       "main",
			EgressInterface: "eth0",
			PreferredSource: "192.168.1.84",
			Success:         true,
		},
		Interface: &model.InterfaceReport{
			Name:     "eth0",
			Role:     "physical",
			IsTunnel: false,
			MTU:      1500,
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusTimeout,
		},
	}

	report := Compare(goodSnap, badSnap)
	if report == nil {
		t.Fatal("expected non-nil comparison report")
	}

	// Verify route/interface differences are marked HIGH relevance
	var foundHighRoute bool
	var foundHighInterface bool
	for _, d := range report.Differences {
		if d.Category == "Route" && d.Field == "egress_interface" && d.Relevance == model.RelevanceHigh {
			foundHighRoute = true
		}
		if d.Category == "Interface" && d.Field == "interface_role" && d.Relevance == model.RelevanceHigh {
			foundHighInterface = true
		}
	}

	if !foundHighRoute {
		t.Errorf("expected egress_interface diff to be ranked HIGH relevance")
	}
	if !foundHighInterface {
		t.Errorf("expected interface_role diff to be ranked HIGH relevance")
	}
}

func TestDNSDivergenceScenario(t *testing.T) {
	tgt := model.Target{
		Raw:  "api.internal:443",
		Host: "api.internal",
		Port: 443,
	}

	goodSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			ARecords: []string{"10.40.8.21"},
			Success:  true,
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusConnected,
		},
	}

	badSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		DNS: &model.DNSReport{
			Hostname: "api.internal",
			Success:  false,
			Error:    "no such host",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusFailed,
		},
	}

	report := Compare(goodSnap, badSnap)
	var foundDNSHigh bool
	for _, d := range report.Differences {
		if d.Category == "DNS" && d.Relevance == model.RelevanceHigh {
			foundDNSHigh = true
		}
	}

	if !foundDNSHigh {
		t.Errorf("expected DNS failure to be ranked HIGH relevance")
	}
}

func TestConnectionRefusedBehavior(t *testing.T) {
	tgt := model.Target{
		Raw:  "10.40.8.21:443",
		Host: "10.40.8.21",
		Port: 443,
		IsIP: true,
	}

	goodSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		Route: &model.RouteReport{
			Table:           200,
			EgressInterface: "tun0",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusConnected,
		},
	}

	badSnap := &model.Snapshot{
		SchemaVersion: "ndiff/v1",
		Target:        tgt,
		Route: &model.RouteReport{
			Table:           254,
			EgressInterface: "tun0",
		},
		TCP: &model.TCPReport{
			Status: model.TCPStatusRefused, // Connection refused confirms host was reached!
		},
	}

	report := Compare(goodSnap, badSnap)
	for _, d := range report.Differences {
		if d.Category == "Route" && d.Field == "routing_table" {
			if d.Relevance == model.RelevanceHigh {
				t.Errorf("expected routing diff to be downgraded from HIGH when connection was actively refused")
			}
		}
	}
}
