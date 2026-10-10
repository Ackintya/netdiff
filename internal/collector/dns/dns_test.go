package dns

import (
	"context"
	"testing"
	"time"

	"netdiff/pkg/model"
)

func TestDNSCollectorDirectIP(t *testing.T) {
	collector := New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tgt := model.Target{
		Raw:  "127.0.0.1:80",
		Host: "127.0.0.1",
		Port: 80,
		IsIP: true,
	}

	report, err := collector.Collect(ctx, tgt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Success {
		t.Errorf("expected success for direct IP, got failure: %s", report.Error)
	}
	if len(report.ARecords) == 0 || report.ARecords[0] != "127.0.0.1" {
		t.Errorf("expected A record [127.0.0.1], got %v", report.ARecords)
	}
}
