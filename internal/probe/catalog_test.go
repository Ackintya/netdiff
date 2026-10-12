package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"netdiff/pkg/model"
)

func TestProbeUnknown(t *testing.T) {
	ctx := context.Background()
	tgt := model.Target{Host: "127.0.0.1", Port: 80, Raw: "127.0.0.1:80"}
	_, err := ExecuteProbe(ctx, tgt, "TEST_INVALID_PROBE", "")
	if err == nil {
		t.Fatal("expected error for unknown probe, got nil")
	}
}

func TestProbeDirectIP(t *testing.T) {
	// Local listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	tgt := model.Target{
		Host: "localhost",
		Port: port,
		Raw:  listener.Addr().String(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := ExecuteProbe(ctx, tgt, "TEST_DIRECT_IP", "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected probe success, got failure: %s", result.Output)
	}
}
