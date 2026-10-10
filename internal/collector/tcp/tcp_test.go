package tcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"netdiff/pkg/model"
)

func TestClassifyTCPError(t *testing.T) {
	tests := []struct {
		err      error
		expected model.TCPStatus
	}{
		{nil, model.TCPStatusConnected},
		{errors.New("dial tcp: connection refused"), model.TCPStatusRefused},
		{errors.New("i/o timeout (Client.Timeout exceeded)"), model.TCPStatusTimeout},
		{errors.New("connection reset by peer"), model.TCPStatusReset},
		{errors.New("no route to host"), model.TCPStatusUnreachable},
		{errors.New("unknown error occurred"), model.TCPStatusFailed},
	}

	for _, tt := range tests {
		got := classifyTCPError(tt.err)
		if got != tt.expected {
			t.Errorf("classifyTCPError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

func TestTCPCollectorLocalListener(t *testing.T) {
	// Spin up a local TCP listener to verify TCP collector
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	collector := New(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tgt := model.Target{
		Host: "127.0.0.1",
		Port: tcpAddr.Port,
		IsIP: true,
	}

	report, err := collector.Collect(ctx, tgt, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected collect error: %v", err)
	}

	if report.Status != model.TCPStatusConnected {
		t.Errorf("expected status connected, got %s (err: %s)", report.Status, report.Error)
	}
}
