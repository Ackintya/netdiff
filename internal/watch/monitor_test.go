package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"netdiff/pkg/model"
)

type mockCaptureEngine struct {
	snapshot *model.Snapshot
	err      error
}

func (m *mockCaptureEngine) Capture(ctx context.Context, tgt model.Target) (*model.Snapshot, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.snapshot, nil
}

func TestAuditOnce_Healthy(t *testing.T) {
	baseSnap := &model.Snapshot{
		Target:    model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080},
		Route:     &model.RouteReport{EgressInterface: "tun0", Success: true},
		Interface: &model.InterfaceReport{Name: "tun0", OperState: "UP"},
		TCP:       &model.TCPReport{Status: model.TCPStatusConnected, LatencyMs: 20},
	}
	liveSnap := &model.Snapshot{
		Target:    model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080},
		Route:     &model.RouteReport{EgressInterface: "tun0", Success: true},
		Interface: &model.InterfaceReport{Name: "tun0", OperState: "UP"},
		TCP:       &model.TCPReport{Status: model.TCPStatusConnected, LatencyMs: 22},
	}

	engine := &mockCaptureEngine{snapshot: liveSnap}
	cfg := WatchConfig{
		Target:   baseSnap.Target,
		Baseline: baseSnap,
		Engine:   engine,
	}

	event, err := AuditOnce(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !event.Healthy {
		t.Errorf("expected healthy true, got false")
	}
	if event.Status != "HEALTHY" {
		t.Errorf("expected status HEALTHY, got %s", event.Status)
	}
	if event.DivergenceCount != 0 {
		t.Errorf("expected 0 divergence count, got %d", event.DivergenceCount)
	}
	if !strings.Contains(event.Summary, "tun0") {
		t.Errorf("expected summary to mention tun0, got %s", event.Summary)
	}
}

func TestAuditOnce_DriftDetected(t *testing.T) {
	baseSnap := &model.Snapshot{
		Target:    model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080},
		Route:     &model.RouteReport{EgressInterface: "tun0", PolicyRule: "to 10.40.0.0/16 lookup 200", Success: true},
		Interface: &model.InterfaceReport{Name: "tun0", OperState: "UP"},
		TCP:       &model.TCPReport{Status: model.TCPStatusConnected},
	}
	// Live environment drifted: rule missing, routes out eth0, TCP times out
	liveSnap := &model.Snapshot{
		Target:    model.Target{Raw: "10.40.8.21:8080", Host: "10.40.8.21", Port: 8080},
		Route:     &model.RouteReport{EgressInterface: "eth0", Success: true},
		Interface: &model.InterfaceReport{Name: "eth0", OperState: "UP"},
		TCP:       &model.TCPReport{Status: model.TCPStatusTimeout},
	}

	engine := &mockCaptureEngine{snapshot: liveSnap}
	cfg := WatchConfig{
		Target:   baseSnap.Target,
		Baseline: baseSnap,
		Engine:   engine,
	}

	event, err := AuditOnce(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Healthy {
		t.Errorf("expected healthy false when route diverges")
	}
	if event.Status != "DRIFT_DETECTED" {
		t.Errorf("expected DRIFT_DETECTED, got %s", event.Status)
	}
	if event.DivergenceCount == 0 {
		t.Errorf("expected divergences > 0")
	}
	if event.RemediationCmd == "" {
		t.Errorf("expected remediation hint command, got empty")
	}
}

func TestAuditOnce_NilBaseline(t *testing.T) {
	cfg := WatchConfig{
		Target:   model.Target{Raw: "api.corp:443"},
		Baseline: nil,
		Engine:   &mockCaptureEngine{},
	}
	_, err := AuditOnce(context.Background(), cfg)
	if err == nil {
		t.Errorf("expected error for nil baseline")
	}
}

func TestAuditOnce_CaptureError(t *testing.T) {
	baseSnap := &model.Snapshot{Target: model.Target{Raw: "api.corp:443"}}
	cfg := WatchConfig{
		Target:   baseSnap.Target,
		Baseline: baseSnap,
		Engine:   &mockCaptureEngine{err: errors.New("network interface down")},
	}
	event, err := AuditOnce(context.Background(), cfg)
	if err == nil {
		t.Errorf("expected error from engine")
	}
	if event.Status != "CAPTURE_ERROR" {
		t.Errorf("expected CAPTURE_ERROR, got %s", event.Status)
	}
}

func TestWatch_CountIterations(t *testing.T) {
	baseSnap := &model.Snapshot{
		Target: model.Target{Raw: "10.0.0.1:80", Host: "10.0.0.1", Port: 80},
		Route:  &model.RouteReport{EgressInterface: "eth0", Success: true},
		TCP:    &model.TCPReport{Status: model.TCPStatusConnected},
	}
	buf := new(bytes.Buffer)

	cfg := WatchConfig{
		Target:       baseSnap.Target,
		Baseline:     baseSnap,
		BaselinePath: "/tmp/base.ndiff",
		Interval:     10 * time.Millisecond,
		Count:        2,
		Engine:       &mockCaptureEngine{snapshot: baseSnap},
		Writer:       buf,
	}

	err := Watch(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "NetDiff Proactive Baseline Drift Monitor") {
		t.Errorf("expected header banner in output: %s", output)
	}
	if !strings.Contains(output, "[OK]") {
		t.Errorf("expected [OK] log line in output: %s", output)
	}
}

func TestWatch_JSONOutput(t *testing.T) {
	baseSnap := &model.Snapshot{
		Target: model.Target{Raw: "10.0.0.1:80", Host: "10.0.0.1", Port: 80},
		Route:  &model.RouteReport{EgressInterface: "eth0", Success: true},
		TCP:    &model.TCPReport{Status: model.TCPStatusConnected},
	}
	buf := new(bytes.Buffer)

	cfg := WatchConfig{
		Target:     baseSnap.Target,
		Baseline:   baseSnap,
		Interval:   10 * time.Millisecond,
		Count:      1,
		JSONOutput: true,
		Engine:     &mockCaptureEngine{snapshot: baseSnap},
		Writer:     buf,
	}

	err := Watch(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var event DriftEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("failed to parse json line %q: %v", line, err)
	}

	if event.Target != "10.0.0.1:80" {
		t.Errorf("expected target 10.0.0.1:80, got %s", event.Target)
	}
	if !event.Healthy {
		t.Errorf("expected healthy true in json")
	}
}

func TestWatch_ContextCancel(t *testing.T) {
	baseSnap := &model.Snapshot{
		Target: model.Target{Raw: "10.0.0.1:80", Host: "10.0.0.1", Port: 80},
		Route:  &model.RouteReport{EgressInterface: "eth0", Success: true},
		TCP:    &model.TCPReport{Status: model.TCPStatusConnected},
	}
	buf := new(bytes.Buffer)

	ctx, cancel := context.WithCancel(context.Background())

	cfg := WatchConfig{
		Target:   baseSnap.Target,
		Baseline: baseSnap,
		Interval: 50 * time.Millisecond,
		Count:    0, // infinite
		Engine:   &mockCaptureEngine{snapshot: baseSnap},
		Writer:   buf,
	}

	// Cancel after brief moment
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := Watch(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "Monitor stopped by operator") {
		t.Errorf("expected cancellation message, got: %s", buf.String())
	}
}
