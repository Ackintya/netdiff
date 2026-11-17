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

func TestProbeInterfaceState_ExistingUp(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no network interfaces available")
	}

	var upIface *net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 {
			upIface = &iface
			break
		}
	}

	if upIface == nil {
		t.Skip("no UP interface found")
	}

	ctx := context.Background()
	tgt := model.Target{Raw: "local"}
	res, err := ExecuteProbe(ctx, tgt, "TEST_INTERFACE_STATE", upIface.Name)
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}

	if !res.Success {
		t.Errorf("expected probe success for UP interface %s, got failure: %s", upIface.Name, res.Output)
	}
	if res.InterfaceState == nil {
		t.Fatal("expected non-nil InterfaceState")
	}
	if !res.InterfaceState.Exists {
		t.Errorf("expected Exists=true for %s", upIface.Name)
	}
	if !res.InterfaceState.AdminUp {
		t.Errorf("expected AdminUp=true for %s", upIface.Name)
	}
}

func TestProbeInterfaceState_Missing(t *testing.T) {
	ctx := context.Background()
	tgt := model.Target{Raw: "local"}
	res, err := ExecuteProbe(ctx, tgt, "TEST_INTERFACE_STATE", "nonexistent_iface_xyz99")
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}

	if res.Success {
		t.Error("expected probe failure for nonexistent interface, got success")
	}
	if res.InterfaceState == nil {
		t.Fatal("expected non-nil InterfaceState")
	}
	if res.InterfaceState.Exists {
		t.Error("expected Exists=false for nonexistent interface")
	}
	if res.InterfaceState.OperState != "missing" {
		t.Errorf("expected OperState='missing', got %q", res.InterfaceState.OperState)
	}
}

func TestProbeInterfaceState_EmptyParam(t *testing.T) {
	ctx := context.Background()
	tgt := model.Target{Raw: "local"}
	_, err := ExecuteProbe(ctx, tgt, "TEST_INTERFACE_STATE", "")
	if err == nil {
		t.Fatal("expected error for empty interface name, got nil")
	}
}

func TestProbeInterfaceState_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	tgt := model.Target{Raw: "local"}
	_, err := ExecuteProbe(ctx, tgt, "TEST_INTERFACE_STATE", "any0")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}
