//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestLabScenarios executes the 5 network failure scenarios inside isolated Linux network namespaces.
// Must be run with elevated privileges (root/sudo) and '-tags integration'.
func TestLabScenarios(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux network namespace lab test on non-Linux platform")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping lab test: requires root privileges for namespace management")
	}

	// Find scripts/lab/lab.sh relative to test file or repository root
	labScript, err := filepath.Abs("../../scripts/lab/lab.sh")
	if err != nil {
		t.Fatalf("failed to resolve lab.sh path: %v", err)
	}

	cmd := exec.Command("bash", labScript, "run-all")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("lab run-all execution failed: %v", err)
	}
}
