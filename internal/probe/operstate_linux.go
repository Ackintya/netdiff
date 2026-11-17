//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"strings"
)

// getInterfaceOperState reads the operational state of an interface on Linux.
func getInterfaceOperState(ifaceName string) string {
	path := filepath.Join("/sys/class/net", ifaceName, "operstate")
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
