//go:build !linux

package probe

// getInterfaceOperState returns "unknown" on non-Linux platforms where sysfs is unavailable.
func getInterfaceOperState(_ string) string {
	return "unknown"
}
