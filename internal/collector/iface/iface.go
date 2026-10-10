package iface

import (
	"context"
	"strings"

	"netdiff/pkg/model"
)

type Collector interface {
	Collect(ctx context.Context, ifaceName string) (*model.InterfaceReport, error)
}

// ClassifyRole assigns a semantic role to an interface based on name and characteristics.
func ClassifyRole(name string) (role string, isTunnel bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "lo"):
		return "loopback", false
	case strings.HasPrefix(lower, "tun"),
		strings.HasPrefix(lower, "tap"),
		strings.HasPrefix(lower, "wg"),
		strings.HasPrefix(lower, "tailscale"),
		strings.HasPrefix(lower, "utun"),
		strings.Contains(lower, "vpn"):
		return "tunnel", true
	case strings.HasPrefix(lower, "docker"),
		strings.HasPrefix(lower, "cbr"),
		strings.HasPrefix(lower, "flannel"),
		strings.HasPrefix(lower, "cni"),
		strings.HasPrefix(lower, "veth"),
		strings.HasPrefix(lower, "br-"):
		return "virtual", false
	case strings.HasPrefix(lower, "eth"),
		strings.HasPrefix(lower, "en"),
		strings.HasPrefix(lower, "wl"):
		return "physical", false
	default:
		return "interface", false
	}
}
