package firewall

import (
	"context"
	"strings"

	"netdiff/pkg/model"
)

type Collector interface {
	Collect(ctx context.Context) (*model.FirewallReport, error)
}

// HasActiveIptablesRules parses iptables -S output to identify active rules or drop/reject policies.
func HasActiveIptablesRules(output string) bool {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "-A") {
			return true
		}
		if strings.HasPrefix(trimmed, "-P") {
			if strings.Contains(trimmed, "DROP") || strings.Contains(trimmed, "REJECT") {
				return true
			}
		}
	}
	return false
}
