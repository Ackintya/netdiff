//go:build linux

package rule

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"strings"
)

type LinuxRuleCollector struct{}

func New() Collector {
	return &LinuxRuleCollector{}
}

func (c *LinuxRuleCollector) Collect(ctx context.Context, destIP string) (string, []string, error) {
	cmd := exec.CommandContext(ctx, "ip", "rule", "show")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return "", nil, err
	}

	lines := strings.Split(out.String(), "\n")
	var allRules []string
	var matchedRule string

	var parsedIP net.IP
	if destIP != "" {
		parsedIP = net.ParseIP(destIP)
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		allRules = append(allRules, trimmed)

		if matchedRule == "" && parsedIP != nil {
			if matchesRule(trimmed, parsedIP) {
				matchedRule = trimmed
			}
		}
	}

	if matchedRule == "" && len(allRules) > 0 {
		// Default fallthrough rule
		for _, r := range allRules {
			if strings.Contains(r, "lookup main") {
				matchedRule = r
				break
			}
		}
	}

	return matchedRule, allRules, nil
}

// matchesRule inspects if a rule line like "100: from all to 10.40.0.0/16 lookup 200" matches parsedIP
func matchesRule(ruleLine string, ip net.IP) bool {
	fields := strings.Fields(ruleLine)
	for i := 0; i < len(fields); i++ {
		if fields[i] == "to" && i+1 < len(fields) {
			cidr := fields[i+1]
			if !strings.Contains(cidr, "/") {
				cidr = cidr + "/32"
			}
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}
