//go:build linux

package firewall

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"

	"netdiff/pkg/model"
)

type LinuxFirewallCollector struct{}

func New() Collector {
	return &LinuxFirewallCollector{}
}

func (c *LinuxFirewallCollector) Collect(ctx context.Context) (*model.FirewallReport, error) {
	report := &model.FirewallReport{
		Backend: "none",
		Active:  false,
	}

	// 1. Check nftables
	cmd := exec.CommandContext(ctx, "nft", "list", "tables")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		if strings.TrimSpace(out.String()) != "" {
			report.Backend = "nftables"
			report.Active = true
			return report, nil
		}
	}

	// 2. Check iptables via procfs or iptables-legacy
	if _, err := os.Stat("/proc/net/ip_tables_names"); err == nil {
		report.Backend = "iptables"
		report.Active = true
		return report, nil
	}

	return report, nil
}
