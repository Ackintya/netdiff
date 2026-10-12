//go:build !linux

package firewall

import (
	"context"
	"netdiff/pkg/model"
)

type FallbackFirewallCollector struct{}

func New() Collector {
	return &FallbackFirewallCollector{}
}

func (c *FallbackFirewallCollector) Collect(_ context.Context) (*model.FirewallReport, error) {
	return &model.FirewallReport{
		Backend: "none",
		Active:  false,
	}, nil
}
