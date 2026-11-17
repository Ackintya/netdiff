//go:build !linux

package route

import (
	"context"
	"netdiff/pkg/model"
)

type FallbackRouteCollector struct{}

func New() Collector {
	return &FallbackRouteCollector{}
}

func (c *FallbackRouteCollector) Collect(_ context.Context, destIP string) (*model.RouteReport, error) {
	report := &model.RouteReport{
		DestinationIP: destIP,
		Table:         254,
		TableName:     "main",
	}

	if destIP == "" {
		report.Error = "no destination IP provided"
		return report, nil
	}

	report.Error = "kernel route lookup (ip route get) is only supported on Linux"
	report.Success = false
	return report, nil
}
