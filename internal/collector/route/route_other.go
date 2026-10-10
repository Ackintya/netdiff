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
	return &model.RouteReport{
		DestinationIP:   destIP,
		Table:           254,
		TableName:       "main",
		EgressInterface: "default",
		Success:         true,
	}, nil
}
