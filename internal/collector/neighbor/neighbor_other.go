//go:build !linux

package neighbor

import (
	"context"
	"netdiff/pkg/model"
)

type FallbackNeighborCollector struct{}

func New() Collector {
	return &FallbackNeighborCollector{}
}

func (c *FallbackNeighborCollector) Collect(_ context.Context, gatewayIP, ifaceName string) (*model.NeighborReport, error) {
	return &model.NeighborReport{
		IP:        gatewayIP,
		Interface: ifaceName,
		Present:   false,
	}, nil
}
