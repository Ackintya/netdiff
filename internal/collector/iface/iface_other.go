//go:build !linux

package iface

import (
	"context"
	"net"

	"netdiff/pkg/model"
)

type FallbackInterfaceCollector struct{}

func New() Collector {
	return &FallbackInterfaceCollector{}
}

func (c *FallbackInterfaceCollector) Collect(_ context.Context, ifaceName string) (*model.InterfaceReport, error) {
	if ifaceName == "" {
		return &model.InterfaceReport{
			Name:  "default",
			MTU:   1500,
			Role:  "physical",
			OperState: "up",
		}, nil
	}

	netIface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return &model.InterfaceReport{
			Name:      ifaceName,
			MTU:       1500,
			Role:      "physical",
			OperState: "up",
		}, nil
	}

	role, isTunnel := ClassifyRole(ifaceName)
	return &model.InterfaceReport{
		Name:      netIface.Name,
		Index:     netIface.Index,
		MTU:       netIface.MTU,
		IsTunnel:  isTunnel,
		Role:      role,
		OperState: "up",
	}, nil
}
