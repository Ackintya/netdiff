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
			Error: "interface name is empty",
		}, nil
	}

	netIface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return &model.InterfaceReport{
			Name:  ifaceName,
			Error: err.Error(),
		}, nil
	}

	role, isTunnel := ClassifyRole(ifaceName)
	operState := "down"
	var flags []string
	if netIface.Flags&net.FlagUp != 0 {
		operState = "up"
		flags = append(flags, "UP")
	}
	if netIface.Flags&net.FlagBroadcast != 0 {
		flags = append(flags, "BROADCAST")
	}
	if netIface.Flags&net.FlagLoopback != 0 {
		flags = append(flags, "LOOPBACK")
	}
	if netIface.Flags&net.FlagPointToPoint != 0 {
		flags = append(flags, "POINTOPOINT")
	}
	if netIface.Flags&net.FlagMulticast != 0 {
		flags = append(flags, "MULTICAST")
	}

	var addrs []string
	if ifAddrs, err := netIface.Addrs(); err == nil {
		for _, a := range ifAddrs {
			addrs = append(addrs, a.String())
		}
	}

	return &model.InterfaceReport{
		Name:      netIface.Name,
		Index:     netIface.Index,
		MTU:       netIface.MTU,
		IsTunnel:  isTunnel,
		Role:      role,
		OperState: operState,
		Flags:     flags,
		Addresses: addrs,
	}, nil
}
