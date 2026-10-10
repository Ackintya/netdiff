//go:build linux

package iface

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"netdiff/pkg/model"
)

type LinuxInterfaceCollector struct{}

func New() Collector {
	return &LinuxInterfaceCollector{}
}

func (c *LinuxInterfaceCollector) Collect(_ context.Context, ifaceName string) (*model.InterfaceReport, error) {
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

	report := &model.InterfaceReport{
		Name:      netIface.Name,
		Index:     netIface.Index,
		MTU:       netIface.MTU,
		IsTunnel:  isTunnel,
		Role:      role,
		OperState: readOperState(ifaceName),
	}

	// Flags
	if netIface.Flags&net.FlagUp != 0 {
		report.Flags = append(report.Flags, "UP")
	}
	if netIface.Flags&net.FlagBroadcast != 0 {
		report.Flags = append(report.Flags, "BROADCAST")
	}
	if netIface.Flags&net.FlagLoopback != 0 {
		report.Flags = append(report.Flags, "LOOPBACK")
	}
	if netIface.Flags&net.FlagPointToPoint != 0 {
		report.Flags = append(report.Flags, "POINTOPOINT")
	}
	if netIface.Flags&net.FlagMulticast != 0 {
		report.Flags = append(report.Flags, "MULTICAST")
	}

	// Addresses
	addrs, err := netIface.Addrs()
	if err == nil {
		for _, addr := range addrs {
			report.Addresses = append(report.Addresses, addr.String())
		}
	}

	return report, nil
}

func readOperState(ifaceName string) string {
	path := fmt.Sprintf("/sys/class/net/%s/operstate", ifaceName)
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
