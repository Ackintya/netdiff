//go:build linux

package neighbor

import (
	"bytes"
	"context"
	"os/exec"
	"strings"

	"netdiff/pkg/model"
)

type LinuxNeighborCollector struct{}

func New() Collector {
	return &LinuxNeighborCollector{}
}

func (c *LinuxNeighborCollector) Collect(ctx context.Context, gatewayIP, ifaceName string) (*model.NeighborReport, error) {
	report := &model.NeighborReport{
		IP:        gatewayIP,
		Interface: ifaceName,
	}

	if gatewayIP == "" {
		return report, nil
	}

	args := []string{"neigh", "show", "to", gatewayIP}
	if ifaceName != "" {
		args = append(args, "dev", ifaceName)
	}

	cmd := exec.CommandContext(ctx, "ip", args...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		report.Error = err.Error()
		return report, nil
	}

	// Output format: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
	output := strings.TrimSpace(out.String())
	if output != "" {
		report.Present = true
		fields := strings.Fields(output)
		for i := 0; i < len(fields); i++ {
			switch fields[i] {
			case "lladdr":
				if i+1 < len(fields) {
					report.MAC = fields[i+1]
					i++
				}
			}
		}
		// The last token is typically the neighbor state (REACHABLE, STALE, FAILED, INCOMPLETE, etc.)
		if len(fields) > 0 {
			report.State = fields[len(fields)-1]
		}
	}

	return report, nil
}
