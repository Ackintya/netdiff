//go:build linux

package route

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"netdiff/pkg/model"
)

type LinuxRouteCollector struct{}

func New() Collector {
	return &LinuxRouteCollector{}
}

func (c *LinuxRouteCollector) Collect(ctx context.Context, destIP string) (*model.RouteReport, error) {
	report := &model.RouteReport{
		DestinationIP: destIP,
		Table:         254, // default to main
		TableName:     "main",
	}

	if destIP == "" {
		report.Error = "no destination IP provided"
		return report, nil
	}

	// Execute `ip route get <destIP>` which performs the kernel FIB lookup (respecting policy routing rules)
	cmd := exec.CommandContext(ctx, "ip", "route", "get", destIP)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		report.Error = fmt.Sprintf("ip route get failed: %v (%s)", err, strings.TrimSpace(stderr.String()))
		return report, nil
	}

	parseRouteGetOutput(out.String(), report)
	report.Success = true
	return report, nil
}

// parseRouteGetOutput parses typical output like:
// "10.40.8.21 via 192.168.1.1 dev eth0 src 192.168.1.84 table 200 metric 100 uid 1000"
// or "10.40.8.21 dev tun0 table 200 src 10.8.0.14 uid 1000"
func parseRouteGetOutput(output string, report *model.RouteReport) {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return
	}
	firstLine := strings.TrimSpace(lines[0])
	tokens := strings.Fields(firstLine)

	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "dev":
			if i+1 < len(tokens) {
				report.EgressInterface = tokens[i+1]
				i++
			}
		case "via":
			if i+1 < len(tokens) {
				report.Gateway = tokens[i+1]
				i++
			}
		case "src":
			if i+1 < len(tokens) {
				report.PreferredSource = tokens[i+1]
				i++
			}
		case "table":
			if i+1 < len(tokens) {
				tableVal := tokens[i+1]
				if t, err := strconv.Atoi(tableVal); err == nil {
					report.Table = t
				}
				report.TableName = tableVal
				i++
			}
		case "metric":
			if i+1 < len(tokens) {
				if m, err := strconv.Atoi(tokens[i+1]); err == nil {
					report.Metric = m
				}
				i++
			}
		}
	}
}
