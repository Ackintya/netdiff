package dns

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"time"

	"netdiff/pkg/model"
)

type Collector struct {
	Resolver *net.Resolver
}

func New() *Collector {
	return &Collector{
		Resolver: net.DefaultResolver,
	}
}

func (c *Collector) Collect(ctx context.Context, target model.Target) (*model.DNSReport, error) {
	report := &model.DNSReport{
		Hostname:    target.Host,
		Nameservers: getNameservers(),
	}

	if target.IsIP {
		report.Success = true
		report.ARecords = []string{target.Host}
		return report, nil
	}

	start := time.Now()
	addrs, err := c.Resolver.LookupIP(ctx, "ip", target.Host)
	report.ResolutionMs = time.Since(start).Milliseconds()

	if err != nil {
		report.Success = false
		report.Error = err.Error()
		return report, nil
	}

	report.Success = true
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			report.ARecords = append(report.ARecords, ipv4.String())
		} else {
			report.AAAARecords = append(report.AAAARecords, addr.String())
		}
	}

	return report, nil
}

// getNameservers parses /etc/resolv.conf if on Unix/Linux, or returns empty if not available
func getNameservers() []string {
	var ns []string
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ns
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ns = append(ns, parts[1])
			}
		}
	}
	return ns
}
