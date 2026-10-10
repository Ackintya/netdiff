package tcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"netdiff/pkg/model"
)

type Collector struct {
	Timeout time.Duration
}

func New(timeout time.Duration) *Collector {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Collector{
		Timeout: timeout,
	}
}

func (c *Collector) Collect(ctx context.Context, target model.Target, resolvedIP string) (*model.TCPReport, error) {
	connectHost := target.Host
	if resolvedIP != "" {
		connectHost = resolvedIP
	}

	address := net.JoinHostPort(connectHost, fmt.Sprintf("%d", target.Port))
	report := &model.TCPReport{
		RemoteIP:   resolvedIP,
		RemotePort: target.Port,
	}

	dialer := &net.Dialer{
		Timeout: c.Timeout,
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	report.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		report.Status = classifyTCPError(err)
		report.Error = err.Error()
		return report, nil
	}
	defer conn.Close()

	report.Status = model.TCPStatusConnected
	if conn.LocalAddr() != nil {
		report.LocalAddr = conn.LocalAddr().String()
	}

	return report, nil
}

func classifyTCPError(err error) model.TCPStatus {
	if err == nil {
		return model.TCPStatusConnected
	}

	errStr := strings.ToLower(err.Error())

	if strings.Contains(errStr, "refused") || strings.Contains(errStr, "connection refused") {
		return model.TCPStatusRefused
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "timed out") || strings.Contains(errStr, "deadline exceeded") {
		return model.TCPStatusTimeout
	}
	if strings.Contains(errStr, "reset") || strings.Contains(errStr, "connection reset") {
		return model.TCPStatusReset
	}
	if strings.Contains(errStr, "unreachable") || strings.Contains(errStr, "no route to host") {
		return model.TCPStatusUnreachable
	}

	return model.TCPStatusFailed
}
