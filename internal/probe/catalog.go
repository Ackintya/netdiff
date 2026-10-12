package probe

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"netdiff/internal/collector/tcp"
	"netdiff/pkg/model"
)

// ProbeResult contains the diagnostic output of a follow-up validation test.
type ProbeResult struct {
	ProbeName string          `json:"probe_name"`
	Target    string          `json:"target"`
	Parameter string          `json:"parameter,omitempty"`
	Success   bool            `json:"success"`
	Output    string          `json:"output"`
	TCPReport *model.TCPReport `json:"tcp_report,omitempty"`
}

// ExecuteProbe executes a bounded diagnostic validation probe from the fixed catalog.
func ExecuteProbe(ctx context.Context, target model.Target, probeName, param string) (*ProbeResult, error) {
	result := &ProbeResult{
		ProbeName: probeName,
		Target:    target.Raw,
		Parameter: param,
	}

	switch probeName {
	case "TEST_TCP_BIND_INTERFACE":
		return executeTCPBindInterface(ctx, target, param, result)

	case "TEST_TCP_BIND_SOURCE":
		return executeTCPBindSource(ctx, target, param, result)

	case "TEST_DNS_WITH_RESOLVER":
		return executeDNSWithResolver(ctx, target, param, result)

	case "TEST_PROXY_DISABLED":
		return executeProxyDisabled(ctx, target, result)

	case "TEST_DIRECT_IP":
		return executeDirectIP(ctx, target, param, result)

	default:
		return nil, fmt.Errorf("unknown probe %q; supported probes: TEST_TCP_BIND_INTERFACE, TEST_TCP_BIND_SOURCE, TEST_DNS_WITH_RESOLVER, TEST_PROXY_DISABLED, TEST_DIRECT_IP", probeName)
	}
}

func executeTCPBindInterface(ctx context.Context, target model.Target, ifaceName string, res *ProbeResult) (*ProbeResult, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("interface parameter is required for TEST_TCP_BIND_INTERFACE")
	}

	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	// Set socket control to bind interface where supported
	setInterfaceControl(dialer, ifaceName)

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		res.Success = false
		res.Output = fmt.Sprintf("Failed to connect via interface %s: %v (elapsed: %dms)", ifaceName, err, elapsed)
		res.TCPReport = &model.TCPReport{
			Status:    model.TCPStatusFailed,
			LatencyMs: elapsed,
			Error:     err.Error(),
		}
		return res, nil
	}
	defer conn.Close()

	res.Success = true
	res.Output = fmt.Sprintf("Successfully connected to %s explicitly bound to %s (latency: %dms)", addr, ifaceName, elapsed)
	res.TCPReport = &model.TCPReport{
		Status:    model.TCPStatusConnected,
		LatencyMs: elapsed,
		LocalAddr: conn.LocalAddr().String(),
	}
	return res, nil
}

func executeTCPBindSource(ctx context.Context, target model.Target, srcIP string, res *ProbeResult) (*ProbeResult, error) {
	if srcIP == "" {
		return nil, fmt.Errorf("source IP parameter is required for TEST_TCP_BIND_SOURCE")
	}

	localAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(srcIP, "0"))
	if err != nil {
		return nil, fmt.Errorf("invalid source IP %s: %w", srcIP, err)
	}

	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   5 * time.Second,
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		res.Success = false
		res.Output = fmt.Sprintf("Failed to connect using source IP %s: %v", srcIP, err)
		res.TCPReport = &model.TCPReport{
			Status:    model.TCPStatusFailed,
			LatencyMs: elapsed,
			Error:     err.Error(),
		}
		return res, nil
	}
	defer conn.Close()

	res.Success = true
	res.Output = fmt.Sprintf("Successfully connected using bound source IP %s (latency: %dms)", srcIP, elapsed)
	res.TCPReport = &model.TCPReport{
		Status:    model.TCPStatusConnected,
		LatencyMs: elapsed,
		LocalAddr: conn.LocalAddr().String(),
	}
	return res, nil
}

func executeDNSWithResolver(ctx context.Context, target model.Target, resolverIP string, res *ProbeResult) (*ProbeResult, error) {
	if resolverIP == "" {
		return nil, fmt.Errorf("resolver IP parameter is required for TEST_DNS_WITH_RESOLVER")
	}

	customResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			resolverAddr := resolverIP
			if !hasPort(resolverAddr) {
				resolverAddr = net.JoinHostPort(resolverAddr, "53")
			}
			return d.DialContext(ctx, "udp", resolverAddr)
		},
	}

	ips, err := customResolver.LookupIP(ctx, "ip", target.Host)
	if err != nil {
		res.Success = false
		res.Output = fmt.Sprintf("Resolver %s failed to resolve %s: %v", resolverIP, target.Host, err)
		return res, nil
	}

	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}

	res.Success = true
	res.Output = fmt.Sprintf("Resolver %s successfully resolved %s -> %v", resolverIP, target.Host, ipStrs)
	return res, nil
}

func executeProxyDisabled(ctx context.Context, target model.Target, res *ProbeResult) (*ProbeResult, error) {
	// Temporarily clear proxy env
	prevHTTP := os.Getenv("HTTP_PROXY")
	prevHTTPS := os.Getenv("HTTPS_PROXY")
	prevAll := os.Getenv("ALL_PROXY")
	os.Unsetenv("HTTP_PROXY")
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("ALL_PROXY")
	defer func() {
		if prevHTTP != "" {
			os.Setenv("HTTP_PROXY", prevHTTP)
		}
		if prevHTTPS != "" {
			os.Setenv("HTTPS_PROXY", prevHTTPS)
		}
		if prevAll != "" {
			os.Setenv("ALL_PROXY", prevAll)
		}
	}()

	tcpCollector := tcp.New(5 * time.Second)
	report, err := tcpCollector.Collect(ctx, target, "")
	if err != nil {
		res.Success = false
		res.Output = fmt.Sprintf("Direct probe without proxy failed: %v", err)
		return res, nil
	}

	res.TCPReport = report
	res.Success = report.Status == model.TCPStatusConnected
	res.Output = fmt.Sprintf("Direct connection with proxy bypassed: status=%s latency=%dms", report.Status, report.LatencyMs)
	return res, nil
}

func executeDirectIP(ctx context.Context, target model.Target, directIP string, res *ProbeResult) (*ProbeResult, error) {
	if directIP == "" {
		return nil, fmt.Errorf("direct IP parameter required for TEST_DIRECT_IP")
	}

	tcpCollector := tcp.New(5 * time.Second)
	report, err := tcpCollector.Collect(ctx, target, directIP)
	if err != nil {
		res.Success = false
		res.Output = fmt.Sprintf("Direct IP connect to %s failed: %v", directIP, err)
		return res, nil
	}

	res.TCPReport = report
	res.Success = report.Status == model.TCPStatusConnected
	res.Output = fmt.Sprintf("Direct IP probe to %s: status=%s latency=%dms", directIP, report.Status, report.LatencyMs)
	return res, nil
}

func hasPort(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}
