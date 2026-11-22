package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	return &Collector{Timeout: timeout}
}

// Collect executes a TLS handshake against target if target is TLS-enabled and returns a TLSReport.
func (c *Collector) Collect(ctx context.Context, target model.Target, destIP string) (*model.TLSReport, error) {
	if !target.IsTLS() {
		return nil, nil
	}

	dialHost := target.Host
	if destIP != "" {
		dialHost = destIP
	}
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", target.Port))

	dialer := &net.Dialer{
		Timeout: c.Timeout,
	}

	report := &model.TLSReport{
		ServerName: target.Host,
	}

	// 1. First attempt: standard strict CA validation
	cfg := &tls.Config{
		ServerName: target.Host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err == nil {
		defer conn.Close()
		state := conn.ConnectionState()
		report.HandshakeSuccess = true
		report.Version = tlsVersionName(state.Version)
		report.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > 0 {
			populateCertInfo(report, state.PeerCertificates[0])
		}
		return report, nil
	}

	// 2. Handshake or verification failed
	report.HandshakeSuccess = false
	report.Error = err.Error()
	report.ErrorCategory = classifyTLSError(err)

	// 3. If failure was certificate-related, perform an insecure probe to extract the certificate details anyway
	insecureCfg := &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true,
	}
	if inConn, inErr := tls.DialWithDialer(dialer, "tcp", addr, insecureCfg); inErr == nil {
		defer inConn.Close()
		state := inConn.ConnectionState()
		report.Version = tlsVersionName(state.Version)
		report.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > 0 {
			populateCertInfo(report, state.PeerCertificates[0])
		}
	}

	return report, nil
}

func classifyTLSError(err error) string {
	if err == nil {
		return ""
	}
	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return "untrusted_root"
	}
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		if certInvalidErr.Reason == x509.Expired {
			return "expired"
		}
		return "invalid_cert"
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "hostname_mismatch"
	}

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "signed by unknown authority") {
		return "untrusted_root"
	}
	if strings.Contains(errStr, "expired") || strings.Contains(errStr, "has expired") {
		return "expired"
	}
	if strings.Contains(errStr, "doesn't contain any ip sans") || strings.Contains(errStr, "certificate is valid for") || strings.Contains(errStr, "name mismatch") {
		return "hostname_mismatch"
	}
	if strings.Contains(errStr, "protocol version") || strings.Contains(errStr, "no common cipher") {
		return "protocol_version"
	}

	return "handshake_failed"
}

func populateCertInfo(report *model.TLSReport, cert *x509.Certificate) {
	if cert == nil {
		return
	}
	report.Subject = cert.Subject.CommonName
	if report.Subject == "" && len(cert.Subject.Organization) > 0 {
		report.Subject = cert.Subject.Organization[0]
	}
	report.Issuer = cert.Issuer.CommonName
	if report.Issuer == "" && len(cert.Issuer.Organization) > 0 {
		report.Issuer = cert.Issuer.Organization[0]
	}
	report.DNSNames = cert.DNSNames
	report.Expiry = cert.NotAfter.UTC().Format(time.RFC3339)
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	report.DaysUntilExpiry = days
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
