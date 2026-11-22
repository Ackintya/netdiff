package tls

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"netdiff/pkg/model"
)

func TestCollect_NonTLSTarget(t *testing.T) {
	c := New(2 * time.Second)
	tgt := model.Target{
		Raw:      "10.10.0.2:8080",
		Host:     "10.10.0.2",
		Port:     8080,
		Protocol: "tcp",
	}

	report, err := c.Collect(context.Background(), tgt, "10.10.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report != nil {
		t.Errorf("expected nil report for non-TLS target, got %+v", report)
	}
}

func TestClassifyTLSError(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{x509.UnknownAuthorityError{}, "untrusted_root"},
		{x509.CertificateInvalidError{Reason: x509.Expired}, "expired"},
		{x509.HostnameError{Host: "foo.com"}, "hostname_mismatch"},
		{errors.New("tls: certificate signed by unknown authority"), "untrusted_root"},
		{errors.New("x509: certificate has expired or is not yet valid"), "expired"},
		{errors.New("tls: server selected unsupported protocol version 0301"), "protocol_version"},
		{errors.New("remote error: tls: handshake failure"), "handshake_failed"},
	}

	for _, tt := range tests {
		got := classifyTLSError(tt.err)
		if got != tt.expected {
			t.Errorf("classifyTLSError(%v) = %q, want %q", tt.err, got, tt.expected)
		}
	}
}

func TestPopulateCertInfo(t *testing.T) {
	report := &model.TLSReport{}
	expiry := time.Now().Add(48 * time.Hour)
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "api.internal.corp"},
		Issuer:   pkix.Name{CommonName: "Internal Root CA"},
		DNSNames: []string{"api.internal.corp", "api.corp"},
		NotAfter: expiry,
	}

	populateCertInfo(report, cert)
	if report.Subject != "api.internal.corp" {
		t.Errorf("unexpected subject: %s", report.Subject)
	}
	if report.Issuer != "Internal Root CA" {
		t.Errorf("unexpected issuer: %s", report.Issuer)
	}
	if len(report.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(report.DNSNames))
	}
	if report.DaysUntilExpiry < 1 || report.DaysUntilExpiry > 2 {
		t.Errorf("expected ~2 days until expiry, got %d", report.DaysUntilExpiry)
	}
}
