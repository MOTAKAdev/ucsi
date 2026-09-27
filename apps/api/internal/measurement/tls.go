package measurement

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"pikify.local/pikify-engine/api/internal/domain"
	"pikify.local/pikify-engine/api/internal/security"
)

type ValidateOptions struct {
	DNSEnabled     bool
	TCPEnabled     bool
	TLSEnabled     bool
	SNIEnabled     bool
	LatencyEnabled bool
}

func Validate(ctx context.Context, c domain.Candidate, sampleCount int, timeout time.Duration) ([]domain.Observation, error) {
	return ValidateWithOptions(ctx, c, sampleCount, timeout, ValidateOptions{
		DNSEnabled:     true,
		TCPEnabled:     true,
		TLSEnabled:     true,
		SNIEnabled:     true,
		LatencyEnabled: true,
	})
}

func ValidateWithOptions(ctx context.Context, c domain.Candidate, sampleCount int, timeout time.Duration, opt ValidateOptions) ([]domain.Observation, error) {
	if sampleCount < 1 {
		sampleCount = 1
	}
	if sampleCount > 20 {
		sampleCount = 20
	}

	// DNS resolution is always used internally for SSRF-safe destination pinning.
	// The DNS stage can still be marked NOT_TESTED.
	ips, err := security.ResolvePublic(ctx, c.Hostname)
	if err != nil {
		return nil, err
	}

	results := make([]domain.Observation, 0, len(ips)*sampleCount)

	for _, ipa := range ips {
		fam := "IPv6"
		if ipa.IP.To4() != nil {
			fam = "IPv4"
		}

		for i := 0; i < sampleCount; i++ {
			measured := time.Now().UTC()

			dnsStatus := "RESOLVED"
			if !opt.DNSEnabled {
				dnsStatus = "NOT_TESTED"
			}

			obs := domain.Observation{
				CandidateID:   c.ID,
				Origin:        "central_worker",
				ProbeID:       "central",
				MeasuredAt:    measured,
				ResolvedIP:    ipa.IP.String(),
				AddressFamily: fam,
				DNSStatus:     dnsStatus,
				TCPResult:     "NOT_TESTED",
				TLSResult:     "NOT_TESTED",
			}

			// No TCP/TLS/latency measurement requested.
			if !opt.TCPEnabled && !opt.TLSEnabled && !opt.LatencyEnabled {
				results = append(results, obs)
				continue
			}

			d := net.Dialer{Timeout: timeout}
			start := time.Now()

			conn, e := d.DialContext(
				ctx,
				"tcp",
				net.JoinHostPort(ipa.IP.String(), "443"),
			)
			if e != nil {
				if opt.TCPEnabled {
					obs.TCPResult = "FAILED"
				}
				obs.ErrorCode = classifyNetError(e)
				results = append(results, obs)
				continue
			}

			if opt.LatencyEnabled {
				obs.TCPConnectMS = elapsedMS(start)
			}

			if opt.TCPEnabled {
				obs.TCPResult = "SUCCESS"
			}

			if !opt.TLSEnabled {
				_ = conn.Close()
				results = append(results, obs)
				continue
			}

			serverName := ""
			if opt.SNIEnabled {
				serverName = c.Hostname
			}

			cfg := &tls.Config{
				ServerName:         serverName,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			}

			tc := tls.Client(conn, cfg)

			hsStart := time.Now()
			e = tc.HandshakeContext(ctx)

			if opt.LatencyEnabled {
				obs.TLSHandshakeMS = elapsedMS(hsStart)
				obs.TotalConnectionMS = elapsedMS(start)
			}

			if e != nil {
				_ = tc.Close()
				obs.TLSResult = "FAILED"
				obs.ErrorCode = classifyTLSError(e)
				results = append(results, obs)
				continue
			}

			cs := tc.ConnectionState()
			_ = tc.Close()

			obs.TLSResult = "SUCCESS"
			obs.TLSVersion = tlsVersion(cs.Version)
			obs.Cipher = tls.CipherSuiteName(cs.CipherSuite)
			obs.ALPN = cs.NegotiatedProtocol

			if len(cs.PeerCertificates) > 0 {
				cert := cs.PeerCertificates[0]
				sum := sha256.Sum256(cert.Raw)

				obs.CertFingerprint = hex.EncodeToString(sum[:])
				obs.CertIssuer = cert.Issuer.String()
				obs.CertSubject = cert.Subject.String()
				obs.CertHostnameValid = cert.VerifyHostname(c.Hostname) == nil
				obs.SNIAccepted = opt.SNIEnabled && obs.CertHostnameValid
				obs.CertChainValid = verifyChain(cert, cs.PeerCertificates[1:], c.Hostname)
			}

			results = append(results, obs)
		}
	}

	return results, nil
}

func verifyChain(leaf *x509.Certificate, intermediates []*x509.Certificate, hostname string) bool {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return false
	}

	inter := x509.NewCertPool()
	for _, cert := range intermediates {
		inter.AddCert(cert)
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		DNSName:       hostname,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	return err == nil
}

func elapsedMS(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func classifyNetError(e error) string {
	s := strings.ToLower(e.Error())

	if strings.Contains(s, "timeout") {
		return "TCP_TIMEOUT"
	}
	if strings.Contains(s, "refused") {
		return "TCP_REFUSED"
	}

	return "TCP_UNREACHABLE"
}

func classifyTLSError(e error) string {
	s := strings.ToLower(e.Error())

	if strings.Contains(s, "timeout") {
		return "TLS_TIMEOUT"
	}

	return "TLS_HANDSHAKE_FAILED"
}
