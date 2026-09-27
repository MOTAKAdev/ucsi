package reality

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"pikify.local/pikify-engine/api/internal/security"
)

// X25519MLKEM768 is the TLS NamedGroup code used by the hybrid post-quantum group.
const x25519MLKEM768 = tls.CurveID(0x11EC)

type ScanResult struct {
	Target      string   `json:"target"`
	Host        string   `json:"host"`
	IP          string   `json:"ip,omitempty"`
	Port        int      `json:"port"`
	SNI         string   `json:"sni,omitempty"`
	Feasible    bool     `json:"feasible"`
	TLS13       bool     `json:"tls13"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	H2          bool     `json:"h2"`
	ALPN        string   `json:"alpn,omitempty"`
	Cipher      string   `json:"cipher,omitempty"`
	X25519      *bool    `json:"x25519,omitempty"`
	PostQuantum *bool    `json:"post_quantum,omitempty"`
	Curve       string   `json:"curve,omitempty"`
	H3          bool     `json:"h3"`
	CertValid   bool     `json:"cert_valid"`
	CertSubject string   `json:"cert_subject,omitempty"`
	CertIssuer  string   `json:"cert_issuer,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	ServerNames []string `json:"server_names,omitempty"`
	LatencyMS   int64    `json:"latency_ms,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

type targetInfo struct {
	host string
	port int
	ip   net.IP
}

func Scan(ctx context.Context, target string, timeout time.Duration) (ScanResult, error) {
	if timeout < time.Second {
		timeout = time.Second
	}
	if timeout > 20*time.Second {
		timeout = 20 * time.Second
	}
	info, err := parseTarget(target)
	if err != nil {
		return ScanResult{}, err
	}
	res := ScanResult{Target: target, Host: info.host, Port: info.port}
	ips, err := resolvePinned(ctx, info.host, info.ip)
	if err != nil {
		return res, err
	}

	serverName := info.host
	var state tls.ConnectionState
	var leaf *x509.Certificate
	var chain []*x509.Certificate
	var usedIP net.IP
	var latency time.Duration

	for _, ip := range ips {
		st, cert, certs, d, e := tlsProbe(ctx, ip, info.port, serverName, timeout, nil)
		if e != nil {
			continue
		}
		state, leaf, chain, latency, usedIP = st, cert, certs, d, ip
		break
	}
	if leaf == nil {
		return res, fmt.Errorf("TLS 1.3 handshake failed")
	}

	if net.ParseIP(info.host) != nil {
		serverName = discoverSNI(leaf)
		if serverName != "" {
			if st, cert, certs, d, e := tlsProbe(ctx, usedIP, info.port, serverName, timeout, nil); e == nil {
				state, leaf, chain, latency = st, cert, certs, d
			}
		}
	}

	res.IP = usedIP.String()
	res.SNI = serverName
	res.LatencyMS = latency.Milliseconds()
	res.TLSVersion = tlsVersion(state.Version)
	res.TLS13 = state.Version == tls.VersionTLS13
	res.ALPN = state.NegotiatedProtocol
	res.H2 = state.NegotiatedProtocol == "h2"
	res.Cipher = tls.CipherSuiteName(state.CipherSuite)
	res.CertSubject = leaf.Subject.String()
	res.CertIssuer = leaf.Issuer.String()
	res.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	res.ServerNames = certificateNames(leaf)
	res.CertValid = verifyCertificate(leaf, chain[1:], serverName)

	x := probeCurve(ctx, usedIP, info.port, serverName, timeout, tls.X25519)
	pq := probeCurve(ctx, usedIP, info.port, serverName, timeout, x25519MLKEM768)
	res.X25519 = &x
	res.PostQuantum = &pq
	if pq {
		res.Curve = "X25519MLKEM768"
	} else if x {
		res.Curve = "X25519"
	} else {
		res.Curve = "Unknown"
	}
	res.H3 = probeH3Advertisement(ctx, usedIP, info.port, serverName, timeout)
	res.Feasible = res.TLS13 && res.H2 && res.CertValid
	res.Reason = buildReason(res)
	return res, nil
}

func parseTarget(raw string) (targetInfo, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return targetInfo{}, fmt.Errorf("target is required")
	}
	if ip := net.ParseIP(raw); ip != nil {
		if !security.IsPublicIP(ip.String()) {
			return targetInfo{}, fmt.Errorf("target IP is not public")
		}
		return targetInfo{host: ip.String(), port: 443, ip: ip}, nil
	}
	host, port := raw, 443
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host = h
		port, err = parsePort(p)
		if err != nil {
			return targetInfo{}, err
		}
	} else if strings.Count(raw, ":") == 1 {
		parts := strings.SplitN(raw, ":", 2)
		if p, e := parsePort(parts[1]); e == nil {
			host, port = parts[0], p
		}
	}
	h, err := security.NormalizeHostname(host)
	if err != nil {
		return targetInfo{}, err
	}
	return targetInfo{host: h, port: port}, nil
}

func parsePort(raw string) (int, error) {
	var p int
	if _, err := fmt.Sscan(raw, &p); err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid target port")
	}
	return p, nil
}

func resolvePinned(ctx context.Context, host string, ip net.IP) ([]net.IP, error) {
	if ip != nil {
		return []net.IP{ip}, nil
	}
	ips, err := security.ResolvePublic(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(ips))
	for _, item := range ips {
		out = append(out, item.IP)
	}
	return out, nil
}

func tlsProbe(ctx context.Context, ip net.IP, port int, sni string, timeout time.Duration, curves []tls.CurveID) (tls.ConnectionState, *x509.Certificate, []*x509.Certificate, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		return tls.ConnectionState{}, nil, nil, 0, err
	}
	cfg := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}
	if len(curves) > 0 {
		cfg.CurvePreferences = curves
	}
	tc := tls.Client(conn, cfg)
	start := time.Now()
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return tls.ConnectionState{}, nil, nil, time.Since(start), err
	}
	latency := time.Since(start)
	state := tc.ConnectionState()
	certs := append([]*x509.Certificate(nil), state.PeerCertificates...)
	_ = tc.Close()
	if len(certs) == 0 {
		return state, nil, certs, latency, fmt.Errorf("server did not present a certificate")
	}
	return state, certs[0], certs, latency, nil
}

func probeCurve(ctx context.Context, ip net.IP, port int, sni string, timeout time.Duration, curve tls.CurveID) bool {
	_, _, _, _, err := tlsProbe(ctx, ip, port, sni, timeout, []tls.CurveID{curve})
	return err == nil
}

func probeH3Advertisement(ctx context.Context, ip net.IP, port int, sni string, timeout time.Duration) bool {
	if ip == nil || sni == "" {
		return false
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	}
	client := &http.Client{Transport: transport, Timeout: timeout + 2*time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := url.URL{Scheme: "https", Host: net.JoinHostPort(sni, fmt.Sprintf("%d", port))}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint.String(), nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		transport.CloseIdleConnections()
		return false
	}
	alt := strings.ToLower(resp.Header.Get("Alt-Svc"))
	_ = resp.Body.Close()
	transport.CloseIdleConnections()
	return strings.Contains(alt, "h3")
}

func verifyCertificate(leaf *x509.Certificate, intermediates []*x509.Certificate, name string) bool {
	if leaf == nil || name == "" {
		return false
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return false
	}
	inter := x509.NewCertPool()
	for _, cert := range intermediates {
		inter.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err == nil
}

func discoverSNI(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, name := range cert.DNSNames {
		if name != "" && !strings.Contains(name, "*") {
			return name
		}
	}
	if cert.Subject.CommonName != "" && !strings.Contains(cert.Subject.CommonName, "*") {
		return cert.Subject.CommonName
	}
	return ""
}

func certificateNames(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.DNSNames))
	for _, name := range cert.DNSNames {
		if name != "" && !strings.Contains(name, "*") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func tlsVersion(v uint16) string {
	if v == tls.VersionTLS13 {
		return "TLS 1.3"
	}
	if v == tls.VersionTLS12 {
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%x", v)
}

func buildReason(r ScanResult) string {
	missing := make([]string, 0, 3)
	if !r.TLS13 {
		missing = append(missing, "TLS 1.3")
	}
	if !r.H2 {
		missing = append(missing, "HTTP/2")
	}
	if !r.CertValid {
		missing = append(missing, "valid certificate")
	}
	if len(missing) == 0 {
		return "TLS 1.3, HTTP/2 and certificate validation passed"
	}
	return "Missing: " + strings.Join(missing, ", ")
}
