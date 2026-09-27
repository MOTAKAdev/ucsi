package measurement

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pikify.local/pikify-engine/api/internal/security"
)

type HTTPObservation struct {
	StatusCode    int
	Protocol      string
	Server        string
	Location      string
	Redirects     int
	ResponseMS    float64
	ContentLength int64
	ContentType   string
	HSTS          bool
}

func ValidateHTTP(ctx context.Context, hostname string, timeout time.Duration, maxBody int64, maxRedirects int) (HTTPObservation, error) {
	if maxBody <= 0 {
		maxBody = 64 * 1024
	}
	if maxRedirects < 0 {
		maxRedirects = 0
	}
	if maxRedirects > 5 {
		maxRedirects = 5
	}
	h, err := security.NormalizeHostname(hostname)
	if err != nil {
		return HTTPObservation{}, err
	}
	current := &url.URL{Scheme: "https", Host: h}
	visited := map[string]struct{}{}
	for redirect := 0; ; redirect++ {
		if current.Scheme != "https" && current.Scheme != "http" {
			return HTTPObservation{}, fmt.Errorf("unsupported redirect scheme")
		}
		port := 443
		if current.Scheme == "http" {
			port = 80
		}
		ips, err := security.ResolvePublic(ctx, current.Hostname())
		if err != nil {
			return HTTPObservation{}, fmt.Errorf("http destination rejected: %w", err)
		}
		transport := &http.Transport{
			Proxy:                  nil,
			TLSHandshakeTimeout:    timeout,
			ResponseHeaderTimeout:  timeout,
			MaxResponseHeaderBytes: 32 * 1024,
			IdleConnTimeout:        timeout,
			DisableKeepAlives:      true,
			TLSClientConfig:        &tls.Config{ServerName: current.Hostname(), MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13},
		}
		transport.DialContext = pinnedDialer(ips, port, timeout)
		client := &http.Client{Transport: transport, Timeout: timeout + 2*time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, current.String(), nil)
		if err != nil {
			return HTTPObservation{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			transport.CloseIdleConnections()
			return HTTPObservation{}, err
		}
		if resp.StatusCode == http.StatusMethodNotAllowed {
			_ = resp.Body.Close()
			transport.CloseIdleConnections()
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
			if err != nil {
				return HTTPObservation{}, err
			}
			resp, err = client.Do(req)
			if err != nil {
				return HTTPObservation{}, err
			}
		}
		headers := resp.Header.Clone()
		_, _ = io.CopyN(io.Discard, resp.Body, maxBody+1)
		_ = resp.Body.Close()
		transport.CloseIdleConnections()
		obs := HTTPObservation{StatusCode: resp.StatusCode, Protocol: resp.Proto, Server: headers.Get("Server"), Location: headers.Get("Location"), Redirects: redirect, ResponseMS: float64(time.Since(start).Microseconds()) / 1000, ContentLength: resp.ContentLength, ContentType: headers.Get("Content-Type"), HSTS: strings.Contains(strings.ToLower(headers.Get("Strict-Transport-Security")), "max-age")}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || obs.Location == "" || redirect >= maxRedirects {
			return obs, nil
		}
		next, err := current.Parse(obs.Location)
		if err != nil {
			return obs, fmt.Errorf("invalid redirect location: %w", err)
		}
		if next.Scheme != "http" && next.Scheme != "https" {
			return obs, fmt.Errorf("redirect scheme blocked")
		}
		nextHost, err := security.NormalizeHostname(next.Hostname())
		if err != nil {
			return obs, fmt.Errorf("redirect host blocked: %w", err)
		}
		if next.Scheme == "https" && next.Port() != "" && next.Port() != "443" {
			return obs, fmt.Errorf("non-standard HTTPS redirect port blocked")
		}
		if next.Scheme == "http" && next.Port() != "" && next.Port() != "80" {
			return obs, fmt.Errorf("non-standard HTTP redirect port blocked")
		}
		next.Host = nextHost
		key := next.String()
		if _, ok := visited[key]; ok {
			return obs, fmt.Errorf("redirect loop detected")
		}
		visited[key] = struct{}{}
		current = next
	}
}

func pinnedDialer(ips []net.IPAddr, port int, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: timeout}
		var last error
		for _, ip := range ips {
			c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.IP.String(), fmt.Sprintf("%d", port)))
			if e == nil {
				return c, nil
			}
			last = e
		}
		return nil, last
	}
}
