package originscan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"pikify.local/pikify-engine/api/internal/security"
)

const (
	maxCandidates        = 1200
	qualifiedKeep        = 15
	deepCandidates = 72
	tlsGateConcurrency   = 48
	deepConcurrency      = 18
	tlsGateTO            = 1200 * time.Millisecond
	deepTO               = 2500 * time.Millisecond
	defaultTO            = deepTO
	maxRedirects         = 0
	trancoURL            = "https://tranco-list.eu/top-1m.csv.zip"
	majesticURL          = "https://downloads.majestic.com/majestic_million.csv"
)

// The built-in list is deliberately only a fallback. AutoScan prefers a
// configurable local candidate file and otherwise refreshes a public ranking
// cache, then applies the mandatory protocol gate before ranking.
var DefaultCandidates = []string{
	"cloudflare.com", "www.cloudflare.com", "google.com", "www.google.com", "googleapis.com", "gstatic.com",
	"youtube.com", "www.youtube.com", "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
	"whatsapp.com", "www.whatsapp.com", "microsoft.com", "www.microsoft.com", "bing.com", "apple.com", "www.apple.com",
	"amazon.com", "www.amazon.com", "github.com", "www.github.com", "gitlab.com", "wikipedia.org", "www.wikipedia.org",
	"mozilla.org", "www.mozilla.org", "reddit.com", "www.reddit.com", "discord.com", "telegram.org", "www.telegram.org",
	"fastly.com", "www.fastly.com", "jsdelivr.com", "cdnjs.com", "npmjs.com", "pypi.org", "docker.com", "kernel.org",
	"gnu.org", "python.org", "go.dev", "golang.org", "rust-lang.org", "stackoverflow.com", "ietf.org", "icann.org",
	"letsencrypt.org", "cloud.google.com", "developers.google.com", "raw.githubusercontent.com", "www.paypal.com", "stripe.com",
	"shopify.com", "www.shopify.com", "netflix.com", "www.netflix.com", "spotify.com", "www.spotify.com", "zoom.us", "www.zoom.us",
	"dropbox.com", "www.dropbox.com", "slack.com", "www.slack.com", "notion.so", "www.notion.so", "linkedin.com", "www.linkedin.com",
	"twitch.tv", "www.twitch.tv", "medium.com", "archive.org", "w3.org", "mit.edu", "www.nytimes.com", "bbc.com", "www.bbc.com",
	"cnn.com", "www.cnn.com", "yandex.com", "www.yandex.com", "vk.com", "www.vk.com", "baidu.com", "www.baidu.com",
	"qq.com", "www.qq.com", "samsung.com", "www.samsung.com", "adobe.com", "www.adobe.com", "oracle.com", "www.oracle.com",
	"intel.com", "www.intel.com", "nvidia.com", "www.nvidia.com", "cloud.google.com", "storage.googleapis.com", "fonts.googleapis.com",
}

type CandidateResult struct {
	Rank           int      `json:"rank"`
	SNI            string   `json:"sni"`
	Target         string   `json:"target"`
	IP             string   `json:"ip,omitempty"`
	Status         string   `json:"status"`
	Reason         string   `json:"reason,omitempty"`
	TCPConnectMS   float64  `json:"tcp_connect_ms,omitempty"`
	TLSHandshakeMS float64  `json:"tls_handshake_ms,omitempty"`
	LatencyMS      float64  `json:"latency_ms,omitempty"`
	ServerToSNIMS  float64  `json:"server_to_sni_ms,omitempty"`
	Stability      float64  `json:"stability"`
	TLS13          bool     `json:"tls13"`
	H2             bool     `json:"http2"`
	SNIAccepted    bool     `json:"sni_accepted"`
	CertValid      bool     `json:"certificate_valid"`
	CertSubject    string   `json:"certificate_subject,omitempty"`
	CertIssuer     string   `json:"certificate_issuer,omitempty"`
	CertExpiresAt  string   `json:"certificate_expires_at,omitempty"`
	CertSANs       []string `json:"certificate_sans,omitempty"`
	ALPN           string   `json:"alpn,omitempty"`
	HTTPStatus     int      `json:"http_status,omitempty"`
	HTTPProtocol   string   `json:"http_protocol,omitempty"`
	Redirects      int      `json:"redirects"`
	RedirectTarget string   `json:"redirect_target,omitempty"`
	X25519         *bool    `json:"x25519,omitempty"`
	PostQuantum    *bool    `json:"post_quantum,omitempty"`
	HTTP3             *bool   `json:"http3,omitempty"`
	HTTP3Advertised    bool    `json:"http3_advertised"`
	HTTP3HandshakeMS   float64 `json:"http3_handshake_ms,omitempty"`
	ServerP95MS        float64 `json:"server_p95_ms,omitempty"`
	JitterMS           float64 `json:"jitter_ms,omitempty"`
	RankingScore       float64 `json:"ranking_score,omitempty"`
	EvidenceScore      float64 `json:"evidence_score,omitempty"`
	Confidence         string  `json:"confidence,omitempty"`
}

type AutoResult struct {
	OriginIP          string            `json:"origin_ip"`
	Origin            string            `json:"origin"`
	CandidatesScanned int               `json:"candidates_scanned"`
	QualifiedCount    int               `json:"qualified_count"`
	Results           []CandidateResult `json:"results"`
	DurationMS        int64             `json:"duration_ms"`
}

type webEvidence struct {
	OK             bool
	TLS13          bool
	H2             bool
	SNIAccepted    bool
	CertValid      bool
	ALPN           string
	HTTPStatus     int
	HTTPProtocol   string
	H3             bool
	H3Advertised   bool
	H3HandshakeMS  float64
	Redirects      int
	RedirectTarget string
	IP             net.IP
	TCPMS          float64
	TLSMS          float64
	CertSubject    string
	CertIssuer     string
	CertExpires    string
	CertSANs       []string
}

type tlsObservation struct {
	OK          bool
	TLS13       bool
	H2          bool
	SNIAccepted bool
	CertValid   bool
	ALPN        string
	TCPMS       float64
	TLSMS       float64
	IP          net.IP
	CertSubject string
	CertIssuer  string
	CertExpires string
	CertSANs    []string
	Error       string
}

type aggregate struct {
	CandidateResult
	successes int
	attempts  int
	tcp       []float64
	tls       []float64
	total     []float64
}

var candidateCache struct {
	sync.Mutex
	at   time.Time
	list []string
}

func AutoScan(ctx context.Context, originIP string, samples, topN int, candidateFile string) (AutoResult, error) {
	origin, err := verifyOrigin(originIP)
	if err != nil {
		return AutoResult{}, err
	}
	if samples < 1 || samples > 3 {
		return AutoResult{}, fmt.Errorf("samples must be between 1 and 3")
	}
	if topN < 1 || topN > qualifiedKeep {
		return AutoResult{}, fmt.Errorf("top_n must be between 1 and %d", qualifiedKeep)
	}

	candidates := loadCandidates(ctx, candidateFile)

	// Always include the target server's PTR hostname when available.
	// It is a high-value SNI candidate for arbitrary server IPs and does not
	// require the hostname to appear in global ranking lists.
	if ptrs, err := net.DefaultResolver.LookupAddr(ctx, origin); err == nil && len(ptrs) > 0 {
		candidates = uniqueCandidates(append(ptrs, candidates...))
	}

	if len(candidates) == 0 {
		return AutoResult{}, fmt.Errorf("no SNI candidates configured")
	}
	if len(candidates) > maxCandidates {
		candidates = candidates[:maxCandidates]
	}

	started := time.Now()
	fast := make([]CandidateResult, len(candidates))
	sem := make(chan struct{}, tlsGateConcurrency)
	var wg sync.WaitGroup
	for i, candidate := range candidates {
		wg.Add(1)
		go func(i int, candidate string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			fast[i] = fastScreen(ctx, origin, candidate, tlsGateTO)
		}(i, candidate)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return AutoResult{}, err
	}

	gate := make([]CandidateResult, 0, len(fast))
	for _, r := range fast {
		if tlsReady(r) {
			gate = append(gate, r)
		}
	}
	sort.SliceStable(gate, func(i, j int) bool { return better(gate[i], gate[j]) })
	if len(gate) > deepCandidates {
		gate = gate[:deepCandidates]
	}

	qualified := make([]CandidateResult, 0, qualifiedKeep*2)
	deepSem := make(chan struct{}, deepConcurrency)
	phase2 := make([]CandidateResult, len(gate))
	phase2OK := make([]bool, len(gate))
	var qwg sync.WaitGroup
	for i := range gate {
		qwg.Add(1)
		go func(i int) {
			defer qwg.Done()
			select {
			case deepSem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-deepSem }()
			res := scanQualified(ctx, origin, gate[i], gate[i].SNI, samples, deepTO)
			if mandatoryReady(res) && res.Stability >= 1 {
				phase2[i] = res
				phase2OK[i] = true
			}
		}(i)
	}
	qwg.Wait()
	if err := ctx.Err(); err != nil {
		return AutoResult{}, err
	}
	for i := range phase2 {
		if phase2OK[i] {
			qualified = append(qualified, phase2[i])
		}
	}

	assignRankingScores(qualified)
	qualifiedTotal := len(qualified)
	sort.SliceStable(qualified, func(i, j int) bool { return better(qualified[i], qualified[j]) })
	if len(qualified) > topN {
		qualified = qualified[:topN]
	}
	if len(qualified) > qualifiedKeep {
		qualified = qualified[:qualifiedKeep]
	}
	for i := range qualified {
		qualified[i].Rank = i + 1
	}

	return AutoResult{
		OriginIP:          origin,
		Origin:            "user_server",
		CandidatesScanned: len(candidates),
		QualifiedCount:    qualifiedTotal,
		Results:           qualified,
		DurationMS:        time.Since(started).Milliseconds(),
	}, nil
}

func ManualScan(ctx context.Context, originIP, sni, target string, port, samples int) (CandidateResult, error) {
	origin, err := verifyOrigin(originIP)
	if err != nil {
		return CandidateResult{}, err
	}

	sni = strings.TrimSpace(sni)
	if _, err := security.NormalizeHostname(sni); err != nil {
		return CandidateResult{}, fmt.Errorf("invalid SNI: %w", err)
	}

	normalizedTarget, err := security.NormalizeHostname(strings.TrimSpace(target))
	if err != nil {
		return CandidateResult{}, fmt.Errorf("invalid target: %w", err)
	}

	if port < 1 || port > 65535 {
		return CandidateResult{}, fmt.Errorf("invalid target port")
	}

	if samples < 1 || samples > 3 {
		return CandidateResult{}, fmt.Errorf("samples must be between 1 and 3")
	}

	ips, err := security.ResolvePublic(ctx, normalizedTarget)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("target DNS resolution failed: %w", err)
	}

	var base CandidateResult
	base.SNI = sni
	base.Target = fmt.Sprintf("%s:%d", normalizedTarget, port)
	base.Status = "NOT_READY"

	for _, ipAddr := range filterIPv4(ips) {
		ip := ipAddr.IP.To4()
		if ip == nil {
			continue
		}

		ev := probeWeb(ctx, origin, ip, sni, defaultTO)
		if !ev.OK {
			continue
		}

		base.IP = ip.String()
		base.TLS13 = ev.TLS13
		base.H2 = ev.H2
		base.SNIAccepted = ev.SNIAccepted
		base.CertValid = ev.CertValid
		base.ALPN = ev.ALPN
		base.HTTPStatus = ev.HTTPStatus
		base.HTTPProtocol = ev.HTTPProtocol
		base.HTTP3Advertised = ev.H3Advertised
		base.HTTP3 = boolPtr(false)
		if ev.H3Advertised {
			h3 := probeHTTP3(ctx, origin, ip, sni, defaultTO)
			base.HTTP3HandshakeMS = h3.ElapsedMS
			base.HTTP3 = boolPtr(h3.Success)
		}
		base.Redirects = ev.Redirects
		base.RedirectTarget = ev.RedirectTarget
		base.TCPConnectMS = ev.TCPMS
		base.TLSHandshakeMS = ev.TLSMS
		base.CertSubject = ev.CertSubject
		base.CertIssuer = ev.CertIssuer
		base.CertExpiresAt = ev.CertExpires
		base.CertSANs = ev.CertSANs
		base.ServerToSNIMS = ev.TCPMS + ev.TLSMS
		base.LatencyMS = base.ServerToSNIMS
		break
	}

	if !httpReady(base) {
		base.Rank = 1
		base.Reason = "HTTPS capability probe failed"
		return base, nil
	}

	res := scanQualified(ctx, origin, base, normalizedTarget, samples, defaultTO)
	res.Target = fmt.Sprintf("%s:%d", normalizedTarget, port)
	res.Rank = 1
	return res, nil
}

func verifyOrigin(raw string) (string, error) {
	ip := strings.TrimSpace(raw)
	if !security.IsPublicIP(ip) {
		return "", fmt.Errorf("server IPv4 must be a public IP")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("server IPv4 is required")
	}
	normalized := parsed.To4().String()
	if expected := strings.TrimSpace(os.Getenv("PIKIFY_ORIGIN_IP")); expected != "" {
		if expectedParsed := net.ParseIP(expected); expectedParsed == nil || expectedParsed.To4() == nil || expectedParsed.To4().String() != normalized {
			return "", fmt.Errorf("entered server IP does not match the configured Pikify server origin")
		}
	}
	return normalized, nil
}

func loadCandidates(ctx context.Context, path string) []string {
	if strings.TrimSpace(path) == "" {
		path = strings.TrimSpace(os.Getenv("UCSI_SNI_CANDIDATES_FILE"))
	}
	if path != "" {
		if lines, err := readCandidateFile(path); err == nil && len(lines) > 0 {
			return uniqueCandidates(lines)
		}
	}
	candidateCache.Lock()
	if len(candidateCache.list) > 0 && time.Since(candidateCache.at) < 6*time.Hour {
		list := append([]string(nil), candidateCache.list...)
		candidateCache.Unlock()
		return list
	}
	candidateCache.Unlock()

var wg sync.WaitGroup
	var tranco, majestic []string
	wg.Add(2)
	go func() {
		defer wg.Done()
		tranco, _ = fetchTranco(ctx)
	}()
	go func() {
		defer wg.Done()
		majestic, _ = fetchMajestic(ctx)
	}()
	wg.Wait()

	combined := make([]string, 0, maxCandidates*4)
	combined = append(combined, diversifySource(tranco, 900)...)
	combined = append(combined, diversifySource(majestic, 900)...)
	combined = append(combined, DefaultCandidates...)
	list := uniqueCandidates(combined)

	candidateCache.Lock()
	candidateCache.list = append([]string(nil), list...)
	candidateCache.at = time.Now()
	candidateCache.Unlock()
	return list
}

func uniqueCandidates(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		candidate := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, "\r")))
		if candidate == "" || strings.HasPrefix(candidate, "#") {
			continue
		}
		if _, err := security.NormalizeHostname(candidate); err != nil {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func readCandidateFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(b), "\n"), nil
}

func diversifySource(in []string, budget int) []string {
	if len(in) <= budget {
		return append([]string(nil), in...)
	}
	out := make([]string, 0, budget)
	buckets := []struct {
		start int
		count int
	}{
		{0, 350},
		{500, 250},
		{1000, 200},
		{2000, 100},
	}
	for _, b := range buckets {
		if len(out) >= budget || b.start >= len(in) {
			break
		}
		end := b.start + b.count
		if end > len(in) {
			end = len(in)
		}
		for _, v := range in[b.start:end] {
			out = append(out, v)
			if len(out) >= budget {
				break
			}
		}
	}
	return out
}

func fetchTranco(ctx context.Context) ([]string, error) {
	localCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(localCtx, http.MethodGet, trancoURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("tranco status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, zf := range zr.File {
		if !strings.HasSuffix(strings.ToLower(zf.Name), ".csv") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		reader := csv.NewReader(bufio.NewReader(rc))
		reader.FieldsPerRecord = -1
		out := make([]string, 0, 3000)
		for len(out) < 3000 {
			row, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil || len(row) < 2 {
				continue
			}
			domain := strings.TrimSpace(row[1])
			if domain == "" || strings.Contains(domain, " ") {
				continue
			}
			out = append(out, domain)
		}
		return out, nil
	}
	return nil, fmt.Errorf("tranco CSV not found")
}

func fetchMajestic(ctx context.Context) ([]string, error) {
	localCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(localCtx, http.MethodGet, majesticURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("majestic status %d", resp.StatusCode)
	}
	reader := csv.NewReader(bufio.NewReader(resp.Body))
	reader.FieldsPerRecord = -1
	out := make([]string, 0, 3000)
	for len(out) < 3000 {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(row) < 3 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(row[0]), "GlobalRank") {
			continue
		}
		domain := strings.TrimSpace(row[2])
		if domain == "" || strings.Contains(domain, " ") {
			continue
		}
		out = append(out, domain)
	}
	return out, nil
}

func fastScreen(ctx context.Context, origin, candidate string, timeout time.Duration) CandidateResult {
	res := CandidateResult{
		SNI:    candidate,
		Target: fmt.Sprintf("%s:443", origin),
		Status: "NOT_READY",
	}

	ip := net.ParseIP(origin)
	if ip == nil || ip.To4() == nil {
		res.Reason = "Invalid server IPv4"
		return res
	}

	ev := probeWeb(ctx, origin, ip.To4(), candidate, timeout)
	if !ev.OK {
		res.Reason = "HTTPS capability probe failed"
		return res
	}

	res.IP = ip.To4().String()
	res.TLS13 = ev.TLS13
	res.H2 = ev.H2
	res.SNIAccepted = ev.SNIAccepted
	res.CertValid = ev.CertValid
	res.ALPN = ev.ALPN
	res.HTTPStatus = ev.HTTPStatus
	res.HTTPProtocol = ev.HTTPProtocol
	res.HTTP3Advertised = ev.H3Advertised
	res.HTTP3 = boolPtr(ev.H3Advertised)
	res.Redirects = ev.Redirects
	res.RedirectTarget = ev.RedirectTarget
	res.TCPConnectMS = ev.TCPMS
	res.TLSHandshakeMS = ev.TLSMS
	res.ServerToSNIMS = ev.TCPMS + ev.TLSMS
	res.LatencyMS = res.ServerToSNIMS
	res.CertSubject = ev.CertSubject
	res.CertIssuer = ev.CertIssuer
	res.CertExpiresAt = ev.CertExpires
	res.CertSANs = ev.CertSANs
	res.Status = "PROVISIONAL"
	return res
}

func scanQualified(ctx context.Context, origin string, base CandidateResult, target string, samples int, timeout time.Duration) CandidateResult {
	res := base
	res.Target = fmt.Sprintf("%s:443", target)

	web := probeWeb(ctx, origin, net.ParseIP(res.IP), res.SNI, timeout)
	if !web.OK {
		res.Status = "NOT_READY"
		res.Reason = "HTTPS capability probe failed"
		return res
	}
	res.HTTPStatus = web.HTTPStatus
	res.HTTPProtocol = web.HTTPProtocol
	res.HTTP3Advertised = web.H3Advertised
	res.Redirects = web.Redirects
	res.RedirectTarget = web.RedirectTarget
	res.HTTP3 = boolPtr(false)

	var h3 http3Evidence
	var x25519OK, pqOK bool
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if res.HTTP3Advertised {
			h3 = probeHTTP3(ctx, origin, net.ParseIP(res.IP), res.SNI, timeout)
		}
	}()
	go func() {
		defer wg.Done()
		x25519OK = probeCurve(ctx, origin, net.ParseIP(res.IP), 443, res.SNI, timeout, tls.X25519)
	}()
	go func() {
		defer wg.Done()
		pqOK = probeCurve(ctx, origin, net.ParseIP(res.IP), 443, res.SNI, timeout, tls.X25519MLKEM768)
	}()
	wg.Wait()

	res.HTTP3HandshakeMS = h3.ElapsedMS
	res.HTTP3 = boolPtr(h3.Success)
	res.X25519 = boolPtr(x25519OK)
	res.PostQuantum = boolPtr(pqOK)

	if !x25519OK || !pqOK {
		res.Status = "NOT_READY"
		res.Reason = "Mandatory key-exchange gate failed"
		return res
	}
	if !httpReady(res) {
		res.Status = "NOT_READY"
		res.Reason = "HTTP/2 + certificate + HTTP/3 Alt-Svc validation failed"
		return res
	}

	ag := &aggregate{CandidateResult: res, attempts: samples}
	ip := net.ParseIP(res.IP)
	for i := 0; i < samples; i++ {
		if ip == nil {
			break
		}
		o := tlsProbe(ctx, origin, ip, 443, res.SNI, timeout)
		if !o.OK {
			continue
		}
		ag.successes++
		ag.candidateResultSet(o)
		if o.TCPMS > 0 {
			ag.tcp = append(ag.tcp, o.TCPMS)
		}
		if o.TLSMS > 0 {
			ag.tls = append(ag.tls, o.TLSMS)
		}
		if o.TCPMS > 0 && o.TLSMS > 0 {
			ag.total = append(ag.total, o.TCPMS+o.TLSMS)
		}
	}
	final := ag.finalize()
	if mandatoryReady(final) && final.Stability >= 1 {
		final.Status = "READY"
		final.Reason = "All mandatory TLS/HTTP2/certificate/X25519/PQ/HTTP3 checks passed"
	} else {
		final.Status = "NOT_READY"
		if final.Reason == "" {
			final.Reason = "Mandatory gate or stability check failed"
		}
	}
	return final
}

func tlsReady(r CandidateResult) bool {
	return r.TLS13 &&
		r.H2 &&
		r.ALPN == "h2" &&
		r.SNIAccepted &&
		r.CertValid
}

func httpReady(r CandidateResult) bool {
	return tlsReady(r) &&
		r.HTTP3Advertised
}

func mandatoryReady(r CandidateResult) bool {
	return httpReady(r) &&
		r.X25519 != nil &&
		*r.X25519 &&
		r.PostQuantum != nil &&
		*r.PostQuantum
}

func (a *aggregate) candidateResultSet(o tlsObservation) {
	if o.IP != nil {
		a.IP = o.IP.String()
	}
	a.TLS13 = a.TLS13 || o.TLS13
	a.H2 = a.H2 || o.H2
	a.SNIAccepted = a.SNIAccepted || o.SNIAccepted
	a.CertValid = a.CertValid || o.CertValid
	if o.ALPN != "" {
		a.ALPN = o.ALPN
	}
	if o.TCPMS > 0 {
		a.TCPConnectMS = o.TCPMS
	}
	if o.TLSMS > 0 {
		a.TLSHandshakeMS = o.TLSMS
	}
	if o.CertSubject != "" {
		a.CertSubject = o.CertSubject
	}
	if o.CertIssuer != "" {
		a.CertIssuer = o.CertIssuer
	}
	if o.CertExpires != "" {
		a.CertExpiresAt = o.CertExpires
	}
	if len(o.CertSANs) > 0 {
		a.CertSANs = append([]string(nil), o.CertSANs...)
	}
}

func (a *aggregate) finalize() CandidateResult {
	a.Stability = float64(a.successes) / float64(max(1, a.attempts))
	sort.Float64s(a.tcp)
	sort.Float64s(a.tls)
	sort.Float64s(a.total)
	if len(a.tcp) > 0 {
		a.TCPConnectMS = median(a.tcp)
	}
	if len(a.tls) > 0 {
		a.TLSHandshakeMS = median(a.tls)
	}
	if len(a.total) > 0 {
		a.ServerToSNIMS = median(a.total)
		a.ServerP95MS = percentile(a.total, 0.95)
		a.JitterMS = a.ServerP95MS - a.ServerToSNIMS
	} else {
		a.ServerToSNIMS = a.TCPConnectMS + a.TLSHandshakeMS
	}
	a.LatencyMS = a.ServerToSNIMS
	if mandatoryReady(a.CandidateResult) && a.Stability >= 1 {
		a.Status = "READY"
	} else {
		a.Status = "NOT_READY"
	}
	return a.CandidateResult
}

func assignRankingScores(results []CandidateResult) {
	if len(results) == 0 {
		return
	}
	minLatency, minJitter, minH3 := 0.0, 0.0, 0.0
	for _, r := range results {
		if r.ServerToSNIMS > 0 && (minLatency == 0 || r.ServerToSNIMS < minLatency) {
			minLatency = r.ServerToSNIMS
		}
		if r.JitterMS > 0 && (minJitter == 0 || r.JitterMS < minJitter) {
			minJitter = r.JitterMS
		}
		if r.HTTP3HandshakeMS > 0 && (minH3 == 0 || r.HTTP3HandshakeMS < minH3) {
			minH3 = r.HTTP3HandshakeMS
		}
	}
	for i := range results {
		r := &results[i]
		lat := ratioScore(r.ServerToSNIMS, minLatency)
		jit := 100.0
		if minJitter > 0 && r.JitterMS > 0 {
			jit = ratioScore(r.JitterMS, minJitter)
		}
		h3 := ratioScore(r.HTTP3HandshakeMS, minH3)
		r.EvidenceScore = 100
		if !r.HTTP3Advertised || r.HTTP3 == nil || !*r.HTTP3 {
			r.EvidenceScore = 70
		}
		r.RankingScore = lat*0.60 + jit*0.25 + h3*0.15
		r.Confidence = "HIGH"
	}
}

func ratioScore(value, best float64) float64 {
	if value <= 0 || best <= 0 {
		return 0
	}
	score := 100 * best / value
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func better(a, b CandidateResult) bool {
	if a.RankingScore != b.RankingScore {
		return a.RankingScore > b.RankingScore
	}
	if a.ServerToSNIMS != b.ServerToSNIMS {
		if a.ServerToSNIMS == 0 {
			return false
		}
		if b.ServerToSNIMS == 0 {
			return true
		}
		return a.ServerToSNIMS < b.ServerToSNIMS
	}
	if a.JitterMS != b.JitterMS {
		return a.JitterMS < b.JitterMS
	}
	if a.Stability != b.Stability {
		return a.Stability > b.Stability
	}
	return a.SNI < b.SNI
}

func percentile(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	if q <= 0 {
		return v[0]
	}
	if q >= 1 {
		return v[len(v)-1]
	}
	idx := int(math.Ceil(q*float64(len(v)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(v) {
		idx = len(v) - 1
	}
	return v[idx]
}


func filterIPv4(in []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(in))
	for _, x := range in {
		if x.IP.To4() != nil {
			out = append(out, x)
		}
	}
	return out
}

func probeWeb(ctx context.Context, origin string, ip net.IP, sni string, timeout time.Duration) webEvidence {
	out := webEvidence{IP: ip}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if ip == nil || sni == "" {
		return out
	}

	connPort := "443"
	tr := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			ServerName: sni,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	tr.DialContext = func(c context.Context, _, _ string) (net.Conn, error) {
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(c, "tcp", net.JoinHostPort(ip.String(), connPort))
		if err == nil {
			out.TCPMS = float64(time.Since(start).Microseconds()) / 1000
		}
		return conn, err
	}
	client := &http.Client{Transport: tr, Timeout: timeout + 500*time.Millisecond, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, (&url.URL{Scheme: "https", Host: net.JoinHostPort(sni, "443"), Path: "/"}).String(), nil)
	if err != nil {
		return out
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("X-Pikify-Probe", "1")
	resp, err := client.Do(req)
	if err != nil {
		tr.CloseIdleConnections()
		return out
	}
	defer resp.Body.Close()
	tr.CloseIdleConnections()
	out.HTTPStatus = resp.StatusCode
	out.HTTPProtocol = resp.Proto
	if resp.TLS != nil {
		out.TLS13 = resp.TLS.Version == tls.VersionTLS13
		out.H2 = resp.TLS.NegotiatedProtocol == "h2"
		out.ALPN = resp.TLS.NegotiatedProtocol
		if len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			out.CertValid = verifyCert(leaf, resp.TLS.PeerCertificates[1:], sni)
			out.SNIAccepted = out.CertValid
			out.CertSubject = leaf.Subject.String()
			out.CertIssuer = leaf.Issuer.String()
			out.CertExpires = leaf.NotAfter.UTC().Format(time.RFC3339)
			out.CertSANs = append([]string(nil), leaf.DNSNames...)
		}
	}
	alt := strings.ToLower(resp.Header.Get("Alt-Svc"))
	out.H3Advertised = hasH3Advertisement(alt)
	out.OK = out.TLS13 && out.H2 && out.CertValid
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		out.Redirects = 1
		out.RedirectTarget = resp.Header.Get("Location")
	}
	return out
}

func hasH3Advertisement(alt string) bool {
	for _, part := range strings.Split(alt, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(part, "=", 2)[0])
		if key == "h3" || strings.HasPrefix(key, "h3-") {
			return true
		}
	}
	return false
}

type http3Evidence struct {
	Success   bool
	ElapsedMS float64
	HTTPStatus int
	Protocol string
}

func probeHTTP3(ctx context.Context, origin string, ip net.IP, sni string, timeout time.Duration) http3Evidence {
	out := http3Evidence{}
	if ip == nil || sni == "" {
		return out
	}
	localCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return out
	}
	defer udpConn.Close()

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: sni,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"h3"},
		},
		Dial: func(dctx context.Context, _ string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
			cfg := tlsCfg.Clone()
			cfg.ServerName = sni
			cfg.NextProtos = []string{"h3"}
			remote := &net.UDPAddr{IP: ip.To4(), Port: 443}
			return quic.Dial(dctx, udpConn, remote, cfg, quicCfg)
		},
	}
	defer transport.Close()

	req, err := http.NewRequestWithContext(localCtx, http.MethodGet, (&url.URL{
		Scheme: "https",
		Host: net.JoinHostPort(sni, "443"),
		Path: "/",
	}).String(), nil)
	if err != nil {
		return out
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("X-Pikify-Probe", "1")
	start := time.Now()
	resp, err := transport.RoundTrip(req)
	out.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	out.HTTPStatus = resp.StatusCode
	out.Protocol = resp.Proto
	out.Success = resp.ProtoMajor == 3
	return out
}

func tlsProbe(ctx context.Context, origin string, ip net.IP, port int, sni string, timeout time.Duration) tlsObservation {
	out := tlsObservation{IP: ip}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.TCPMS = float64(time.Since(start).Microseconds()) / 1000
	tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	start = time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		out.Error = err.Error()
		return out
	}
	out.TLSMS = float64(time.Since(start).Microseconds()) / 1000
	state := tlsConn.ConnectionState()
	out.TLS13 = state.Version == tls.VersionTLS13
	out.H2 = state.NegotiatedProtocol == "h2"
	out.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		out.CertValid = verifyCert(leaf, state.PeerCertificates[1:], sni)
		out.SNIAccepted = out.CertValid
		out.CertSubject = leaf.Subject.String()
		out.CertIssuer = leaf.Issuer.String()
		out.CertExpires = leaf.NotAfter.UTC().Format(time.RFC3339)
		out.CertSANs = append([]string(nil), leaf.DNSNames...)
	}
	out.OK = out.TLS13 && out.CertValid
	_ = tlsConn.Close()
	return out
}

func probeCurve(ctx context.Context, origin string, ip net.IP, port int, sni string, timeout time.Duration, curve tls.CurveID) bool {
	if ip == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{curve}, NextProtos: []string{"h2", "http/1.1"}})
	return tc.HandshakeContext(ctx) == nil
}

func verifyCert(leaf *x509.Certificate, intermediates []*x509.Certificate, name string) bool {
	if leaf == nil || name == "" {
		return false
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return false
	}
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err == nil
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[(len(v)-1)/2]
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func boolPtr(v bool) *bool { return &v }
