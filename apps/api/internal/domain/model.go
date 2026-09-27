package domain

import "time"

type ScanMode string
type ScanProfile string

const (
	ModeTLS     ScanMode    = "TLS"
	ModeREALITY ScanMode    = "REALITY"
	Fast        ScanProfile = "FAST"
	Balanced    ScanProfile = "BALANCED"
	Deep        ScanProfile = "DEEP"
	Custom      ScanProfile = "CUSTOM"
)

type CustomScanConfig struct {
	ValidationRounds int  `json:"validation_rounds,omitempty"`
	DNSEnabled       bool `json:"dns_enabled"`
	TCPEnabled       bool `json:"tcp_enabled"`
	TLSEnabled       bool `json:"tls_enabled"`
	SNIEnabled       bool `json:"sni_enabled"`
	HTTPEnabled      bool `json:"http_enabled"`
	HTTPRuns         int  `json:"http_runs,omitempty"`
	LatencyEnabled   bool `json:"latency_enabled"`
	ScoringEnabled   bool `json:"scoring_enabled"`
	RankingEnabled   bool `json:"ranking_enabled"`
}

type ScanInput struct {
	Server      string            `json:"server"`
	Country     string            `json:"country,omitempty"`
	City        string            `json:"city,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	ASN         string            `json:"asn,omitempty"`
	Datacenter  string            `json:"datacenter,omitempty"`
	Mode        ScanMode          `json:"mode"`
	Profile     ScanProfile       `json:"profile"`
	TopN        int               `json:"top_n"`
	SampleCount int               `json:"sample_count"`
	Custom      *CustomScanConfig `json:"custom,omitempty"`
}

type Candidate struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	OriginalName string    `json:"original_name"`
	Source       string    `json:"source"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

type Observation struct {
	CandidateID       string    `json:"candidate_id"`
	Origin            string    `json:"origin"`
	ProbeID           string    `json:"probe_id,omitempty"`
	MeasuredAt        time.Time `json:"measured_at"`
	ResolvedIP        string    `json:"resolved_ip,omitempty"`
	AddressFamily     string    `json:"address_family,omitempty"`
	DNSStatus         string    `json:"dns_status,omitempty"`
	TCPResult         string    `json:"tcp_result,omitempty"`
	TCPConnectMS      float64   `json:"tcp_connect_ms,omitempty"`
	TLSResult         string    `json:"tls_result,omitempty"`
	TLSHandshakeMS    float64   `json:"tls_handshake_ms,omitempty"`
	TotalConnectionMS float64   `json:"total_connection_ms,omitempty"`
	TLSVersion        string    `json:"tls_version,omitempty"`
	Cipher            string    `json:"cipher,omitempty"`
	ALPN              string    `json:"alpn,omitempty"`
	SNIAccepted       bool      `json:"sni_accepted"`
	CertHostnameValid bool      `json:"cert_hostname_valid"`
	CertChainValid    bool      `json:"cert_chain_valid"`
	CertFingerprint   string    `json:"cert_fingerprint,omitempty"`
	CertIssuer        string    `json:"cert_issuer,omitempty"`
	CertSubject       string    `json:"cert_subject,omitempty"`
	HTTPStatus        int       `json:"http_status,omitempty"`
	HTTPProtocol      string    `json:"http_protocol,omitempty"`
	HTTPTimeMS        float64   `json:"http_time_ms,omitempty"`
	ErrorCode         string    `json:"error_code,omitempty"`
}

type Result struct {
	Rank        int       `json:"rank"`
	CandidateID string    `json:"candidate_id"`
	SNI         string    `json:"sni"`
	Target      string    `json:"target"`
	MedianRTTMS float64   `json:"median_rtt_ms"`
	P95RTTMS    float64   `json:"p95_rtt_ms"`
	Stability   float64   `json:"stability"`
	Score       float64   `json:"score"`
	Confidence  string    `json:"confidence"`
	Freshness   float64   `json:"freshness"`
	TLS         string    `json:"tls"`
	ALPN        string    `json:"alpn"`
	IPv4        string    `json:"ipv4"`
	IPv6        string    `json:"ipv6"`
	Explanation []string  `json:"explanation"`
	LastChecked time.Time `json:"last_checked"`
}
