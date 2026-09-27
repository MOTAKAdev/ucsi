package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"pikify.local/pikify-engine/api/internal/domain"
	"pikify.local/pikify-engine/api/internal/originscan"
	"pikify.local/pikify-engine/api/internal/reality"
	"pikify.local/pikify-engine/api/internal/security"
	"pikify.local/pikify-engine/api/internal/store"
)


type Metrics struct {
	Requests uint64
	Errors   uint64
	Scans    uint64
}

type Server struct {
	Store         *store.Store
	Token         string
	MaxCandidates int
	Metrics       *Metrics
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/system/health", s.health)
	mux.HandleFunc("/api/v1/system/metrics", s.metrics)
	mux.HandleFunc("/api/v1/scans", s.scans)
	mux.HandleFunc("/api/v1/scans/", s.scanByID)
	mux.HandleFunc("/api/v1/results/top", s.top)
	mux.HandleFunc("/api/v1/candidates/validate", s.validate)
	mux.HandleFunc("/api/v1/candidates/", s.candidateByID)
	mux.HandleFunc("/api/v1/probes", s.probes)
	mux.HandleFunc("/api/v1/probes/", s.probeByID)
	mux.HandleFunc("/api/v1/sources/health", s.sourcesHealth)
	mux.HandleFunc("/api/v1/origin/scan", s.originScan)
	mux.HandleFunc("/api/v1/origin/manual", s.originManual)
	mux.HandleFunc("/api/v1/reality/scan", s.realityScan)
	return s.observe(s.cors(s.auth(mux)))
}

func (s *Server) observe(next http.Handler) http.Handler {
	m := s.Metrics
	if m == nil {
		m = &Metrics{}
		s.Metrics = m
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&m.Requests, 1)
		w.Header().Set("X-Request-ID", requestID(r))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	allowed := strings.FieldsFunc(os.Getenv("UCSI_CORS_ORIGINS"), func(r rune) bool { return r == ',' || r == ' ' })
	set := map[string]struct{}{}
	for _, v := range allowed {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := set[origin]; !ok {
				http.Error(w, `{"error":{"code":"CORS_ORIGIN_BLOCKED"}}`, http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/system/health" {
			next.ServeHTTP(w, r)
			return
		}
		if s.Token == "" {
			http.Error(w, `{"error":{"code":"SERVER_AUTH_MISCONFIGURED"}}`, 500)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if len(got) != len(s.Token) || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			http.Error(w, `{"error":{"code":"UNAUTHORIZED"}}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestID(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if v == "" {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	if len(v) > 128 {
		return v[:128]
	}
	return v
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, code string, status int, message string) {
	if message == "" {
		message = code
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func (s *Server) realityScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
		return
	}
	var req struct {
		Target  string  `json:"target"`
		Timeout float64 `json:"timeout,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, "INVALID_REQUEST", 400, "invalid request body")
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeError(w, "INVALID_TARGET", 400, "target is required")
		return
	}
	timeout := 10 * time.Second
	if req.Timeout > 0 {
		if req.Timeout < 1 {
			req.Timeout = 1
		}
		if req.Timeout > 20 {
			req.Timeout = 20
		}
		timeout = time.Duration(req.Timeout * float64(time.Second))
	}
	result, err := reality.Scan(r.Context(), target, timeout)
	if err != nil {
		writeError(w, "REALITY_SCAN_FAILED", 400, err.Error())
		return
	}
	writeJSON(w, result)
}

var realityScanSlots = make(chan struct{}, 2)

var originScanGate = make(chan struct{}, 1)

func (s *Server) originScan(w http.ResponseWriter, r *http.Request) {
	select {
	case originScanGate <- struct{}{}:
		defer func() { <-originScanGate }()
	default:
		writeError(w, "SCAN_BUSY", 429, "Another scan is already running. Please wait.")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
		return
	}
	var req struct {
		ServerIP string `json:"server_ip"`
		Samples  *int   `json:"samples"`
		TopN     *int   `json:"top_n"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
		writeError(w, "INVALID_REQUEST", 400, "invalid request body")
		return
	}
	if strings.TrimSpace(req.ServerIP) == "" {
		writeError(w, "INVALID_SERVER_IP", 400, "server_ip is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()

	samples, topN := 3, 3
	if req.Samples != nil {
		samples = *req.Samples
	}
	if req.TopN != nil {
		topN = *req.TopN
	}
	result, err := originscan.AutoScan(ctx, req.ServerIP, samples, topN, "")
	if err != nil {
		writeError(w, "ORIGIN_SCAN_FAILED", 400, err.Error())
		return
	}
	writeJSON(w, result)
}

func (s *Server) originManual(w http.ResponseWriter, r *http.Request) {
	select {
	case originScanGate <- struct{}{}:
		defer func() { <-originScanGate }()
	default:
		writeError(w, "SCAN_BUSY", 429, "Another scan is already running. Please wait.")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
		return
	}
	var req struct {
		ServerIP string `json:"server_ip"`
		SNI      string `json:"sni"`
		Target   string `json:"target"`
		Port     int    `json:"port"`
		Samples  *int   `json:"samples"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
		writeError(w, "INVALID_REQUEST", 400, "invalid request body")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	samples := 3
	if req.Samples != nil {
		samples = *req.Samples
	}
	result, err := originscan.ManualScan(ctx, req.ServerIP, req.SNI, req.Target, req.Port, samples)
	if err != nil {
		writeError(w, "MANUAL_SCAN_FAILED", 400, err.Error())
		return
	}
	writeJSON(w, result)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.DB.Ping(ctx); err != nil {
		writeError(w, "DB_UNAVAILABLE", 503, "database health check failed")
		return
	}
	writeJSON(w, map[string]any{"status": "healthy", "database": "healthy", "time": time.Now().UTC()})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	m := s.Metrics
	if m == nil {
		m = &Metrics{}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "ucsi_http_requests_total %d\n", atomic.LoadUint64(&m.Requests))
	fmt.Fprintf(w, "ucsi_http_errors_total %d\n", atomic.LoadUint64(&m.Errors))
	fmt.Fprintf(w, "ucsi_scans_created_total %d\n", atomic.LoadUint64(&m.Scans))
}

func (s *Server) scans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
		return
	}
	var in domain.ScanInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&in); err != nil {
		writeError(w, "INVALID_REQUEST", 400, "invalid request body")
		return
	}
	if in.Mode != domain.ModeTLS && in.Mode != domain.ModeREALITY {
		writeError(w, "INVALID_MODE", 400, "mode must be TLS or REALITY")
		return
	}
	if in.Profile == "" {
		in.Profile = domain.Balanced
	}
	if in.Profile != domain.Fast && in.Profile != domain.Balanced && in.Profile != domain.Deep && in.Profile != domain.Custom {
		writeError(w, "INVALID_SCAN_PROFILE", 400, "profile must be FAST, BALANCED, DEEP or CUSTOM")
		return
	}
	if in.TopN < 1 {
		in.TopN = 20
	}
	if in.TopN > 100 {
		in.TopN = 100
	}
	if in.SampleCount < 1 {
		in.SampleCount = 3
	}
	if in.SampleCount > 20 {
		in.SampleCount = 20
	}
	if in.Server == "" {
		writeError(w, "INVALID_TARGET", 400, "server is required")
		return
	}
	ip := strings.TrimSpace(in.Server)
	if parsed := net.ParseIP(ip); parsed != nil {
		netIP, err := security.ValidateIPTarget(ip)
		if err != nil {
			writeError(w, "SSRF_BLOCKED", 400, err.Error())
			return
		}
		in.Server = netIP
	} else {
		h, err := security.NormalizeHostname(in.Server)
		if err != nil {
			writeError(w, "INVALID_TARGET", 400, err.Error())
			return
		}
		in.Server = h
	}

	id, err := s.Store.CreateScan(r.Context(), in)
	if err != nil {
		atomic.AddUint64(&s.Metrics.Errors, 1)
		writeError(w, "INTERNAL_ERROR", 500, "could not create scan")
		return
	}
	atomic.AddUint64(&s.Metrics.Scans, 1)
	_ = s.Store.AddAudit(r.Context(), "api", "scan.create", requestID(r), id, in)
	writeJSON(w, map[string]any{"id": id, "status": "PENDING"})
}

func (s *Server) scanByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := parts[0]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "results" {
		rows, err := s.Store.ListResults(r.Context(), id, 100)
		if err != nil {
			writeError(w, "INTERNAL_ERROR", 500, "could not read results")
			return
		}
		writeJSON(w, map[string]any{"scan_id": id, "results": rows})
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" {
		if r.Method != http.MethodPost {
			writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
			return
		}
		if err := s.Store.CancelScan(r.Context(), id); err != nil {
			writeError(w, "INTERNAL_ERROR", 500, "could not cancel scan")
			return
		}
		_ = s.Store.AddAudit(r.Context(), "api", "scan.cancel", requestID(r), id, nil)
		writeJSON(w, map[string]any{"id": id, "status": "CANCELLED"})
		return
	}
	v, err := s.Store.GetScan(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, v)
}

func (s *Server) top(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("scan_id"))
	if id == "" {
		writeError(w, "MISSING_SCAN_ID", 400, "scan_id is required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.Store.ListResults(r.Context(), id, limit)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", 500, "could not read results")
		return
	}
	writeJSON(w, rows)
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
		return
	}
	var req struct {
		Hostname string `json:"hostname"`
		Samples  int    `json:"samples"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, "INVALID_REQUEST", 400, "invalid request body")
		return
	}
	h, err := security.NormalizeHostname(req.Hostname)
	if err != nil {
		writeError(w, "INVALID_TARGET", 400, err.Error())
		return
	}
	if req.Samples < 1 {
		req.Samples = 1
	}
	if req.Samples > 20 {
		req.Samples = 20
	}
	in := domain.ScanInput{Server: h, Mode: domain.ModeTLS, Profile: domain.Fast, TopN: 1, SampleCount: req.Samples}
	id, err := s.Store.CreateScan(r.Context(), in)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", 500, "could not queue validation")
		return
	}
	_ = s.Store.AddAudit(r.Context(), "api", "candidate.validate", requestID(r), id, map[string]any{"hostname": h, "samples": req.Samples})
	writeJSON(w, map[string]any{"scan_id": id, "hostname": h, "state": "QUEUED"})
}

func (s *Server) candidateByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/candidates/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")

	if len(parts) != 2 || parts[1] != "history" {
		http.NotFound(w, r)
		return
	}

	candidateID := strings.TrimSpace(parts[0])
	if candidateID == "" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
		return
	}

	history, err := s.Store.GetCandidateHistory(r.Context(), candidateID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	writeJSON(w, history)
}

func (s *Server) probes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "METHOD_NOT_ALLOWED", 405, "method not allowed")
		return
	}
	rows, err := s.Store.ListProbes(r.Context(), 100)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", 500, "could not read probes")
		return
	}
	writeJSON(w, rows)
}
func (s *Server) probeByID(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/probes/"), "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	p, err := s.Store.GetProbe(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, p)
}
func (s *Server) sourcesHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"sources": []map[string]any{{"name": "user_seed", "status": "HEALTHY"}, {"name": "crtsh", "status": func() string {
		if os.Getenv("UCSI_CT_ENABLED") == "true" {
			return "ENABLED"
		}
		return "DISABLED"
	}()}}})
}
