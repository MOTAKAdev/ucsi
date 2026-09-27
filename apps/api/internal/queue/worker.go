package queue

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"pikify.local/pikify-engine/api/internal/discovery"
	"pikify.local/pikify-engine/api/internal/domain"
	"pikify.local/pikify-engine/api/internal/measurement"
	"pikify.local/pikify-engine/api/internal/scoring"
	"pikify.local/pikify-engine/api/internal/security"
	"pikify.local/pikify-engine/api/internal/store"
)

func RunWorker(ctx context.Context, s *store.Store) {
	max := envInt("UCSI_MAX_CANDIDATES_PER_SCAN", 200)
	defaultSamples := envInt("UCSI_DEFAULT_SAMPLE_COUNT", 3)
	ctEnabled := os.Getenv("UCSI_CT_ENABLED") == "true"
	ct := discovery.CRTShSource{Endpoint: os.Getenv("UCSI_CT_ENDPOINT")}
	for ctx.Err() == nil {
		job, scan, err := s.ClaimJob(ctx)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if status, e := s.GetScan(ctx, scan); e != nil || status["status"] == "CANCELLED" {
			s.CompleteJob(ctx, job, false, "scan cancelled or unavailable")
			continue
		}
		s.MarkScan(ctx, scan, "RUNNING")
		err = process(ctx, s, scan, job, max, defaultSamples, ctEnabled, ct)
		if err != nil {
			slog.Error("scan failed", "scan_id", scan, "error", err)
			s.CompleteJob(ctx, job, false, err.Error())
			s.MarkScan(ctx, scan, "FAILED")
			continue
		}
		s.CompleteJob(ctx, job, true, "")
		s.MarkScan(ctx, scan, "SUCCEEDED")
	}
}

func process(ctx context.Context, s *store.Store, scan, job string, max, samples int, ctEnabled bool, ct discovery.CRTShSource) error {
	v, err := s.GetScan(ctx, scan)
	if err != nil {
		return err
	}
	raw, ok := v["input"].(map[string]any)
	if !ok {
		return errors.New("invalid scan input")
	}
	server, _ := raw["server"].(string)
	if x, ok := raw["sample_count"].(float64); ok && x > 0 {
		samples = int(x)
	}
	if samples < 1 {
		samples = 3
	}
	if samples > 20 {
		samples = 20
	}
	profile := domain.ScanProfile("BALANCED")
	if p, ok := raw["profile"].(string); ok && p != "" {
		profile = domain.ScanProfile(p)
	}

	validationRounds := 1
	httpRuns := 0

	dnsEnabled := true
	httpEnabled := true
	tcpEnabled := true
	tlsEnabled := true
	sniEnabled := true
	latencyEnabled := true
	scoringEnabled := true
	rankingEnabled := true

	switch profile {
	case domain.Fast:
		validationRounds = 1
		httpRuns = 0

	case domain.Balanced:
		validationRounds = 1
		httpRuns = 1

	case domain.Deep:
		validationRounds = 2
		httpRuns = 2

	case domain.Custom:
		validationRounds = 1
		httpRuns = 1

		if cfg, ok := raw["custom"].(map[string]any); ok {
			if v, ok := cfg["validation_rounds"].(float64); ok {
				validationRounds = int(v)
			}

			dnsEnabled = customBool(cfg, "dns_enabled", true)
			httpEnabled = customBool(cfg, "http_enabled", true)
			tcpEnabled = customBool(cfg, "tcp_enabled", true)
			tlsEnabled = customBool(cfg, "tls_enabled", true)
			sniEnabled = customBool(cfg, "sni_enabled", true)
			latencyEnabled = customBool(cfg, "latency_enabled", true)
			scoringEnabled = customBool(cfg, "scoring_enabled", true)
			rankingEnabled = customBool(cfg, "ranking_enabled", true)

			httpEnabled := customBool(cfg, "http_enabled", true)

			if !httpEnabled {
				httpRuns = 0
			} else {
				httpRuns = 1
				if v, ok := cfg["http_runs"].(float64); ok {
					httpRuns = int(v)
				}
			}
		}

		if validationRounds < 1 {
			validationRounds = 1
		}
		if validationRounds > 5 {
			validationRounds = 5
		}
		if httpRuns < 0 {
			httpRuns = 0
		}
		if httpRuns > 3 {
			httpRuns = 3
		}
	}

	// CUSTOM stage switches are independent.
	if !httpEnabled {
		httpRuns = 0
	} else if !tcpEnabled || !tlsEnabled {
		httpRuns = 0
	}
	if !scoringEnabled {
		rankingEnabled = false
	}

	stageID, err := s.StartStage(ctx, scan, "DISCOVERY", 0)
	if err != nil {
		return err
	}
	cands, err := seedCandidates(ctx, server)
	if err != nil {
		_ = s.CompleteStage(ctx, stageID, "FAILED", 0, 1)
		return err
	}
	if ctEnabled && net.ParseIP(server) == nil {
		extra, e2 := ct.Discover(ctx, server)
		if e2 != nil {
			slog.Warn("CT source degraded", "error", e2)
		} else {
			cands = mergeCandidates(cands, extra)
		}
	}
	if len(cands) > max {
		cands = cands[:max]
	}
	if err := s.CompleteStage(ctx, stageID, "SUCCEEDED", len(cands), 0); err != nil {
		return err
	}

	all := make([]scoredCandidate, 0, len(cands))
	for _, c := range cands {
		if err := s.UpsertCandidate(ctx, c); err != nil {
			return err
		}
		var obs []domain.Observation

		for round := 0; round < validationRounds; round++ {
			batch, e2 := measurement.ValidateWithOptions(
				ctx,
				c,
				samples,
				5*time.Second,
				measurement.ValidateOptions{
					DNSEnabled: dnsEnabled,
					TCPEnabled: tcpEnabled,
					TLSEnabled: tlsEnabled,
					SNIEnabled: sniEnabled,
				},
			)
			if e2 != nil {
				slog.Warn(
					"candidate validation failed",
					"hostname", c.Hostname,
					"round", round+1,
					"error", e2,
				)
				continue
			}
			obs = append(obs, batch...)
		}

		if len(obs) == 0 {
			continue
		}

		for run := 0; run < httpRuns; run++ {
			h, e := measurement.ValidateHTTP(
				ctx,
				c.Hostname,
				5*time.Second,
				int64(envInt("UCSI_HTTP_MAX_BODY_BYTES", 64*1024)),
				2,
			)

			if e != nil {
				slog.Warn(
					"HTTP evidence unavailable",
					"hostname", c.Hostname,
					"run", run+1,
					"error", e,
				)
				continue
			}

			measuredAt := time.Now().UTC()

			if err := s.AddHTTPObservation(
				ctx,
				c.ID,
				measuredAt,
				h.StatusCode,
				h.Protocol,
				h.Server,
				h.Location,
				h.Redirects,
				h.ResponseMS,
				h.ContentLength,
				h.ContentType,
				h.HSTS,
				"",
			); err != nil {
				return err
			}

			for i := range obs {
				if obs[i].TLSResult == "SUCCESS" {
					obs[i].HTTPStatus = h.StatusCode
					obs[i].HTTPProtocol = h.Protocol
					obs[i].HTTPTimeMS = h.ResponseMS
				}
			}
		}

		for _, o := range obs {
			if err := s.AddObservation(ctx, o); err != nil {
				return err
			}
		}
		if latencyEnabled {
			if err := persistLatencySummary(ctx, s, c.ID, obs); err != nil {
				return err
			}
		}
		// A user-visible TARGET requires live TLS evidence plus the requested hostname
		// being accepted by the certificate. DNS or TCP success alone is insufficient.
		sc := 0.0
		conf := "NOT_SCORED"
		reasons := []string{"scoring skipped by custom policy"}

		if scoringEnabled {
			sc, conf, reasons = scoring.ScoreWithOptions(
				obs,
				scoring.Default,
				time.Now().UTC(),
				scoring.ScoreOptions{
					Latency:      latencyEnabled,
					Stability:    tcpEnabled,
					TLS:          tlsEnabled,
					SNI:          sniEnabled,
					Reachability: tcpEnabled,
					Freshness:    true,
					Evidence:     true,
				},
			)
		}

		all = append(all, scoredCandidate{
			Candidate:  c,
			Obs:        obs,
			Score:      sc,
			Confidence: conf,
			Reasons:    reasons,
		})
	}
	if rankingEnabled {
		sort.SliceStable(all, func(i, j int) bool {
			if all[i].Score != all[j].Score {
				return all[i].Score > all[j].Score
			}
			return all[i].Candidate.Hostname < all[j].Candidate.Hostname
		})
	}
	top := 20
	if n, ok := raw["top_n"].(float64); ok && int(n) > 0 {
		top = int(n)
	}
	if top > len(all) {
		top = len(all)
	}
	for i := 0; i < top; i++ {
		if err := s.SaveResult(ctx, scan, makeResult(i+1, all[i])); err != nil {
			return err
		}
	}
	return nil
}

func customBool(cfg map[string]any, key string, def bool) bool {
	if v, ok := cfg[key].(bool); ok {
		return v
	}
	return def
}

func persistLatencySummary(ctx context.Context, s *store.Store, candidateID string, obs []domain.Observation) error {
	vals := make([]float64, 0, len(obs))
	var tcpVals, tlsVals, totalVals []float64
	successes := 0
	last := time.Time{}
	for _, o := range obs {
		if o.MeasuredAt.After(last) {
			last = o.MeasuredAt
		}
		if o.TCPResult == "SUCCESS" {
			successes++
			if o.TCPConnectMS > 0 {
				vals = append(vals, o.TCPConnectMS)
				tcpVals = append(tcpVals, o.TCPConnectMS)
			}
		}
		if o.TLSHandshakeMS > 0 {
			tlsVals = append(tlsVals, o.TLSHandshakeMS)
		}
		if o.TotalConnectionMS > 0 {
			totalVals = append(totalVals, o.TotalConnectionMS)
		}
	}
	sort.Float64s(vals)
	sort.Float64s(tcpVals)
	sort.Float64s(tlsVals)
	sort.Float64s(totalVals)
	if len(vals) == 0 {
		return s.SaveLatencyMeasurement(ctx, candidateID, "central_worker", len(obs), successes, len(obs)-successes, 0, 0, 0, 0, 0, 1, firstPositive(tcpVals), firstPositive(tlsVals), firstPositive(totalVals), last)
	}
	mean := 0.0
	for _, v := range vals {
		mean += v
	}
	mean /= float64(len(vals))
	jitter := 0.0
	if len(vals) > 1 {
		for i := 1; i < len(vals); i++ {
			jitter += abs(vals[i] - vals[i-1])
		}
		jitter /= float64(len(vals) - 1)
	}
	loss := float64(len(obs)-successes) / float64(len(obs))
	return s.SaveLatencyMeasurement(ctx, candidateID, "central_worker", len(obs), successes, len(obs)-successes, vals[0], percentile(vals, .50), mean, percentile(vals, .95), jitter, loss, medianFloat(tcpVals), medianFloat(tlsVals), medianFloat(totalVals), last)
}
func firstPositive(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[0]
}
func medianFloat(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return percentile(v, .50)
}
func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func validatedTLSObservation(obs []domain.Observation, requireSNI bool) bool {
	for _, o := range obs {
		if o.TCPResult != "SUCCESS" || o.TLSResult != "SUCCESS" {
			continue
		}
		if requireSNI && (!o.SNIAccepted || !o.CertHostnameValid) {
			continue
		}
		return true
	}
	return false
}

type scoredCandidate struct {
	Candidate  domain.Candidate
	Obs        []domain.Observation
	Score      float64
	Confidence string
	Reasons    []string
}

func seedCandidates(ctx context.Context, server string) ([]domain.Candidate, error) {
	if ip := net.ParseIP(server); ip != nil {
		if !security.IsPublicIP(ip.String()) {
			return nil, errors.New("target IP is not public")
		}
		names, e := net.DefaultResolver.LookupAddr(ctx, ip.String())
		if e != nil || len(names) == 0 {
			return nil, errors.New("IP target has no usable reverse-DNS hostname")
		}
		return (&discovery.SeedSource{}).Discover(ctx, names[0])
	}
	return (&discovery.SeedSource{}).Discover(ctx, server)
}

func mergeCandidates(a, b []domain.Candidate) []domain.Candidate {
	seen := map[string]bool{}
	out := make([]domain.Candidate, 0, len(a)+len(b))
	for _, c := range append(a, b...) {
		if !seen[c.Hostname] {
			seen[c.Hostname] = true
			out = append(out, c)
		}
	}
	return out
}
func makeResult(rank int, c scoredCandidate) domain.Result {
	var tcp []float64
	var ok4, ok6, seen4, seen6 int
	last := time.Time{}
	alpn, tlsv := "", ""

	for _, o := range c.Obs {
		switch o.AddressFamily {
		case "IPv4":
			seen4++
			if o.TCPResult == "SUCCESS" {
				ok4++
			}
		case "IPv6":
			seen6++
			if o.TCPResult == "SUCCESS" {
				ok6++
			}
		}

		if o.TCPResult == "SUCCESS" && o.TCPConnectMS > 0 {
			tcp = append(tcp, o.TCPConnectMS)
		}
		if o.ALPN != "" {
			alpn = o.ALPN
		}
		if o.TLSVersion != "" {
			tlsv = o.TLSVersion
		}
		if o.MeasuredAt.After(last) {
			last = o.MeasuredAt
		}
	}

	sort.Float64s(tcp)

	med, p95 := 0.0, 0.0
	if len(tcp) > 0 {
		med = percentile(tcp, .50)
		p95 = percentile(tcp, .95)
	}

	// Keep stability separate from reachability.
	// Stability is calculated from repeated outcome consistency.
	stability := scoring.Stability(c.Obs)

	age := time.Since(last).Hours() / 24
	if age < 0 {
		age = 0
	}
	fresh := 1.0 / (1.0 + age)

	return domain.Result{
		Rank:        rank,
		CandidateID: c.Candidate.ID,
		SNI:         c.Candidate.Hostname,
		Target:      c.Candidate.Hostname + ":443",
		MedianRTTMS: med,
		P95RTTMS:    p95,
		Stability:   stability,
		Score:       c.Score,
		Confidence:  c.Confidence,
		Freshness:   fresh,
		TLS:         tlsv,
		ALPN:        alpn,
		IPv4:        status(seen4 > 0, ok4 > 0),
		IPv6:        status(seen6 > 0, ok6 > 0),
		Explanation: append([]string{}, c.Reasons...),
		LastChecked: last,
	}
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	i := int(float64(len(v)-1) * p)
	return v[i]
}
func familyStatus(tested, available, healthy bool) string {
	if !tested {
		return "NOT_TESTED"
	}
	return status(available, healthy)
}

func status(available, healthy bool) string {
	if !available {
		return "NOT_OBSERVED"
	}
	if healthy {
		return "HEALTHY"
	}
	return "DEGRADED"
}
func envInt(k string, d int) int {
	v, _ := strconv.Atoi(os.Getenv(k))
	if v <= 0 {
		return d
	}
	return v
}
