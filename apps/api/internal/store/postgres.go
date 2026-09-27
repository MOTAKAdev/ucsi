package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pikify.local/pikify-engine/api/internal/domain"
)

type Store struct{ DB *pgxpool.Pool }

func New(ctx context.Context, url string) (*Store, error) {
	db, e := pgxpool.New(ctx, url)
	if e != nil {
		return nil, e
	}
	if e = db.Ping(ctx); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{DB: db}, nil
}
func (s *Store) Close() { s.DB.Close() }
func id(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
func (s *Store) CreateScan(ctx context.Context, in domain.ScanInput) (string, error) {
	scanID := id("scan-")
	b, _ := json.Marshal(in)
	if _, e := s.DB.Exec(ctx, `insert into scans(id,input,mode,profile,top_n,sample_count,status) values($1,$2,$3,$4,$5,$6,'PENDING')`, scanID, b, in.Mode, in.Profile, in.TopN, in.SampleCount); e != nil {
		return "", e
	}
	_, e := s.DB.Exec(ctx, `insert into scan_jobs(id,scan_id,job_type,status) values($1,$2,'DISCOVERY','PENDING')`, id("job-"), scanID)
	return scanID, e
}
func (s *Store) GetScan(ctx context.Context, id string) (map[string]any, error) {
	var input []byte
	var status string
	var created, timeDone *time.Time
	e := s.DB.QueryRow(ctx, `select input,status,created_at,completed_at from scans where id=$1`, id).Scan(&input, &status, &created, &timeDone)
	if e != nil {
		return nil, e
	}
	var in any
	_ = json.Unmarshal(input, &in)
	return map[string]any{"id": id, "input": in, "status": status, "created_at": created, "completed_at": timeDone}, nil
}
func (s *Store) ClaimJob(ctx context.Context) (string, string, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", "", e
	}
	defer tx.Rollback(ctx)
	var id, scan string
	e = tx.QueryRow(ctx, `select id,scan_id from scan_jobs where status='PENDING' order by created_at for update skip locked limit 1`).Scan(&id, &scan)
	if e != nil {
		return "", "", e
	}
	workerID := os.Getenv("HOSTNAME")
	if workerID == "" {
		workerID = "worker-local"
	}
	if _, e = tx.Exec(ctx, `update scan_jobs set status='RUNNING',attempt=attempt+1,started_at=now(),worker_id=$2 where id=$1`, id, workerID); e != nil {
		return "", "", e
	}
	if e = tx.Commit(ctx); e != nil {
		return "", "", e
	}
	return id, scan, nil
}
func (s *Store) UpsertCandidate(ctx context.Context, c domain.Candidate) error {
	_, e := s.DB.Exec(ctx, `insert into candidates(id,hostname,original_name,source,first_seen,last_seen) values($1,$2,$3,$4,$5,$6) on conflict(hostname) do update set last_seen=excluded.last_seen`, c.ID, c.Hostname, c.OriginalName, c.Source, c.FirstSeen, c.LastSeen)
	return e
}
func (s *Store) AddHTTPObservation(ctx context.Context, candidateID string, measuredAt time.Time, statusCode int, protocol, serverHeader, location string, redirects int, responseMS float64, contentLength int64, contentType string, hsts bool, errorCode string) error {
	_, e := s.DB.Exec(ctx, `insert into http_observations(id,candidate_id,measured_at,status_code,protocol,server_header,redirect_location,redirect_count,response_ms,content_length,content_type,hsts,error_code) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id("http-"), candidateID, measuredAt, statusCode, protocol, serverHeader, location, redirects, responseMS, contentLength, contentType, hsts, errorCode)
	return e
}
func (s *Store) SaveLatencyMeasurement(ctx context.Context, candidateID, origin string, sampleCount, successful, failed int, minMS, medianMS, meanMS, p95MS, jitterMS, packetLoss, tcpMS, tlsMS, totalMS float64, measuredAt time.Time) error {
	_, e := s.DB.Exec(ctx, `insert into latency_measurements(id,candidate_id,origin,sample_count,successful_samples,failed_samples,min_rtt_ms,median_rtt_ms,mean_rtt_ms,p95_rtt_ms,jitter_ms,packet_loss,tcp_connect_ms,tls_handshake_ms,total_request_ms,measured_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, id("lat-"), candidateID, origin, sampleCount, successful, failed, nullableFloat(minMS), nullableFloat(medianMS), nullableFloat(meanMS), nullableFloat(p95MS), nullableFloat(jitterMS), nullableFloat(packetLoss), nullableFloat(tcpMS), nullableFloat(tlsMS), nullableFloat(totalMS), measuredAt)
	return e
}
func nullableFloat(v float64) any {
	if v <= 0 {
		return nil
	}
	return v
}
func (s *Store) AddObservation(ctx context.Context, o domain.Observation) error {
	_, e := s.DB.Exec(ctx, `insert into tcp_tls_observations(id,candidate_id,origin,probe_id,measured_at,resolved_ip,address_family,dns_status,tcp_result,tcp_connect_ms,tls_result,tls_handshake_ms,total_connection_ms,tls_version,cipher,alpn,sni_accepted,cert_hostname_valid,cert_chain_valid,cert_fingerprint,cert_issuer,cert_subject,error_code,extra) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`, id("obs-"), o.CandidateID, o.Origin, o.ProbeID, o.MeasuredAt, o.ResolvedIP, o.AddressFamily, o.DNSStatus, o.TCPResult, o.TCPConnectMS, o.TLSResult, o.TLSHandshakeMS, o.TotalConnectionMS, o.TLSVersion, o.Cipher, o.ALPN, o.SNIAccepted, o.CertHostnameValid, o.CertChainValid, o.CertFingerprint, o.CertIssuer, o.CertSubject, o.ErrorCode, `{}`)
	return e
}
func (s *Store) SaveResult(ctx context.Context, scanID string, r domain.Result) error {
	ex, _ := json.Marshal(r.Explanation)
	_, e := s.DB.Exec(ctx, `insert into score_snapshots(id,scan_id,candidate_id,final_score,confidence,explanation,score_version,generated_at) values($1,$2,$3,$4,$5,$6,'v1',now())`, id("score-"), scanID, r.CandidateID, r.Score, r.Confidence, ex)
	if e != nil {
		return e
	}
	_, e = s.DB.Exec(ctx, `insert into scan_results(scan_id,candidate_id,rank,sni,target,median_rtt_ms,p95_rtt_ms,stability,score,confidence,freshness,tls,alpn,ipv4,ipv6,explanation,last_checked) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) on conflict(scan_id,candidate_id) do update set rank=excluded.rank,sni=excluded.sni,target=excluded.target,median_rtt_ms=excluded.median_rtt_ms,p95_rtt_ms=excluded.p95_rtt_ms,stability=excluded.stability,score=excluded.score,confidence=excluded.confidence,freshness=excluded.freshness,tls=excluded.tls,alpn=excluded.alpn,ipv4=excluded.ipv4,ipv6=excluded.ipv6,explanation=excluded.explanation,last_checked=excluded.last_checked`, scanID, r.CandidateID, r.Rank, r.SNI, r.Target, r.MedianRTTMS, r.P95RTTMS, r.Stability, r.Score, r.Confidence, r.Freshness, r.TLS, r.ALPN, r.IPv4, r.IPv6, ex, r.LastChecked)
	return e
}
func (s *Store) ListResults(ctx context.Context, scanID string, limit int) ([]domain.Result, error) {
	if limit < 1 {
		limit = 20
	}
	rows, e := s.DB.Query(ctx, `select rank,candidate_id,sni,target,median_rtt_ms,p95_rtt_ms,stability,score,confidence,freshness,tls,alpn,ipv4,ipv6,explanation,last_checked from scan_results where scan_id=$1 order by rank limit $2`, scanID, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []domain.Result
	for rows.Next() {
		var r domain.Result
		var ex []byte
		if e = rows.Scan(&r.Rank, &r.CandidateID, &r.SNI, &r.Target, &r.MedianRTTMS, &r.P95RTTMS, &r.Stability, &r.Score, &r.Confidence, &r.Freshness, &r.TLS, &r.ALPN, &r.IPv4, &r.IPv6, &ex, &r.LastChecked); e != nil {
			return nil, e
		}
		_ = json.Unmarshal(ex, &r.Explanation)
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) CompleteJob(ctx context.Context, jobID string, ok bool, errText string) {
	status := "SUCCEEDED"
	if !ok {
		status = "FAILED"
	}
	_, _ = s.DB.Exec(ctx, `update scan_jobs set status=$2,completed_at=now(),error_message=$3 where id=$1`, jobID, status, errText)
}
func (s *Store) MarkScan(ctx context.Context, id, status string) {
	_, _ = s.DB.Exec(ctx, `update scans set status=$2,completed_at=case when $2 in ('SUCCEEDED','FAILED','CANCELLED') then now() else completed_at end where id=$1`, id, status)
}

func (s *Store) StartStage(ctx context.Context, scanID, stage string, candidateCount int) (string, error) {
	stageID := id("stage-")
	_, err := s.DB.Exec(ctx, `insert into scan_stage_runs(id,scan_id,stage,started_at,candidate_count,status) values($1,$2,$3,now(),$4,'RUNNING')`, stageID, scanID, stage, candidateCount)
	return stageID, err
}

func (s *Store) CompleteStage(ctx context.Context, stageID, status string, successCount, failureCount int) error {
	_, err := s.DB.Exec(ctx, `update scan_stage_runs set completed_at=now(),duration_ms=extract(epoch from (now()-started_at))*1000,status=$2,success_count=$3,failure_count=$4 where id=$1`, stageID, status, successCount, failureCount)
	return err
}

func (s *Store) CancelScan(ctx context.Context, scanID string) error {
	_, err := s.DB.Exec(ctx, `update scan_jobs set status='CANCELLED',completed_at=now() where scan_id=$1 and status in ('PENDING','RUNNING')`, scanID)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `update scans set status='CANCELLED',completed_at=now() where id=$1 and status not in ('SUCCEEDED','FAILED','CANCELLED')`, scanID)
	return err
}

func (s *Store) SaveRealityTest(ctx context.Context, candidateID, status, xrayVersion, transport, handshakeResult, failureReason string, evidence any) error {
	b, _ := json.Marshal(evidence)
	_, err := s.DB.Exec(ctx, `insert into reality_tests(id,candidate_id,status,xray_version,transport,handshake_result,failure_reason,evidence,tested_at) values($1,$2,$3,$4,$5,$6,$7,$8,now())`, id("reality-"), candidateID, status, xrayVersion, transport, handshakeResult, failureReason, b)
	return err
}

func (s *Store) AddAudit(ctx context.Context, actor, action, requestID, scanID string, payload any) error {
	b, _ := json.Marshal(payload)
	_, err := s.DB.Exec(ctx, `insert into audit_logs(id,actor,action,request_id,scan_id,payload) values($1,$2,$3,$4,$5,$6)`, id("audit-"), actor, action, requestID, scanID, b)
	return err
}

func (s *Store) GetCandidateHistory(ctx context.Context, candidateID string) (map[string]any, error) {
	out := map[string]any{}

	var hostname, originalName, source string
	var firstSeen, lastSeen time.Time

	err := s.DB.QueryRow(ctx, `
        select hostname, original_name, source, first_seen, last_seen
        from candidates
        where id=$1
    `, candidateID).Scan(&hostname, &originalName, &source, &firstSeen, &lastSeen)
	if err != nil {
		return nil, err
	}

	out["candidate"] = map[string]any{
		"id":            candidateID,
		"hostname":      hostname,
		"original_name": originalName,
		"source":        source,
		"first_seen":    firstSeen,
		"last_seen":     lastSeen,
	}

	windows := []struct {
		name     string
		interval string
	}{
		{"5m", "5 minutes"},
		{"1h", "1 hour"},
		{"6h", "6 hours"},
		{"24h", "24 hours"},
		{"7d", "7 days"},
		{"30d", "30 days"},
	}

	buckets := make([]map[string]any, 0, len(windows))

	for _, w := range windows {
		var total, success, failed, timeout int
		var median, p95, mean float64

		err := s.DB.QueryRow(ctx, `
            with recent as (
                select tcp_result, error_code, tcp_connect_ms
                from tcp_tls_observations
                where candidate_id=$1
                  and measured_at >= now() - $2::interval
            ),
            latency as (
                select tcp_connect_ms
                from recent
                where tcp_result='SUCCESS'
                  and tcp_connect_ms > 0
            )
            select
                (select count(*) from recent)::int,
                (select count(*) from recent where tcp_result='SUCCESS')::int,
                (select count(*) from recent where tcp_result<>'SUCCESS')::int,
                (select count(*) from recent where error_code='TCP_TIMEOUT')::int,
                coalesce((select percentile_cont(0.50) within group (order by tcp_connect_ms) from latency),0),
                coalesce((select percentile_cont(0.95) within group (order by tcp_connect_ms) from latency),0),
                coalesce((select avg(tcp_connect_ms) from latency),0)
        `, candidateID, w.interval).Scan(
			&total, &success, &failed, &timeout,
			&median, &p95, &mean,
		)
		if err != nil {
			return nil, err
		}

		rate := 0.0
		if total > 0 {
			rate = float64(success) / float64(total)
		}

		buckets = append(buckets, map[string]any{
			"window":        w.name,
			"observations":  total,
			"success":       success,
			"failed":        failed,
			"timeouts":      timeout,
			"success_rate":  rate,
			"median_tcp_ms": median,
			"p95_tcp_ms":    p95,
			"mean_tcp_ms":   mean,
		})
	}

	out["time_buckets"] = buckets

	var currentRate, previousRate float64
	var currentCount, previousCount int

	_ = s.DB.QueryRow(ctx, `
        select
            count(*)::int,
            coalesce(avg(case when tcp_result='SUCCESS' then 1.0 else 0.0 end),0)
        from tcp_tls_observations
        where candidate_id=$1
          and measured_at >= now() - interval '1 hour'
    `, candidateID).Scan(&currentCount, &currentRate)

	_ = s.DB.QueryRow(ctx, `
        select
            count(*)::int,
            coalesce(avg(case when tcp_result='SUCCESS' then 1.0 else 0.0 end),0)
        from tcp_tls_observations
        where candidate_id=$1
          and measured_at >= now() - interval '2 hours'
          and measured_at < now() - interval '1 hour'
    `, candidateID).Scan(&previousCount, &previousRate)

	state := "NEW"

	if currentCount > 0 && previousCount > 0 {
		switch {
		case currentRate+0.20 < previousRate:
			state = "DEGRADED"
		case currentRate >= previousRate+0.20:
			state = "RECOVERED"
		default:
			state = "STABLE"
		}
	}

	out["state"] = state
	out["current_hour_success_rate"] = currentRate
	out["previous_hour_success_rate"] = previousRate

	scoreRows, err := s.DB.Query(ctx, `
        select scan_id, final_score, confidence, score_version, generated_at, explanation
        from score_snapshots
        where candidate_id=$1
        order by generated_at desc
        limit 50
    `, candidateID)
	if err != nil {
		return nil, err
	}
	defer scoreRows.Close()

	scores := make([]map[string]any, 0)
	for scoreRows.Next() {
		var scanID, confidence, version string
		var finalScore float64
		var generatedAt time.Time
		var explanation []byte

		if err := scoreRows.Scan(
			&scanID,
			&finalScore,
			&confidence,
			&version,
			&generatedAt,
			&explanation,
		); err != nil {
			return nil, err
		}

		var ex any
		_ = json.Unmarshal(explanation, &ex)

		scores = append(scores, map[string]any{
			"scan_id":       scanID,
			"final_score":   finalScore,
			"confidence":    confidence,
			"score_version": version,
			"generated_at":  generatedAt,
			"explanation":   ex,
		})
	}

	out["score_history"] = scores

	changeRows, err := s.DB.Query(ctx, `
        select type, previous, current, observed_at
        from change_events
        where candidate_id=$1
        order by observed_at desc
        limit 50
    `, candidateID)
	if err != nil {
		return nil, err
	}
	defer changeRows.Close()

	changes := make([]map[string]any, 0)
	for changeRows.Next() {
		var typ string
		var previous, current []byte
		var observedAt time.Time

		if err := changeRows.Scan(&typ, &previous, &current, &observedAt); err != nil {
			return nil, err
		}

		var prevAny, currentAny any
		_ = json.Unmarshal(previous, &prevAny)
		_ = json.Unmarshal(current, &currentAny)

		changes = append(changes, map[string]any{
			"type":        typ,
			"previous":    prevAny,
			"current":     currentAny,
			"observed_at": observedAt,
		})
	}

	out["change_events"] = changes

	return out, nil
}

func (s *Store) ListProbes(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.DB.Query(ctx, `select id,status,last_seen,version,capabilities,country,city,asn,provider from probes order by last_seen desc nulls last limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, status string
		var lastSeen *time.Time
		var version, country, city, asn, provider *string
		var caps []byte
		if err := rows.Scan(&id, &status, &lastSeen, &version, &caps, &country, &city, &asn, &provider); err != nil {
			return nil, err
		}
		var capabilities any
		_ = json.Unmarshal(caps, &capabilities)
		out = append(out, map[string]any{"id": id, "status": status, "last_seen": lastSeen, "version": version, "capabilities": capabilities, "country": country, "city": city, "asn": asn, "provider": provider})
	}
	return out, rows.Err()
}

func (s *Store) GetProbe(ctx context.Context, probeID string) (map[string]any, error) {
	var id, status string
	var lastSeen *time.Time
	var version, country, city, asn, provider *string
	var caps []byte
	err := s.DB.QueryRow(ctx, `select id,status,last_seen,version,capabilities,country,city,asn,provider from probes where id=$1`, probeID).Scan(&id, &status, &lastSeen, &version, &caps, &country, &city, &asn, &provider)
	if err != nil {
		return nil, err
	}
	var capabilities any
	_ = json.Unmarshal(caps, &capabilities)
	return map[string]any{"id": id, "status": status, "last_seen": lastSeen, "version": version, "capabilities": capabilities, "country": country, "city": city, "asn": asn, "provider": provider}, nil
}
