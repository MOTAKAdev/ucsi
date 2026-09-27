package scoring

import (
	"fmt"
	"math"
	"sort"
	"time"

	"pikify.local/pikify-engine/api/internal/domain"
)

type Weights struct {
	Latency      float64
	Stability    float64
	TLS          float64
	SNI          float64
	Reachability float64
	Freshness    float64
	Evidence     float64
}

var Default = Weights{
	Latency:      .25,
	Stability:    .25,
	TLS:          .15,
	SNI:          .15,
	Reachability: .10,
	Freshness:    .05,
	Evidence:     .05,
}

type ScoreOptions struct {
	Latency      bool
	Stability    bool
	TLS          bool
	SNI          bool
	Reachability bool
	Freshness    bool
	Evidence     bool
}

func Score(obs []domain.Observation, w Weights, now time.Time) (float64, string, []string) {
	return ScoreWithOptions(obs, w, now, ScoreOptions{
		Latency:      true,
		Stability:    true,
		TLS:          true,
		SNI:          true,
		Reachability: true,
		Freshness:    true,
		Evidence:     true,
	})
}

func ScoreWithOptions(obs []domain.Observation, w Weights, now time.Time, opt ScoreOptions) (float64, string, []string) {
	if len(obs) == 0 {
		return 0, "UNKNOWN", []string{"no observations"}
	}

	var times []float64
	var tcpTested, tcpSuccess int
	tlsOK := false
	sniOK := false
	last := time.Time{}

	for _, o := range obs {
		if o.TCPResult == "SUCCESS" || o.TCPResult == "FAILED" {
			tcpTested++
			if o.TCPResult == "SUCCESS" {
				tcpSuccess++
			}
		}

		if o.TCPConnectMS > 0 {
			times = append(times, o.TCPConnectMS)
		}

		if o.TLSResult == "SUCCESS" {
			tlsOK = true
		}

		if o.SNIAccepted {
			sniOK = true
		}

		if o.MeasuredAt.After(last) {
			last = o.MeasuredAt
		}
	}

	sort.Float64s(times)

	var components []float64
	var weights []float64
	var names []string

	reasons := []string{
		"deterministic score from stored observations",
		fmt.Sprintf("observations=%d", len(obs)),
	}

	if opt.Reachability && tcpTested > 0 {
		reach := float64(tcpSuccess) / float64(tcpTested)
		components = append(components, reach)
		weights = append(weights, w.Reachability)
		names = append(names, "reachability")
		reasons = append(reasons,
			fmt.Sprintf("tcp_success=%d", tcpSuccess),
			fmt.Sprintf("tcp_failed=%d", tcpTested-tcpSuccess),
			fmt.Sprintf("reachability=%.1f%%", reach*100),
		)
	} else if opt.Reachability {
		reasons = append(reasons, "reachability=NOT_TESTED")
	}

	if opt.Latency && len(times) > 0 {
		latency := 100.0 / (100.0 + median(times))
		components = append(components, latency)
		weights = append(weights, w.Latency)
		names = append(names, "latency")
		reasons = append(reasons, fmt.Sprintf("latency_score=%.1f%%", latency*100))
	} else if opt.Latency {
		reasons = append(reasons, "latency_score=NOT_TESTED")
	}

	if opt.Stability && tcpTested > 0 {
		stability := Stability(obs)
		components = append(components, stability)
		weights = append(weights, w.Stability)
		names = append(names, "stability")
		reasons = append(reasons, fmt.Sprintf("stability=%.1f%%", stability*100))
	} else if opt.Stability {
		reasons = append(reasons, "stability=NOT_TESTED")
	}

	if opt.TLS {
		hasTLS := false
		for _, o := range obs {
			if o.TLSResult == "SUCCESS" || o.TLSResult == "FAILED" {
				hasTLS = true
				break
			}
		}
		if hasTLS {
			tlsScore := 0.0
			if tlsOK {
				tlsScore = 1
			}
			components = append(components, tlsScore)
			weights = append(weights, w.TLS)
			names = append(names, "tls")
			reasons = append(reasons, fmt.Sprintf("tls_score=%.1f%%", tlsScore*100))
			if tlsOK {
				reasons = append(reasons, "TLS handshake succeeded")
			}
		} else {
			reasons = append(reasons, "tls_score=NOT_TESTED")
		}
	}

	if opt.SNI {
		hasSNI := false
		for _, o := range obs {
			if o.SNIAccepted || o.CertHostnameValid {
				hasSNI = true
				break
			}
		}
		if hasSNI {
			sniScore := 0.0
			if sniOK {
				sniScore = 1
			}
			components = append(components, sniScore)
			weights = append(weights, w.SNI)
			names = append(names, "sni")
			reasons = append(reasons, fmt.Sprintf("sni_score=%.1f%%", sniScore*100))
			if sniOK {
				reasons = append(reasons, "SNI accepted in at least one observation")
			}
		} else {
			reasons = append(reasons, "sni_score=NOT_TESTED")
		}
	}

	hasEvidence := false
	for _, o := range obs {
		if o.DNSStatus != "NOT_TESTED" ||
			o.TCPResult != "NOT_TESTED" ||
			o.TLSResult != "NOT_TESTED" ||
			o.SNIAccepted ||
			o.CertHostnameValid {
			hasEvidence = true
			break
		}
	}

	evidence := 0.0
	if hasEvidence {
		evidence = math.Min(1, float64(len(obs))/10)
	}

	freshness := 0.0
	if !last.IsZero() {
		freshness = math.Exp(-math.Max(0, now.Sub(last).Hours()) / 24.0)
	}

	if opt.Freshness && !last.IsZero() {
		components = append(components, freshness)
		weights = append(weights, w.Freshness)
		names = append(names, "freshness")
		reasons = append(reasons, fmt.Sprintf("freshness=%.1f%%", freshness*100))
	} else if opt.Freshness {
		reasons = append(reasons, "freshness=NOT_TESTED")
	}

	if opt.Evidence && hasEvidence {
		components = append(components, evidence)
		weights = append(weights, w.Evidence)
		names = append(names, "evidence")
		reasons = append(reasons, fmt.Sprintf("evidence=%.1f%%", evidence*100))
	} else if opt.Evidence {
		reasons = append(reasons, "evidence=NOT_TESTED")
	}

	if len(components) == 0 {
		return 0, "NOT_SCORED", append(reasons, "no enabled scoring component has measured data")
	}

	weightSum := 0.0
	weighted := 0.0

	for i := range components {
		weightSum += weights[i]
		weighted += components[i] * weights[i]
	}

	if weightSum <= 0 {
		return 0, "NOT_SCORED", append(reasons, "no scoring weight available")
	}

	total := 100 * weighted / weightSum

	conf := "LOW"

	measured := 0
	if tcpTested > 0 {
		measured = tcpTested
	}
	if measured == 0 && hasEvidence {
		measured = len(obs)
	}

	if measured >= 4 {
		conf = "MEDIUM"
	}

	if measured >= 8 {
		conf = "HIGH"
	}

	reasons = append(reasons, fmt.Sprintf("scored_components=%v", names))

	return math.Round(total*10) / 10, conf, reasons
}

func Stability(obs []domain.Observation) float64 {
	total := 0
	success := 0

	for _, o := range obs {
		if o.AddressFamily != "IPv4" && o.AddressFamily != "IPv6" {
			continue
		}

		if o.TCPResult != "SUCCESS" && o.TCPResult != "FAILED" {
			continue
		}

		total++

		if o.TCPResult == "SUCCESS" {
			success++
		}
	}

	if total == 0 {
		return 0
	}

	return float64(success) / float64(total)
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}

	if len(v)%2 == 1 {
		return v[len(v)/2]
	}

	return (v[len(v)/2-1] + v[len(v)/2]) / 2
}
