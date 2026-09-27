package scoring

import (
	"testing"
	"time"

	"pikify.local/pikify-engine/api/internal/domain"
)

func BenchmarkScore(b *testing.B) {
	now := time.Now().UTC()

	obs := make([]domain.Observation, 100)

	for i := range obs {
		obs[i] = domain.Observation{
			MeasuredAt:    now.Add(time.Duration(i) * time.Second),
			TCPResult:     "SUCCESS",
			TCPConnectMS:  float64(10 + i%9),
			TLSResult:     "SUCCESS",
			SNIAccepted:   true,
			AddressFamily: "IPv4",
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = Score(obs, Default, now)
	}
}
