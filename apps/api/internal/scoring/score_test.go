package scoring

import (
	"testing"
	"time"

	"pikify.local/pikify-engine/api/internal/domain"
)

func TestScoreDeterministic(t *testing.T) {
	now := time.Now().UTC()

	obs := []domain.Observation{
		{
			MeasuredAt:    now,
			TCPResult:     "SUCCESS",
			TCPConnectMS:  20,
			TLSResult:     "SUCCESS",
			SNIAccepted:   true,
			AddressFamily: "IPv4",
		},
		{
			MeasuredAt:    now.Add(time.Second),
			TCPResult:     "SUCCESS",
			TCPConnectMS:  30,
			TLSResult:     "SUCCESS",
			SNIAccepted:   true,
			AddressFamily: "IPv4",
		},
	}

	a, _, _ := Score(obs, Default, now)
	b, _, _ := Score(obs, Default, now)

	if a != b {
		t.Fatalf("%v != %v", a, b)
	}
}
