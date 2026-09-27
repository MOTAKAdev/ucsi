package originscan

import (
	"testing"
)

func TestHasH3Advertisement(t *testing.T) {
	tests := []struct {
		name string
		alt  string
		want bool
	}{
		{"h3", `h3=":443"; ma=86400`, true},
		{"h3-29", `h3-29=":443"; ma=86400`, true},
		{"http2-only", `h2=":443"; ma=86400`, false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasH3Advertisement(tt.alt); got != tt.want {
				t.Fatalf("hasH3Advertisement(%q) = %v, want %v", tt.alt, got, tt.want)
			}
		})
	}
}

func TestPercentileNearestRank(t *testing.T) {
	v := []float64{10, 20, 30}
	if got := percentile(v, 0.95); got != 30 {
		t.Fatalf("percentile(95%%) = %v, want 30", got)
	}
}

func TestMandatoryReadyRequiresRealHTTP3(t *testing.T) {
	x := true
	r := CandidateResult{
		TLS13:          true,
		H2:              true,
		SNIAccepted:    true,
		CertValid:      true,
		ALPN:            "h2",
		HTTP3Advertised: true,
		HTTP3:           &x,
		X25519:          &x,
		PostQuantum:     &x,
	}
	if !mandatoryReady(r) {
		t.Fatal("expected full mandatory result to be ready")
	}
	x = false
	r.HTTP3 = &x
	if mandatoryReady(r) {
		t.Fatal("expected failed HTTP3 handshake to block readiness")
	}
}
