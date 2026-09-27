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

func TestMandatoryReadyRequiresAltSvc(t *testing.T) {
	ok := true
	failed := false
	r := CandidateResult{
		TLS13:           true,
		H2:              true,
		SNIAccepted:     true,
		CertValid:       true,
		ALPN:            "h2",
		HTTP3Advertised: true,
		HTTP3:           &failed,
		X25519:          &ok,
		PostQuantum:     &ok,
	}
	if !mandatoryReady(r) {
		t.Fatal("expected Alt-Svc advertisement to satisfy HTTP/3 gate")
	}
	r.HTTP3Advertised = false
	if mandatoryReady(r) {
		t.Fatal("expected missing Alt-Svc advertisement to block readiness")
	}
}

func TestVerifyOriginAcceptsArbitraryPublicIP(t *testing.T) {
	t.Setenv("PIKIFY_ORIGIN_IP", "206.1.103.54")
	got, err := verifyOrigin("89.163.157.94")
	if err != nil {
		t.Fatalf("verifyOrigin returned error for arbitrary public IP: %v", err)
	}
	if got != "89.163.157.94" {
		t.Fatalf("verifyOrigin = %q, want 89.163.157.94", got)
	}
}
