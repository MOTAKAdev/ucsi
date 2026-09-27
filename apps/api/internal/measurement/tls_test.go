package measurement

import (
	"context"
	"testing"

	"pikify.local/pikify-engine/api/internal/security"
)

func TestClassificationHostnameRejectsURL(t *testing.T) {
	if _, e := security.NormalizeHostname("https://example.com"); e == nil {
		t.Fatal("expected rejection")
	}
}

func TestPublicIPPolicy(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "::ffff:127.0.0.1", "ff02::1"} {
		if security.IsPublicIP(ip) {
			t.Fatalf("%s must be blocked", ip)
		}
	}
	if !security.IsPublicIP("1.1.1.1") {
		t.Fatal("1.1.1.1 should be public")
	}
	_ = context.Background()
}

func TestIDNANormalization(t *testing.T) {
	h, err := security.NormalizeHostname("BÜCHER.Example.")
	if err != nil {
		t.Fatal(err)
	}
	if h != "xn--bcher-kva.example" {
		t.Fatalf("unexpected canonical hostname: %s", h)
	}
}
