package security

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeHostname converts Unicode IDNs to their ASCII wire form and applies
// deterministic lookup-safe normalization. The canonical stored name is ASCII/punycode.
func NormalizeHostname(raw string) (string, error) {
	s := strings.TrimSpace(strings.TrimSuffix(raw, "."))
	if s == "" || strings.ContainsAny(s, "/\\:@?#[]") {
		return "", fmt.Errorf("invalid hostname")
	}
	if net.ParseIP(s) != nil {
		return "", fmt.Errorf("IP addresses are not hostnames")
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(s))
	if err != nil {
		return "", fmt.Errorf("invalid IDNA hostname: %w", err)
	}
	if ascii == "" || strings.Contains(ascii, "..") || len(ascii) > 253 {
		return "", fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname label")
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				return "", fmt.Errorf("hostname contains unsupported characters")
			}
		}
	}
	return ascii, nil
}

func IsPublicIP(s string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !ip.IsValid() {
		return false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return true
}

func ResolvePublic(ctx context.Context, host string) ([]net.IPAddr, error) {
	normalized, err := NormalizeHostname(host)
	if err != nil {
		return nil, err
	}
	resolver := &net.Resolver{PreferGo: true}
	ips, err := resolver.LookupIPAddr(ctx, normalized)
	if err != nil {
		return nil, err
	}
	out := make([]net.IPAddr, 0, len(ips))
	seen := map[string]struct{}{}
	for _, ip := range ips {
		key := ip.IP.String()
		if !IsPublicIP(key) {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no public destination addresses")
	}
	return out, nil
}

func ValidateIPTarget(raw string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !IsPublicIP(ip.String()) {
		return "", fmt.Errorf("target IP is not a public IP")
	}
	return ip.String(), nil
}
