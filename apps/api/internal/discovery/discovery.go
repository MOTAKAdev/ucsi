package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pikify.local/pikify-engine/api/internal/domain"
	"pikify.local/pikify-engine/api/internal/security"
)

type Source interface {
	Name() string
	Discover(context.Context, string) ([]domain.Candidate, error)
}

type SeedSource struct{}

func (SeedSource) Name() string { return "user_seed" }
func (SeedSource) Discover(_ context.Context, seed string) ([]domain.Candidate, error) {
	h, e := security.NormalizeHostname(seed)
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	return []domain.Candidate{{ID: stableID(h), Hostname: h, OriginalName: seed, Source: "user_seed", FirstSeen: now, LastSeen: now}}, nil
}

type CRTShSource struct {
	Endpoint string
	Client   *http.Client
}

func (c CRTShSource) Name() string { return "crtsh" }
func (c CRTShSource) Discover(ctx context.Context, root string) ([]domain.Candidate, error) {
	if c.Endpoint == "" {
		c.Endpoint = "https://crt.sh/?q=%25.%s&output=json"
	}
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 15 * time.Second}
	}
	u := fmt.Sprintf(c.Endpoint, url.PathEscape(root))
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if e != nil {
		return nil, e
	}
	resp, e := c.Client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ct source status %d", resp.StatusCode)
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if e = json.NewDecoder(resp.Body).Decode(&rows); e != nil {
		return nil, e
	}
	seen := map[string]struct{}{}
	out := make([]domain.Candidate, 0, len(rows))
	now := time.Now().UTC()
	for _, r := range rows {
		for _, raw := range strings.Split(r.NameValue, "\n") {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, "*."))
			h, e := security.NormalizeHostname(raw)
			if e != nil {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, domain.Candidate{ID: stableID(h), Hostname: h, OriginalName: raw, Source: "ct:crtsh", FirstSeen: now, LastSeen: now})
		}
	}
	return out, nil
}
func stableID(s string) string {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("cand-%016x", h)
}
