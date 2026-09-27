package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type scanResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}
type result struct {
	Rank       int     `json:"rank"`
	SNI        string  `json:"sni"`
	Target     string  `json:"target"`
	Score      float64 `json:"score"`
	Confidence string  `json:"confidence"`
	Median     float64 `json:"median_rtt_ms"`
}

func main() {
	server := flag.String("server", "", "server IP/hostname")
	mode := flag.String("mode", "TLS", "TLS or REALITY")
	profile := flag.String("profile", "BALANCED", "scan profile")
	top := flag.Int("top", 20, "top N")
	samples := flag.Int("samples", 3, "sample count")
	api := flag.String("api", env("UCSI_API_URL", "http://localhost:8080"), "API URL")
	flag.Parse()
	if *server == "" {
		log.Fatal("-server is required")
	}
	token := os.Getenv("UCSI_API_TOKEN")
	if token == "" {
		log.Fatal("UCSI_API_TOKEN is required")
	}
	body, _ := json.Marshal(map[string]any{"server": *server, "mode": *mode, "profile": *profile, "top_n": *top, "sample_count": *samples})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	scan := scanResponse{}
	post(ctx, *api+"/api/v1/scans", token, body, &scan)
	fmt.Printf("scan_id=%s status=%s\n", scan.ID, scan.Status)
	for {
		var status struct {
			Status string `json:"status"`
		}
		get(ctx, *api+"/api/v1/scans/"+scan.ID, token, &status)
		fmt.Printf("status=%s\n", status.Status)
		if status.Status == "SUCCEEDED" || status.Status == "FAILED" || status.Status == "CANCELLED" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	var out struct {
		Results []result `json:"results"`
	}
	get(ctx, *api+"/api/v1/scans/"+scan.ID+"/results", token, &out)
	for _, r := range out.Results {
		fmt.Printf("#%d\nSNI    %s\nTARGET %s\nSCORE  %.1f (%s)\nTCP    %.1f ms\n\n", r.Rank, r.SNI, r.Target, r.Score, r.Confidence, r.Median)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func post(ctx context.Context, url, token string, body []byte, out any) {
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if e != nil {
		log.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	do(req, out)
}
func get(ctx context.Context, url, token string, out any) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		log.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	do(req, out)
}
func do(req *http.Request, out any) {
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		log.Fatal(e)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		log.Fatalf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	if err := json.Unmarshal(b, out); err != nil {
		log.Fatal(fmt.Errorf("invalid API response: %w", err))
	}
}
