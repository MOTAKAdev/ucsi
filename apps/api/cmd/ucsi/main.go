package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"pikify.local/pikify-engine/api/internal/httpapi"
	"pikify.local/pikify-engine/api/internal/queue"
	"pikify.local/pikify-engine/api/internal/store"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx := context.Background()
	db, err := store.New(ctx, env("UCSI_DATABASE_URL", "postgres://ucsi:ucsi@localhost:5432/ucsi?sslmode=disable"))
	if err != nil {
		slog.Error("database startup failed", "error", err)
		log.Fatal(err)
	}
	defer db.Close()
	r, err := queue.New(env("UCSI_REDIS_URL", "redis://localhost:6379/0"))
	if err != nil {
		slog.Error("redis configuration failed", "error", err)
		log.Fatal(err)
	}
	if err := r.PING(ctx); err != nil {
		slog.Warn("redis unavailable; database queue remains authoritative", "error", err)
	}
	apiToken := env("UCSI_API_TOKEN", "")
	if env("UCSI_ENV", "production") == "production" && (apiToken == "" || apiToken == "dev-token" || apiToken == "replace-with-long-random-token") {
		slog.Error("refusing insecure API token in production")
		os.Exit(1)
	}
	srv := &httpapi.Server{Store: db, Token: apiToken}
	addr := env("UCSI_API_ADDR", "0.0.0.0:8080")
	h := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 160 * time.Second, IdleTimeout: 60 * time.Second}
	slog.Info("UCSI API listening", "addr", addr)
	log.Fatal(h.ListenAndServe())
}
