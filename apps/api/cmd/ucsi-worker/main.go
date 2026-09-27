package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"pikify.local/pikify-engine/api/internal/queue"
	"pikify.local/pikify-engine/api/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	u := os.Getenv("UCSI_DATABASE_URL")
	if u == "" {
		u = "postgres://ucsi:ucsi@localhost:5432/ucsi?sslmode=disable"
	}
	s, e := store.New(ctx, u)
	if e != nil {
		log.Fatal(e)
	}
	defer s.Close()
	queue.RunWorker(ctx, s)
}
