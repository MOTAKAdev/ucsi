package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pikify.local/pikify-engine/api/internal/store"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	db, err := store.New(ctx, env("UCSI_DATABASE_URL", "postgres://ucsi:ucsi@localhost:5432/ucsi?sslmode=disable"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := db.RecoverStaleJobs(ctx, 10*time.Minute); err != nil {
				log.Printf("job recovery failed: %v", err)
			}
		}
	}
}
