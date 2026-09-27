package store

import (
	"context"
	"time"
)

func (s *Store) RecoverStaleJobs(ctx context.Context, maxAge time.Duration) error {
	if maxAge < time.Minute {
		maxAge = 10 * time.Minute
	}
	_, err := s.DB.Exec(ctx, `update scan_jobs set status='PENDING',attempt=attempt+1 where status='RUNNING' and started_at < now() - $1::interval and attempt < max_attempts`, maxAge.String())
	return err
}
