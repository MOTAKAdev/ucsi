.PHONY: fmt test test-core build compose-up compose-down migrate
fmt:
	gofmt -w $$(find apps -name '*.go')
test-core:
	go test ./apps/api/internal/security ./apps/api/internal/measurement ./apps/api/internal/scoring ./apps/api/internal/reality
build:
	go build ./apps/api/cmd/ucsi ./apps/api/cmd/ucsi-worker
compose-up:
	docker compose up -d postgres redis
migrate:
	docker compose run --rm migrate
compose-down:
	docker compose down
