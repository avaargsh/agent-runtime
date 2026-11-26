# Local helpers for a checkout of this repository.
#
# These targets mirror the cluster-free static steps in
# .github/workflows/go-tests.yml: gofmt -l cmd internal must be empty,
# go vet ./..., go mod verify, go mod tidy drift, and
# go test -race -count=1 ./... . They do not start Temporal or PostgreSQL.
#
# go mod tidy -diff reports module drift and does not rewrite go.mod or
# go.sum. The plain `go mod tidy` command in the README can still rewrite
# those files; that form stays outside `make lint`.
#
# GitHub Actions pins Go 1.26.11 with GOTOOLCHAIN=local. go.mod states the
# minimum Go version (1.26.0). This Makefile uses only the installed
# toolchain and does not download one.
#
# Main packages under ./cmd, compiled by `make build`:
#   acp-api, decision-authority-api, guard-authority-api, starter, worker.

.PHONY: help lint test build clean require-go

# Recipes, and any Go command they invoke, stay on the installed toolchain.
export GOTOOLCHAIN := local

# Keep build and clean inside the documented repository-local output directory.
override BIN_DIR := bin

.DEFAULT_GOAL := help

help:
	@echo "Targets (GOTOOLCHAIN=local; the installed Go only; no toolchain download):"
	@echo "  go.mod requires Go 1.26.0 or newer. CI pins Go 1.26.11."
	@echo "  make help   - list targets (default)"
	@echo "  make lint   - gofmt -l cmd internal must be empty, go vet ./..., go mod verify, and go mod tidy -diff (does not rewrite go.mod or go.sum; no Temporal, no PostgreSQL)"
	@echo "  make test   - go test -race -count=1 ./... (does not start Temporal or PostgreSQL; tests that need TEST_DATABASE_URL or other env vars skip; see README)"
	@echo "  make build  - compile every main package under ./cmd into $(BIN_DIR)/ (acp-api, decision-authority-api, guard-authority-api, starter, worker)"
	@echo "  make clean  - delete $(BIN_DIR)/ only; does not clear the Go build cache"

require-go:
	@if ! command -v go >/dev/null 2>&1; then \
		printf '%s\n' "error: go is not installed or not on PATH. Install Go 1.26.0 or newer (CI pins Go 1.26.11). This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi
	@if ! command -v gofmt >/dev/null 2>&1; then \
		printf '%s\n' "error: gofmt is not installed or not on PATH. It ships with the Go toolchain. This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi
	@need=$$(sed -n 's/^go \([0-9][0-9]*\(\.[0-9][0-9]*\)*\).*/\1/p' go.mod | head -n 1); \
	if [ -z "$$need" ]; then \
		printf '%s\n' "error: could not read the required Go version from go.mod." >&2; \
		exit 1; \
	fi; \
	raw=$$(go env GOVERSION 2>/dev/null || true); \
	have=$$(printf '%s\n' "$$raw" | sed -n 's/^go\([0-9][0-9]*\(\.[0-9][0-9]*\)*\)$$/\1/p' | head -n 1); \
	if [ -z "$$have" ]; then \
		printf '%s\n' "error: a stable local Go release is required; unexpected 'go env GOVERSION' (got: $${raw:-empty}). This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi; \
	version_at_least() { \
		have_v="$$1"; need_v="$$2"; \
		while [ -n "$$have_v" ] || [ -n "$$need_v" ]; do \
			h="$${have_v%%.*}"; n="$${need_v%%.*}"; \
			if [ "$$have_v" = "$$h" ]; then have_v=""; else have_v="$${have_v#*.}"; fi; \
			if [ "$$need_v" = "$$n" ]; then need_v=""; else need_v="$${need_v#*.}"; fi; \
			h="$${h%%[!0-9]*}"; n="$${n%%[!0-9]*}"; \
			h="$${h:-0}"; n="$${n:-0}"; \
			if [ "$$h" -gt "$$n" ]; then return 0; fi; \
			if [ "$$h" -lt "$$n" ]; then return 1; fi; \
		done; \
		return 0; \
	}; \
	if ! version_at_least "$$have" "$$need"; then \
		printf '%s\n' "error: local Go $$have is older than go.mod requires Go $$need. Install Go $$need or newer (CI pins Go 1.26.11). This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi

lint: require-go
	@unformatted=$$(gofmt -l cmd internal) || exit $$?; \
	if [ -n "$$unformatted" ]; then \
		printf 'Unformatted Go files:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi
	go vet ./...
	go mod verify
	go mod tidy -diff

test: require-go
	go test -race -count=1 ./...

build: require-go
	mkdir -p $(BIN_DIR)
	@set -e; \
	found=0; \
	for dir in cmd/*; do \
		[ -d "$$dir" ] || continue; \
		if grep -q '^package main$$' "$$dir"/*.go; then \
			found=1; \
			name=$${dir##*/}; \
			printf '%s\n' "go build -o $(BIN_DIR)/$$name ./$$dir"; \
			go build -o $(BIN_DIR)/$$name "./$$dir"; \
		fi; \
	done; \
	if [ "$$found" -eq 0 ]; then \
		printf '%s\n' "error: no main packages under ./cmd" >&2; \
		exit 1; \
	fi

clean:
	rm -rf $(BIN_DIR)
