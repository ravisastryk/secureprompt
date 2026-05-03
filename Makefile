.PHONY: build run test test-race cover clean fmt vet lint lint-ci tidy quickstart semantic

BINARY               = secureprompt
CMD                  = ./cmd/secureprompt
GOLANGCI_LINT_VERSION = v2.6.0

## build: Compile the binary
build:
	go build -o $(BINARY) $(CMD)

## run: Run in development mode
run:
	go run $(CMD)

## test: Run all tests
test:
	go test ./... -v -count=1

## test-race: Run tests with the race detector (mirrors CI)
test-race:
	go test ./... -race -count=1

## cover: Run tests with coverage and print a per-function summary
cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -20

## fmt: Format all Go files
fmt:
	gofmt -s -w .

## vet: Run go vet
vet:
	go vet ./...

## tidy: Verify go.mod / go.sum are tidy (used by CI)
tidy:
	go mod tidy
	@git diff --exit-code go.mod go.sum || (echo "go.mod/go.sum out of date — run 'go mod tidy'" && exit 1)

## lint: Run golangci-lint locally (installs on demand)
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)…"; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	}
	golangci-lint run --timeout=5m

## lint-ci: Same lint config as CI — fmt + vet + golangci-lint
lint-ci: fmt vet lint

## clean: Remove build artifacts
clean:
	rm -f $(BINARY) coverage.out

## health: Check if the API is running
health:
	@curl -s http://localhost:8080/health | jq .

## scan: Quick interactive scan (usage: make scan PROMPT="your text")
scan:
	@curl -s http://localhost:8080/v1/prescan \
		-H 'Content-Type: application/json' \
		-d '{"content":"$(PROMPT)"}' | jq .

## stats: View scan statistics
stats:
	@curl -s http://localhost:8080/v1/stats | jq .

## audit: View the audit log
audit:
	@curl -s http://localhost:8080/v1/audit | jq .

## quickstart: Build, run, and exercise representative prompts end-to-end
##             (loads .env automatically; set SP_SEMANTIC=true + HF_TOKEN
##             there to also exercise the semantic layer)
quickstart:
	bash scripts/quickstart.sh

## semantic: End-to-end run with the semantic layer enabled. Reads HF_TOKEN
##           and SP_SEMANTIC_* from .env (copy from .env.example first).
semantic:
	bash scripts/run_semantic.sh

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
