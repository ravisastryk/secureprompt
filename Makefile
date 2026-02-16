.PHONY: build run test clean fmt vet lint

BINARY  = secureprompt
CMD     = ./cmd/secureprompt

## build: Compile the binary
build:
	go build -o $(BINARY) $(CMD)

## run: Run in development mode
run:
	go run $(CMD)

## test: Run all tests
test:
	go test ./... -v -count=1

## fmt: Format all Go files
fmt:
	gofmt -s -w .

## vet: Run go vet
vet:
	go vet ./...

## lint: Format + vet
lint: fmt vet

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)

## health: Check if the API is running
health:
	@curl -s http://localhost:8080/health | python3 -m json.tool

## scan: Quick interactive scan (usage: make scan PROMPT="your text")
scan:
	@curl -s http://localhost:8080/v1/prescan \
		-H 'Content-Type: application/json' \
		-d '{"content":"$(PROMPT)"}' | python3 -m json.tool

## stats: View scan statistics
stats:
	@curl -s http://localhost:8080/v1/stats | python3 -m json.tool

## audit: View the audit log
audit:
	@curl -s http://localhost:8080/v1/audit | python3 -m json.tool

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
