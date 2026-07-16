.PHONY: build test lint validate-controls validate-log-sources validate-maturity validate-siem compose-config

build:
	go build ./cmd/trisoc

test:
	go test -race -cover ./...

lint:
	go vet ./...

validate-controls:
	go run ./cmd/trisoc controls validate controls

validate-log-sources:
	go run ./cmd/trisoc log-sources check examples/log-source-inventory.yaml --at 2026-07-16T08:00:00Z

validate-maturity:
	go run ./cmd/trisoc maturity check examples/soc-maturity-assessment.yaml

validate-siem:
	go run ./cmd/trisoc siem check --log-sources examples/log-source-inventory.yaml --maturity examples/soc-maturity-assessment.yaml --at 2026-07-16T08:00:00Z

compose-config:
	docker compose config --quiet
