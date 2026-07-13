.PHONY: build test lint validate-controls compose-config

build:
	go build ./cmd/trisoc

test:
	go test -race -cover ./...

lint:
	go vet ./...

validate-controls:
	go run ./cmd/trisoc controls validate controls

compose-config:
	docker compose config --quiet
