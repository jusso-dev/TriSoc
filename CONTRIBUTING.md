# Contributing

Use Go 1.25+, keep changes within one delivery phase, and add tests for security
boundaries. Run:

```sh
gofmt -w cmd internal
go test -race ./...
go vet ./...
go run ./cmd/trisoc controls validate controls
docker compose config --quiet
```

Control changes require an official source, retrieval timestamp and content
hash, classification, permissions, evidence fields, cost impact, deterministic
explanations, and a human reviewer who understands the vendor service. Never
commit recordings until credentials, account identifiers, log bodies, and user
data are sanitised.

Commits should be reviewable and must not combine broad generated formatting
with security logic. New dependencies need a reason and maintenance review.

