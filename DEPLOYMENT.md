# Deployment

`docker compose up --build -d` starts PostgreSQL 17 and the control-catalogue MCP
service. Both published ports bind to `127.0.0.1`. The application container is
non-root, read-only, drops every Linux capability, and uses a small tmpfs.

Set `POSTGRES_PASSWORD` in `.env` before use beyond disposable development. The
current initialisation mount applies the canonical migration only to a new data
volume. Back up the volume before schema upgrades. Kubernetes, Helm, external
secrets, TLS termination, and high availability are phase 7 deliverables.

Production-oriented SIEM infrastructure baselines are separate from the local
application stack. See [docs/SIEM_IAC.md](docs/SIEM_IAC.md) for Microsoft
Sentinel, AWS-native security operations, and Google Security Operations rollout
instructions. Splunk deployment IaC is intentionally excluded.

Treat infrastructure validation and operational readiness as separate required
inputs to one decision. Before deployment and again after connector onboarding,
run the combined gate with environment-specific evidence:

```sh
trisoc siem check \
  --log-sources examples/log-source-inventory.yaml \
  --maturity examples/soc-maturity-assessment.yaml \
  --at 2026-07-16T08:00:00Z
```

IaC success alone is not deployment approval. See
[docs/SOC_MATURITY.md](docs/SOC_MATURITY.md).
