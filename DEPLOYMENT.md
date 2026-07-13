# Deployment

`docker compose up --build -d` starts PostgreSQL 17 and the control-catalogue MCP
service. Both published ports bind to `127.0.0.1`. The application container is
non-root, read-only, drops every Linux capability, and uses a small tmpfs.

Set `POSTGRES_PASSWORD` in `.env` before use beyond disposable development. The
current initialisation mount applies the canonical migration only to a new data
volume. Back up the volume before schema upgrades. Kubernetes, Helm, external
secrets, TLS termination, and high availability are phase 7 deliverables.

