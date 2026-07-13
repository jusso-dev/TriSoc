# Operations

Health is available at `GET /healthz`; it shows process liveness, not cloud or
database attestation health. Validate the bundled catalogue after every upgrade:

```sh
docker compose exec attestor controls validate /app/controls
```

Keep MCP on loopback, monitor container restarts, back up PostgreSQL, test restore,
and retain audit data according to organisation policy. Do not edit historical
rows to correct a result; append a new assessment or decision.

