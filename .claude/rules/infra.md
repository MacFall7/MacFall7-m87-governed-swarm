---
paths:
  - "infra/**"
  - "docker-compose.yml"
  - "Dockerfile*"
---

# Infrastructure Rules

Infrastructure defines the execution boundary and isolation model.

## Service Architecture

| Service        | Role                    | Network Access           |
|----------------|-------------------------|--------------------------|
| redis          | Event store, job queue  | Internal only            |
| api            | Governance engine       | Public (8000)            |
| runner         | Job executor            | Internal + controlled    |
| notifier       | Observation only        | Internal                 |
| ui             | Dashboard               | Public (3000)            |
| *-adapter      | Proposal generators     | Internal (api only)      |

## Rules

- No privileged containers without explicit justification
- Redis has no public port (internal only)
- All services depend on redis and api health checks
- M87_API_KEY must be passed to all services that mutate state
- Adapters cannot access runner directly

## Security Posture

- API key required for all mutations
- CORS restricted to allowed origins
- Test endpoints gated behind M87_ENABLE_TEST_ENDPOINTS
- Redis persistence enabled (AOF)

## Environment Variables

| Variable                    | Required | Purpose                    |
|-----------------------------|----------|----------------------------|
| M87_API_KEY                 | Yes      | Authentication             |
| REDIS_URL                   | Yes      | Redis connection           |
| ALLOWED_ORIGINS             | No       | CORS whitelist             |
| M87_ENABLE_TEST_ENDPOINTS   | No       | Enable /v1/admin/* routes  |

## Prohibited Patterns

- Exposing Redis publicly
- Running containers as root without justification
- Sharing volumes between untrusted services
- Disabling health checks
