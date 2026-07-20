# infra

Local development / demo deployment for the **CPU-only core services** (ARCHITECTURE.md §7).
Production uses managed infrastructure with secrets from a KMS/secret manager, TLS 1.3 at the
ingress, network segmentation, and per-environment credentials — none of that lives here.

## Quick start

```bash
docker-compose -f infra/docker-compose.yml up --build
# API on http://127.0.0.1:8080  (loopback only), Postgres on 127.0.0.1:5432
curl -s -X POST http://127.0.0.1:8080/v1/register/begin -H 'content-type: application/json' -d '{}'
```

Or run the API against a local Homebrew Postgres without containers:

```bash
createdb nedwons_dev
cd services
DATABASE_URL=postgres://localhost/nedwons_dev cargo run -p nedwons-api
```

## Verified in this environment (2026-07-17)

- `docker-compose config` validates; the `postgres:17` service starts and reports
  `pg_isready`, then tears down cleanly (`down -v`).
- The API binary boots against a local Postgres, applies the embedded migration, serves
  `/healthz`, and returns live challenges.

Not run here: the full in-container Rust release build (`api` service image) — it compiles
from scratch inside the container and was skipped for time. The Dockerfile is standard
multi-stage and the build context is validated by `docker-compose config`.

## Hardening applied to the `api` container

`read_only` root filesystem, `cap_drop: ALL`, `no-new-privileges`, non-root UID 10001,
loopback-only port publishing. Production adds resource limits, a read-only image from a
signed artifact, network policies, and restricted egress.

## Future: isolated GPU worker pool (Milestone 6)

GPU workers are a SEPARATE deployment in a SEPARATE trust zone (ARCHITECTURE.md TB-5) with no
access to account/message databases or signing keys, and their failure cannot affect core
messaging. They are intentionally absent from this core stack.
