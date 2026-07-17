# Multi-stage build for the Sentinel API. Runtime is a minimal, non-root image with only
# the statically-needed binary. The `postgres` crate is a pure-Rust client (NoTls in dev),
# so no libpq/openssl is required at runtime.

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
# Copy the whole services workspace (auth-core + api).
COPY . .
RUN cargo build --release -p sentinel-api

FROM debian:bookworm-slim AS runtime
# Non-root user; read-only-friendly layout.
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin sentinel
COPY --from=builder /build/target/release/sentinel-api /usr/local/bin/sentinel-api
# The api reads config from env (DATABASE_URL, SENTINEL_BIND, SENTINEL_RATE_PER_MIN).
USER 10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sentinel-api"]
