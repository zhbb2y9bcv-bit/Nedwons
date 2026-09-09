# Multi-stage build for the Nedwons API. Runtime is a minimal, non-root image with only the
# binary. The `postgres` crate is a pure-Rust client (NoTls in dev), so no libpq/openssl is
# required at runtime.
#
# BUILD CONTEXT IS THE REPOSITORY ROOT, not `services/`:
#   docker build -f services/api/Dockerfile -t nedwons-api .
# The services workspace reaches outside its own directory in two places that a `services`-only
# context cannot see — `core/mls-core` (a dev-dependency, used by the tests that drive real MLS
# ciphertext through the relay) and the `[patch.crates-io]` entry for the vendored
# `core/vendor/openmls_rust_crypto` (ADR-0016's post-quantum provider). Cargo resolves the whole
# manifest before it builds anything, so both must be present even though neither ends up in the
# binary.

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
# Both trees, because the workspace manifest references both.
COPY services ./services
COPY core ./core
WORKDIR /build/services
RUN cargo build --release -p nedwons-api

FROM debian:bookworm-slim AS runtime
# Non-root user; read-only-friendly layout.
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin nedwons
COPY --from=builder /build/services/target/release/nedwons-api /usr/local/bin/nedwons-api
# The api reads config from env (DATABASE_URL, NEDWONS_BIND, NEDWONS_RATE_PER_MIN).
USER 10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/nedwons-api"]
