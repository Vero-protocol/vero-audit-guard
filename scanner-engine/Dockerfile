# scanner-engine — Rust static analyzer for Soroban/Rust contracts.
# Build context must be the repository root (see docker-compose.yml).
FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY scanner-engine /src/scanner-engine
COPY src/audit-guard /src/src/audit-guard

WORKDIR /src/scanner-engine
RUN cargo build --release --locked --bin scanner

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/scanner-engine/target/release/scanner /usr/local/bin/scanner
COPY scanner-engine/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /app
VOLUME ["/app/reports"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/target"]
