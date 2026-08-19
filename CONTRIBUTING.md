# Contributing to vero-audit-guard

Thanks for helping harden the Vero watchtower. This document covers local setup, the Docker Compose workflow, and the expected contribution flow.

## Prerequisites

For a native (non-Docker) workflow:

- Rust toolchain (`rustup install stable`) with `cargo`
- Node.js ≥ 20 (CI uses 22) and npm
- `cargo-audit` (`cargo install cargo-audit --locked`)

For the containerised pipeline you only need **Docker Engine + Compose v2**.

## Docker Compose workflow

The root [`docker-compose.yml`](docker-compose.yml) starts the local multi-service pipeline described in [#279](https://github.com/Vero-protocol/vero-audit-guard/issues/279).

### First run

```bash
cp .env.example .env
docker compose up --build
```

Compose will:

1. Build `scanner-engine` (Rust) and run it against `./docker/sample-target`.
2. Write `reports/latest-scan.json` on the host via a bind mount.
3. Run `verifiable-audit-trail` against that reports directory (dry-run unless `AUDIT_KEYPAIR_SECRET` is set).
4. Start `atomic-rpc-relayer-bridge` on `http://localhost:8545` (`/health`, `/metrics`, `/audit-log`).
5. Start `anomaly-detector`, which polls `http://atomic-rpc-relayer-bridge:8545/metrics` on the compose network.

`scanner-engine` and `verifiable-audit-trail` are one-shot jobs (`restart: "no"`). The bridge and detector stay up until you run `docker compose down`.

### Service map

| Compose service | Dockerfile | Default port | Notes |
|-----------------|------------|--------------|-------|
| `scanner-engine` | `scanner-engine/Dockerfile` (root build context) | — | Needs `src/audit-guard` at build time |
| `anomaly-detector` | `anomaly-detector/Dockerfile` (root build context) | — | Copies the audit-guard TS helpers it imports |
| `atomic-rpc-relayer-bridge` | `atomic-rpc-relayer-bridge/Dockerfile` | `8545` | Local metrics server (`npm run start:local`) |
| `verifiable-audit-trail` | `verifiable-audit-trail/Dockerfile` | — | Waits for `reports/latest-scan.json` |

### Common overrides

```bash
# Point the scanner at a real contract tree on the host
SCAN_HOST_TARGET=../vero-core-contracts docker compose up --build scanner-engine verifiable-audit-trail

# Rebuild a single image after a code change
docker compose build anomaly-detector
docker compose up -d anomaly-detector

# Inspect reports produced by the scanner
cat reports/latest-scan.json
```

Environment variables are documented in [`.env.example`](.env.example) and in the README "Environment Variables" table. Docker Compose reads a host `.env` for interpolation; do not commit secrets.

### Package `.env.example` files

Each package that reads environment variables keeps a local `.env.example` with safe placeholder values. Copy the relevant file to `.env` when running a package locally, then replace placeholder values with your own development configuration.

- `anomaly-detector/.env.example` documents relayer metrics, RPC failover, threat feed, dashboard, and telemetry settings.
- `atomic-rpc-relayer-bridge/.env.example` documents local server bind, bridge endpoint, relayer address, nonce, and failed-transaction sample settings.
- `verifiable-audit-trail/.env.example` documents Stellar Horizon, network, and optional audit keypair settings.
- `src/audit-guard/.env.example` documents webhook, dashboard, on-call, policy, CLI, archive, backup, Stellar, and telemetry settings.

Never commit real secrets, API tokens, private keys, production endpoints that should remain private, or local `.env` files. When adding a new `process.env` or `import.meta.env` read, update the nearest package-level `.env.example` in the same change.

### Acceptance check

`docker compose up --build` should:

- Produce `reports/latest-scan.json`
- Print `[audit-trail]` hash lines (dry-run without a keypair)
- Keep `atomic-rpc-relayer-bridge` healthy on `:8545/health`
- Keep `anomaly-detector` polling without crashing

## Native workflow

```bash
chmod +x BUILD_GUARD.sh
./BUILD_GUARD.sh [path/to/vero-core-contracts]
```

See the README for what each step does.

## Pull requests

1. Branch from `main` using the issue naming convention when one is specified (for example `chore/issue-279-add-docker-compose-setup`).
2. Keep changes scoped to the issue. Prefer additive tooling over drive-by refactors.
3. Make sure new TypeScript compiles under `strict` and that package tests still pass (`npm test` / `cargo test` in the touched crate).
4. Open the PR against `Vero-protocol/vero-audit-guard` and reference the issue (`Closes #279`).
5. Fill in the repository PR description completely — state what was completed from the issue.

Do not commit `.env`, keypairs, or report JSON that may contain sensitive paths.
