# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Security
- Fail closed when OPA policy evaluation crashes or times out instead of silently using the weaker TypeScript fallback (#301).

### Security
- Hardened atomic RPC relayer URL construction so request endpoints must resolve to the configured RPC origin.

### Added
- Added `.github/CODEOWNERS` mapping each sub-package path to responsible reviewers so GitHub automatically routes review requests on every PR.
- Documented CODEOWNERS review-request automation and branch protection setup in `CONTRIBUTING.md`.
- Implemented liveness and readiness health check endpoints.
- Added security incident logger component.
- Initialized `vero-audit-guard` watchtower with core services (scanner-engine, anomaly-detector, audit-guard, verifiable-audit-trail).
