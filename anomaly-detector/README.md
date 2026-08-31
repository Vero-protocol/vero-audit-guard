# Anomaly Detector

Real-time anomaly detector for the relayer service.

## Key Modules

- `threat-feed-fetcher.ts`: Fetches threat feeds and incoming security signals.
- `rpc-failover-monitor.ts`: Monitors RPC endpoint health and handles failover tracking.

## Local Development

- **Development:** `npm run dev`
- **Test:** `npm run test`
- **Build:** `npm run build`

## Inputs & Outputs

- **Inputs:** `nonce-db.json` and relayer configurations.
- **Outputs:** Anomaly alerts and monitoring logs.