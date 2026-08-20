# anomaly-detector — long-running TypeScript relayer monitor.
# Build context must be the repository root: the service imports
# src/audit-guard telemetry/webhook helpers.
FROM node:22-bookworm-slim

WORKDIR /app

COPY anomaly-detector/package.json anomaly-detector/package-lock.json ./anomaly-detector/
COPY src/audit-guard/src/webhook.ts src/audit-guard/src/config.ts \
     src/audit-guard/src/telemetry-ingestion-guard.ts ./src/audit-guard/src/

WORKDIR /app/anomaly-detector
RUN npm ci

COPY anomaly-detector/tsconfig.json anomaly-detector/jest.config.js ./
COPY anomaly-detector/src ./src

ENV NODE_ENV=development
ENV TS_NODE_TRANSPILE_ONLY=1

CMD ["npx", "ts-node", "--transpile-only", "src/index.ts"]
