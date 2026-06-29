# Log Archiver Service

## Overview
The **Log Archiver** moves historical audit logs from the local `logs/` directory to an Amazon S3 bucket. It compresses each log with gzip before upload, then removes the local copy (or moves it to an `archive/` folder).

## Configuration (environment variables)
- `ARCHIVE_S3_BUCKET` – **required** – name of the target S3 bucket.
- `ARCHIVE_S3_REGION` – AWS region (default `us-east-1`).
- `ARCHIVE_LOGS_PATH` – path to the local logs directory (default `logs`).
- `ARCHIVE_RETENTION_DAYS` – how many days to keep logs locally before archiving (default `30`).
- `ARCHIVE_S3_PREFIX` – optional prefix for S3 object keys (default `audit-logs/`).

## Usage
### Manual
```bash
# set required env vars
export ARCHIVE_S3_BUCKET=my-audit-logs
export ARCHIVE_S3_REGION=us-east-1
# run the CLI
npm run archive-logs
```
### Automatic (CI/CD)
Add the `archive-logs` script to your CI pipeline (e.g., GitHub Actions) to run nightly.

## Retention Policy
- Logs newer than `ARCHIVE_RETENTION_DAYS` remain on‑disk for quick access.
- Older logs are archived to S3 and optionally moved to `logs/archive/` locally.

## Security
- The service relies on standard AWS credential mechanisms (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, IAM roles, etc.).
- No secrets are stored in the repository.

## Testing
Run `npm test` – the test suite includes a mock for the S3 client to verify upload logic.
