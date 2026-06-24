// src/audit-guard/src/errors.ts
export class SyncDriftError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SyncDriftError";
  }
}
