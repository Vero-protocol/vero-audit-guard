// src/audit-guard/src/sync-validator.ts
import crypto from "crypto";
import { PRData } from "./policy-engine";
import { SyncDriftError } from "./errors";

/**
 * SyncValidator checks that the provided state hash matches the computed hash
 * of the PR data. This helps detect chain/relayer synchronization drift.
 */
export class SyncValidator {
  /**
   * Compute a deterministic hash of PRData (excluding any existing state_hash).
   */
  private computeHash(prData: PRData): string {
    // Clone without state_hash to avoid circular hash.
    const { state_hash, ...dataWithoutHash } = prData as any;
    const json = JSON.stringify(dataWithoutHash);
    return crypto.createHash("sha256").update(json).digest("hex");
  }

  /**
   * Validate the PR data against its stored state hash.
   * Throws SyncDriftError if the hashes differ.
   */
  async validate(prData: PRData): Promise<void> {
    if (!prData.state_hash) {
      // No state hash provided – nothing to validate.
      return;
    }
    const expected = this.computeHash(prData);
    if (prData.state_hash !== expected) {
      throw new SyncDriftError(
        `Sync drift detected: expected ${expected}, got ${prData.state_hash}`
      );
    }
  }
}
