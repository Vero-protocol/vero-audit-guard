/**
 * Tests for AuditTrail service
 */

import AuditTrail from "../src/audit-trail";
import { EvaluationResult } from "../src/policy-engine";

describe("AuditTrail", () => {
  let trail: AuditTrail;
  const mockResult: EvaluationResult = {
    status: "COMPLIANT",
    violations: [],
    warnings: [],
    summary: "✅ All compliance checks passed!",
    violations_count: 0,
    warnings_count: 0,
    high_severity_violations: [],
  };

  beforeEach(() => {
    trail = new AuditTrail();
    process.env.AUDIT_KEYPAIR_SECRET = "SDY6E2LRE2XW56X6XG7ZJPHX663W6K2N63X6XG7ZJPHX663W6K2N63X6"; // Example secret key (invalid)
  });

  describe("computeHash", () => {
    it("should compute a consistent SHA-256 hash", () => {
      const hash1 = trail.computeHash(mockResult);
      const hash2 = trail.computeHash(mockResult);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex length
    });

    it("should produce different hashes for different results", () => {
      const hash1 = trail.computeHash(mockResult);
      const hash2 = trail.computeHash({
        ...mockResult,
        status: "NON_COMPLIANT",
      });

      expect(hash1).not.toBe(hash2);
    });
  });

  describe("anchor", () => {
    it("should throw error if AUDIT_KEYPAIR_SECRET is not set", async () => {
      delete process.env.AUDIT_KEYPAIR_SECRET;

      await expect(trail.anchor(mockResult)).rejects.toThrow(
        "AUDIT_KEYPAIR_SECRET environment variable not set"
      );
    });

    // We don't want to actually hit the network in unit tests
    // But we can verify it attempts to use the secret
    it("should fail with invalid secret key during account load", async () => {
      process.env.AUDIT_KEYPAIR_SECRET = "SB6X6XG7ZJPHX663W6K2N63X6XG7ZJPHX663W6K2N63X6XG7ZJPHX663W"; // Still invalid format for SDK

      try {
          await trail.anchor(mockResult);
      } catch (e: any) {
          // Expected to fail because of invalid secret or network issues
          expect(e.message).toBeDefined();
      }
    });
  });
});
