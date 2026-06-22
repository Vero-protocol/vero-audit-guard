/**
 * Tests for RelayerTxScanner
 *
 * Issue #25: feat: relayer unauthorized tx scan
 */

import RelayerTxScanner, {
  normalizeSignerKey,
  RelayerScanOptions,
  RelayerTransaction,
} from "./relayer-scanner";
import {
  RELAYER_PATTERNS,
  RELAYER_PATTERN_IDS,
} from "./relayer-patterns";

// ----------------------------------------------------------------------------
// Test fixtures
// ----------------------------------------------------------------------------

/**
 * Build a Stellar-shaped 56-char StrKey identifier (G + 55 base32 chars,
 * A-Z and 2-7). The seed is stripped of any non-base32 character so
 * labels with spaces / punctuation still collapse to a valid StrKey
 * shape. Used to produce consistent fixtures across tests.
 */
function stellarKey(label: string): string {
  const seed = label.toUpperCase().replace(/[^A-Z2-7]/g, "");
  const padded = (seed + "AAAAA".repeat(20)).slice(0, 55);
  return `G${padded}`;
}

const AUTH_A = stellarKey("alpha");
const AUTH_B = stellarKey("bravo");
const BAD = stellarKey("zeta");
const SAME_HASH =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function makeTx(
  overrides: Partial<RelayerTransaction> = {}
): RelayerTransaction {
  return {
    hash: SAME_HASH,
    sourceAccount: AUTH_A,
    sequenceNumber: "123456789",
    fee: 100,
    signatures: [{ signerKey: AUTH_A, signatureValue: "sigA" }],
    operations: [
      { type: "payment", destination: AUTH_B, amount: "10", asset: "XLM" },
    ],
    ...overrides,
  };
}

function makeOptions(
  overrides: Partial<RelayerScanOptions> = {}
): RelayerScanOptions {
  return {
    authorizedSigners: [AUTH_A, AUTH_B],
    ...overrides,
  };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

describe("RelayerTxScanner", () => {
  let scanner: RelayerTxScanner;

  beforeEach(() => {
    scanner = new RelayerTxScanner();
  });

  describe("Test fixtures", () => {
    it("produces valid Stellar StrKey-shaped identifiers (no embedded whitespace)", () => {
      for (const key of [AUTH_A, AUTH_B, BAD]) {
        expect(key).toMatch(/^G[A-Z2-7]{55}$/);
        expect(key).toHaveLength(56);
        // normalizeSignerKey should be a no-op for valid keys.
        expect(normalizeSignerKey(key)).toBe(key);
      }
    });
  });

  // --------------------------------------------------------------------------
  // Pattern library shape
  // --------------------------------------------------------------------------

  describe("Pattern library", () => {
    it("exposes the documented pattern ids and is frozen", () => {
      expect(RELAYER_PATTERN_IDS).toEqual(
        expect.arrayContaining([
          "DENYLISTED_SIGNER",
          "UNKNOWN_SIGNER",
          "MISSING_SIGNATURES",
          "INSUFFICIENT_SIGNATURES",
          "DUPLICATE_SIGNATURE",
          "MALFORMED_SIGNATURE_ENTRY",
          "INVALID_HASH_FORMAT",
          "REPLAY_DETECTED",
          "UNTRUSTED_SOURCE_ACCOUNT",
          "UNSUPPORTED_OPERATION",
          "FEE_OVER_LIMIT",
        ])
      );
      expect(Object.isFrozen(RELAYER_PATTERNS)).toBe(true);
    });

    it("exposes pattern ids through the class getter", () => {
      expect(scanner.patternIds).toEqual(RELAYER_PATTERN_IDS);
    });
  });

  // --------------------------------------------------------------------------
  // Authorization gate — the universal happy path & default
  // --------------------------------------------------------------------------

  describe("Happy path", () => {
    it("returns AUTHORIZED when an authorized signer signs once", () => {
      const r = scanner.scan(makeTx(), makeOptions());
      expect(r.status).toBe("AUTHORIZED");
      expect(r.findings.length).toBe(0);
    });

    it("returns AUTHORIZED when multiple authorized signers sign", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [
            { signerKey: AUTH_A, signatureValue: "sigA" },
            { signerKey: AUTH_B, signatureValue: "sigB" },
          ],
        }),
        makeOptions()
      );
      expect(r.status).toBe("AUTHORIZED");
      expect(r.uniqueSignerCount).toBe(2);
      expect(r.authorizedSignerCount).toBe(2);
    });

    it("normalises whitespace & case on the allowlist", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [
            { signerKey: `  ${AUTH_A.toLowerCase()}  `, signatureValue: "sigA" },
          ],
        }),
        makeOptions({
          // explicitly lower-case + whitespace
          authorizedSigners: [`  ${AUTH_A.toLowerCase()}  `],
        })
      );
      expect(r.status).toBe("AUTHORIZED");
    });
  });

  // --------------------------------------------------------------------------
  // Signer-allowlist pattern
  // --------------------------------------------------------------------------

  describe("Pattern: UNKNOWN_SIGNER", () => {
    it("flags an unknown signer", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: BAD, signatureValue: "sigZ" }],
        }),
        makeOptions()
      );
      expect(r.status).toBe("UNAUTHORIZED");
      const f = r.findings.find((x) => x.ruleId === "UNKNOWN_SIGNER");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("HIGH");
      expect(f!.details).toEqual({ signerKey: BAD });
    });

    it("does NOT flag when every signer is allowlisted", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: AUTH_A, signatureValue: "sigA" }],
        }),
        makeOptions()
      );
      expect(r.findings.some((f) => f.ruleId === "UNKNOWN_SIGNER")).toBe(
        false
      );
    });
  });

  describe("Pattern: DENYLISTED_SIGNER", () => {
    it("denylist trumps allowlist (overlap case)", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: AUTH_A, signatureValue: "sigA" }],
        }),
        makeOptions({ denylistedSigners: [AUTH_A] })
      );
      expect(r.status).toBe("UNAUTHORIZED");
      const f = r.findings.find((x) => x.ruleId === "DENYLISTED_SIGNER");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("CRITICAL");
    });

    it("fires CRITICAL even if the key is the only signature", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: BAD, signatureValue: "sigZ" }],
        }),
        makeOptions({ denylistedSigners: [BAD] })
      );
      expect(r.findings.some((x) => x.ruleId === "DENYLISTED_SIGNER")).toBe(
        true
      );
      expect(r.denylistedSignerCount).toBe(1);
    });
  });

  // --------------------------------------------------------------------------
  // Multi-sig threshold pattern
  // --------------------------------------------------------------------------

  describe("Pattern: INSUFFICIENT_SIGNATURES", () => {
    it("fires HIGH when threshold > 0 but unique count < threshold", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [
            { signerKey: AUTH_A, signatureValue: "sigA" },
            { signerKey: AUTH_B, signatureValue: "sigB" },
          ],
        }),
        makeOptions({ multiSigThreshold: 3 })
      );
      const f = r.findings.find((x) => x.ruleId === "INSUFFICIENT_SIGNATURES");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("HIGH");
      expect(r.status).toBe("UNAUTHORIZED");
    });

    it("does NOT fire when threshold is met (count-by-unique, not raw)", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [
            // AUTH_A signs twice — should count once toward the threshold.
            { signerKey: AUTH_A, signatureValue: "sigA1" },
            { signerKey: AUTH_A, signatureValue: "sigA2" },
            { signerKey: AUTH_B, signatureValue: "sigB" },
          ],
        }),
        makeOptions({ multiSigThreshold: 2 })
      );
      expect(
        r.findings.some((f) => f.ruleId === "INSUFFICIENT_SIGNATURES")
      ).toBe(false);
    });

    it("does NOT fire when threshold is undefined", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: AUTH_A, signatureValue: "sigA" }],
        }),
        makeOptions({ multiSigThreshold: undefined })
      );
      expect(
        r.findings.some((f) => f.ruleId === "INSUFFICIENT_SIGNATURES")
      ).toBe(false);
    });
  });

  describe("Pattern: MISSING_SIGNATURES", () => {
    it("fires CRITICAL when the envelope has zero signatures", () => {
      const r = scanner.scan(
        makeTx({ signatures: [] }),
        makeOptions({ multiSigThreshold: undefined })
      );
      const f = r.findings.find((x) => x.ruleId === "MISSING_SIGNATURES");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("CRITICAL");
      expect(r.status).toBe("UNAUTHORIZED");
    });
  });

  describe("Pattern: DUPLICATE_SIGNATURE", () => {
    it("flags a duplicate signer but does not authoritatively deny", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [
            { signerKey: AUTH_A, signatureValue: "sigA1" },
            { signerKey: AUTH_A, signatureValue: "sigA2" },
          ],
        }),
        makeOptions()
      );
      const f = r.findings.find((x) => x.ruleId === "DUPLICATE_SIGNATURE");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("LOW");
      expect(f!.status).toBe("REQUIRES_REVIEW");
    });
  });

  describe("Pattern: MALFORMED_SIGNATURE_ENTRY", () => {
    it("flags an empty signerKey", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: "   ", signatureValue: "sigA" }],
        }),
        makeOptions()
      );
      expect(
        r.findings.some((x) => x.ruleId === "MALFORMED_SIGNATURE_ENTRY")
      ).toBe(true);
    });

    it("flags an empty signatureValue", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: AUTH_A, signatureValue: "" }],
        }),
        makeOptions()
      );
      expect(
        r.findings.some((x) => x.ruleId === "MALFORMED_SIGNATURE_ENTRY")
      ).toBe(true);
    });

    it("does not flag clean signature objects", () => {
      const r = scanner.scan(makeTx(), makeOptions());
      expect(
        r.findings.some((x) => x.ruleId === "MALFORMED_SIGNATURE_ENTRY")
      ).toBe(false);
    });
  });

  // --------------------------------------------------------------------------
  // Shape & format patterns
  // --------------------------------------------------------------------------

  describe("Pattern: INVALID_HASH_FORMAT", () => {
    it("flags a hash that is not 64 hex chars", () => {
      const r = scanner.scan(
        makeTx({ hash: "not-a-hex-hash" }),
        makeOptions()
      );
      const f = r.findings.find((x) => x.ruleId === "INVALID_HASH_FORMAT");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("MEDIUM");
      expect(r.status).toBe("REQUIRES_REVIEW");
    });

    it("accepts upper-case hex (Stellar returns it in either case)", () => {
      const r = scanner.scan(
        makeTx({ hash: SAME_HASH.toUpperCase() }),
        makeOptions()
      );
      expect(r.findings.some((x) => x.ruleId === "INVALID_HASH_FORMAT")).toBe(
        false
      );
    });
  });

  describe("Pattern: REPLAY_DETECTED", () => {
    it("flags when hash matches an entry in knownHashes", () => {
      const cache = new Set<string>([SAME_HASH]);
      const r = scanner.scan(makeTx(), makeOptions({ knownHashes: cache }));
      const f = r.findings.find((x) => x.ruleId === "REPLAY_DETECTED");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("CRITICAL");
      expect(r.status).toBe("UNAUTHORIZED");
    });

    it("does not flag when cache is empty", () => {
      const r = scanner.scan(
        makeTx(),
        makeOptions({ knownHashes: new Set() })
      );
      expect(r.findings.some((x) => x.ruleId === "REPLAY_DETECTED")).toBe(
        false
      );
    });
  });

  // --------------------------------------------------------------------------
  // Operator-configurable opt-in patterns
  // --------------------------------------------------------------------------

  describe("Pattern: UNTRUSTED_SOURCE_ACCOUNT", () => {
    it("fires when trustedSourceAccounts is set but source is not in it", () => {
      const r = scanner.scan(
        makeTx({ sourceAccount: BAD }),
        makeOptions({ trustedSourceAccounts: [AUTH_A, AUTH_B] })
      );
      const f = r.findings.find((x) => x.ruleId === "UNTRUSTED_SOURCE_ACCOUNT");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("HIGH");
      expect(r.status).toBe("UNAUTHORIZED");
    });

    it("does not fire when not configured", () => {
      const r = scanner.scan(makeTx({ sourceAccount: BAD }), makeOptions());
      expect(
        r.findings.some((x) => x.ruleId === "UNTRUSTED_SOURCE_ACCOUNT")
      ).toBe(false);
    });
  });

  describe("Pattern: UNSUPPORTED_OPERATION", () => {
    it("fires when an op type is not in the allowlist", () => {
      const r = scanner.scan(
        makeTx({
          operations: [{ type: "manageData" }],
        }),
        makeOptions({ allowedOperationTypes: ["payment"] })
      );
      expect(
        r.findings.some((x) => x.ruleId === "UNSUPPORTED_OPERATION")
      ).toBe(true);
    });

    it("does not fire when allowed list is unset", () => {
      const r = scanner.scan(
        makeTx({
          operations: [{ type: "setOptions" }],
        }),
        makeOptions()
      );
      expect(
        r.findings.some((x) => x.ruleId === "UNSUPPORTED_OPERATION")
      ).toBe(false);
    });
  });

  describe("Pattern: FEE_OVER_LIMIT", () => {
    it("flags when fee/op > ceiling", () => {
      const r = scanner.scan(
        makeTx({
          fee: 1000,
          operations: [{ type: "payment" }, { type: "payment" }], // 500 per op
        }),
        makeOptions({ maxFeePerOp: 100 })
      );
      const f = r.findings.find((x) => x.ruleId === "FEE_OVER_LIMIT");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("MEDIUM");
    });

    it("does not fire when fee/op is within ceiling", () => {
      const r = scanner.scan(
        makeTx({
          fee: 100,
          operations: [{ type: "payment" }],
        }),
        makeOptions({ maxFeePerOp: 100 })
      );
      expect(r.findings.some((x) => x.ruleId === "FEE_OVER_LIMIT")).toBe(
        false
      );
    });

    it("does not fire when ceiling is unset", () => {
      const r = scanner.scan(
        makeTx({ fee: 100000 }),
        makeOptions()
      );
      expect(r.findings.some((x) => x.ruleId === "FEE_OVER_LIMIT")).toBe(
        false
      );
    });

    it("does not fire when the tx has no operations", () => {
      const r = scanner.scan(
        makeTx({ fee: 1000000, operations: [] }),
        makeOptions({ maxFeePerOp: 100 })
      );
      expect(r.findings.some((x) => x.ruleId === "FEE_OVER_LIMIT")).toBe(
        false
      );
    });
  });

  // --------------------------------------------------------------------------
  // Status rollup & bookkeeping
  // --------------------------------------------------------------------------

  describe("Status rollup", () => {
    it("reaches UNAUTHORIZED when at least one rule produces UNAUTHORIZED status", () => {
      const r = scanner.scan(
        makeTx({
          signatures: [{ signerKey: BAD, signatureValue: "sigZ" }],
          hash: "not-hex",
        }),
        makeOptions()
      );
      // Bad signer → UNAUTHORIZED.
      expect(r.status).toBe("UNAUTHORIZED");
      expect(r.unknownSignerCount).toBe(1);
    });

    it("reaches REQUIRES_REVIEW when only HIGH-severity warnings are emitted", () => {
      // Source is not in trusted list — UNAUTHORIZED status from
      // UNTRUSTED_SOURCE_ACCOUNT — so this hits UNauthorized.
      // We'll use a clean tx with INVALID_HASH_FORMAT to force REVIEW.
      const r = scanner.scan(
        makeTx({ hash: "definitely-not-hex" }),
        makeOptions()
      );
      expect(r.status).toBe("REQUIRES_REVIEW");
    });

    it("rolls up multiple findings and reports counts", () => {
      const r = scanner.scan(
        makeTx({
          hash: "not-hex",
          signatures: [{ signerKey: BAD, signatureValue: "sigZ" }],
          operations: [{ type: "manageData" }],
        }),
        makeOptions({ allowedOperationTypes: ["payment"] })
      );
      expect(r.status).toBe("UNAUTHORIZED");
      expect(r.findings.length).toBeGreaterThanOrEqual(3);
      const seen = new Set(r.findings.map((f) => f.ruleId));
      expect(seen.has("UNKNOWN_SIGNER")).toBe(true);
      expect(seen.has("INVALID_HASH_FORMAT")).toBe(true);
      expect(seen.has("UNSUPPORTED_OPERATION")).toBe(true);
    });
  });

  // --------------------------------------------------------------------------
  // Subsetting & error isolation
  // --------------------------------------------------------------------------

  describe("Pattern subsetting", () => {
    it("respects options.patterns and runs only the matching subset", () => {
      const r = scanner.scan(
        makeTx({
          hash: "not-hex",
          signatures: [{ signerKey: BAD, signatureValue: "sigZ" }],
        }),
        makeOptions({ patterns: ["INVALID_HASH_FORMAT"] })
      );
      // UNKNOWN_SIGNER must not have fired because we restricted the run.
      expect(r.findings.some((f) => f.ruleId === "UNKNOWN_SIGNER")).toBe(
        false
      );
      expect(
        r.findings.some((f) => f.ruleId === "INVALID_HASH_FORMAT")
      ).toBe(true);
    });
  });

  describe("Error isolation", () => {
    it("a throwing pattern does not crash the scan", () => {
      const throwingPattern = {
        id: "BROKEN",
        title: "broken",
        description: "broken",
        defaultSeverity: "LOW" as const,
        check: () => {
          throw new Error("intentional");
        },
      };
      const custom = new RelayerTxScanner([throwingPattern]);
      const r = custom.scan(makeTx(), makeOptions());
      // The throw produced no findings but didn't kill the run.
      expect(r.status).toBe("AUTHORIZED");
    });
  });

  // --------------------------------------------------------------------------
  // Structural validation — the guardrails
  // --------------------------------------------------------------------------

  describe("Structural validation (assertTxShape)", () => {
    it("throws on missing hash", () => {
      expect(() =>
        scanner.scan(
          makeTx({ hash: "" }),
          makeOptions()
        )
      ).toThrow(/hash is required/);
    });

    it("throws on non-string hash", () => {
      expect(() =>
        scanner.scan(
          makeTx({ hash: 123 as unknown as string }),
          makeOptions()
        )
      ).toThrow(/hash is required/);
    });

    it("throws on missing sourceAccount", () => {
      expect(() =>
        scanner.scan(makeTx({ sourceAccount: "" }), makeOptions())
      ).toThrow(/sourceAccount is required/);
    });

    it("throws on missing sequenceNumber", () => {
      expect(() =>
        scanner.scan(makeTx({ sequenceNumber: "" }), makeOptions())
      ).toThrow(/sequenceNumber is required/);
    });

    it("throws on non-array signatures", () => {
      expect(() =>
        scanner.scan(
          makeTx({ signatures: undefined as unknown as [] }),
          makeOptions()
        )
      ).toThrow(/signatures must be an array/);
    });

    it("throws when signatures exceed the upper bound", () => {
      const huge = Array.from({ length: 257 }, () => ({
        signerKey: AUTH_A,
        signatureValue: "sig",
      }));
      expect(() =>
        scanner.scan(makeTx({ signatures: huge }), makeOptions())
      ).toThrow(/too many signatures/);
    });
  });

  // --------------------------------------------------------------------------
  // Options validation
  // --------------------------------------------------------------------------

  describe("Options validation", () => {
    it("throws on missing authorizedSigners", () => {
      expect(() =>
        scanner.scan(makeTx(), { denylistedSigners: [] } as never)
      ).toThrow(/authorizedSigners must be a non-empty array/);
    });

    it("throws on empty authorizedSigners after normalization", () => {
      expect(() =>
        scanner.scan(makeTx(), {
          authorizedSigners: ["   ", ""],
        })
      ).toThrow(/contains no usable keys/);
    });

    it("throws when input options is missing", () => {
      expect(() => scanner.scan(makeTx(), null as unknown as never)).toThrow(
        /options must be an object/
      );
    });
  });

  // --------------------------------------------------------------------------
  // Report generation
  // --------------------------------------------------------------------------

  describe("Report generation", () => {
    it("produces a markdown report with all sections populated", () => {
      const r = scanner.scan(
        makeTx({
          hash: "not-hex",
          signatures: [{ signerKey: BAD, signatureValue: "sigZ" }],
        }),
        makeOptions()
      );
      const md = scanner.generateReport(r);
      expect(md).toContain("Relayer Tx Scan");
      expect(md).toContain("UNAUTHORIZED");
      expect(md).toContain("Do not relay");
      expect(md).toContain(SAME_HASH.length > 0 ? "`" : "");
      // Findings appear in the report
      expect(md).toMatch(/UNKNOWN_SIGNER|INVALID_HASH_FORMAT/);
    });

    it("produces a clean AUTHORIZED report", () => {
      const r = scanner.scan(makeTx(), makeOptions());
      const md = scanner.generateReport(r);
      expect(md).toContain("AUTHORIZED");
      expect(md).toContain("No authorization findings");
    });
  });

  // --------------------------------------------------------------------------
  // Helper export
  // --------------------------------------------------------------------------

  describe("normalizeSignerKey helper", () => {
    it("uppercases and trims", () => {
      expect(normalizeSignerKey(`  ${AUTH_A.toLowerCase()}  `)).toBe(AUTH_A);
    });
    it("returns null on empty / non-string", () => {
      expect(normalizeSignerKey("")).toBeNull();
      expect(normalizeSignerKey("   ")).toBeNull();
      expect(normalizeSignerKey(null)).toBeNull();
      expect(normalizeSignerKey(123)).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // Severity sort
  // --------------------------------------------------------------------------

  describe("Severity sort", () => {
    it("sorts findings CRITICAL -> LOW", () => {
      const r = scanner.scan(
        makeTx({
          // INVALID_HASH_FORMAT = MEDIUM
          hash: "not-hex",
          // UNKNOWN_SIGNER = HIGH
          signatures: [{ signerKey: BAD, signatureValue: "sigZ" }],
          // FEE_OVER_LIMIT = MEDIUM
          fee: 1000000,
          operations: [{ type: "payment" }],
        }),
        makeOptions({ maxFeePerOp: 100 })
      );
      const ranks = r.findings.map(
        (f) =>
          ({
            LOW: 1,
            MEDIUM: 2,
            HIGH: 3,
            CRITICAL: 4,
          }[f.severity])
      );
      const sorted = [...ranks].sort((a, b) => b - a);
      expect(ranks).toEqual(sorted);
    });
  });
});
