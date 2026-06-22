/**
 * Relayer Tx Scanner — Pattern Library
 *
 * Issue #25: feat: relayer unauthorized tx scan
 *
 * Each pattern is a small, focused check that takes a `RelayerTransaction`,
 * an internal `RelayerContext`, and a `RelayerScanOptions`, and emits
 * zero or more `RelayerFinding`s.
 *
 * Patterns are pure (no I/O, no global state) and side-effect free, so
 * each one can be unit-tested or composed. Heuristics are intentionally
 * conservative: a finding is something a human reviewer should at least
 * glance at. False positives are cheap (the operator can mark them
 * safe); false negatives on denied signers or replayed envelopes are
 * catastrophic — when in doubt, flag.
 */

import type {
  AuthorizationStatus,
  RelayerFinding,
  RelayerScanOptions,
  RelayerSeverity,
  RelayerTransaction,
} from "./relayer-scanner";

// Re-export the types callers may want to import from either module.
// (AuthorizationStatus is exported to surface the tri-state union to
// callers that compose their own status rollups.)
export type {
  AuthorizationStatus,
  RelayerFinding,
  RelayerScanOptions,
  RelayerSeverity,
  RelayerTransaction,
};

export interface RelayerContext {
  hash: string;
  sourceAccount: string;
  /** Unique, normalised signer keys (deduped). */
  uniqueSignerKeys: string[];
  /** Raw, normalised signer keys in original order (preserves duplicates). */
  signerKeys: string[];
  /** Signers present on the tx that are on the allowlist (not in denylist). */
  authorizedSignerKeys: string[];
  /** Signers present on the tx that are NOT on the allowlist. */
  unknownSignerKeys: string[];
  /** Signers present on the tx that ARE on the denylist. */
  denylistedSignerKeys: string[];
  authorizedSet: Set<string>;
  denylistSet: Set<string>;
  /** True if the hash matches a 64-char lower-case hex Stellar tx hash. */
  hashLooksValid: boolean;
  /** True if the source_account matches StrKey G… shape. */
  sourceLooksValid: boolean;
}

export interface RelayerCheckPattern {
  id: string;
  title: string;
  description: string;
  defaultSeverity: RelayerSeverity;
  /** Reference URLs — surfaced in remediation detail. */
  references?: string[];
  check: (
    tx: RelayerTransaction,
    context: RelayerContext,
    options: RelayerScanOptions
  ) => RelayerFinding[];
}

/** Build a `RelayerFinding` with sensible defaults. */
function makeFinding(
  partial: Omit<RelayerFinding, "details" | "remediation"> & {
    remediation: string;
    details?: Record<string, unknown>;
  }
): RelayerFinding {
  return {
    ruleId: partial.ruleId,
    severity: partial.severity,
    status: partial.status,
    message: partial.message,
    remediation: partial.remediation,
    details: partial.details,
  };
}

// ----------------------------------------------------------------------------
// Pattern #1 — DENYLISTED_SIGNER
// A signer on the allowlist AND the denylist must NOT be relayed. The
// denylist always wins (so an admin who accidentally allows a known-bad
// key still gets a deny).
// ----------------------------------------------------------------------------
const DENYLISTED_SIGNER: RelayerCheckPattern = {
  id: "DENYLISTED_SIGNER",
  title: "Signer is on the denylist",
  description:
    "The transaction envelope contains a signature from a key that is explicitly on the denylist.",
  defaultSeverity: "CRITICAL",
  references: [
    "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
  ],
  check: (_tx, ctx) => {
    if (ctx.denylistedSignerKeys.length === 0) return [];
    return ctx.denylistedSignerKeys.map((signerKey) =>
      makeFinding({
        ruleId: "DENYLISTED_SIGNER",
        severity: "CRITICAL",
        status: "UNAUTHORIZED",
        message: `Signer ${signerKey} is on the denylist — refuse to relay.`,
        remediation:
          "Rotate the compromised or sanctioned key, open an IRP, and audit recent relay activity for this signer.",
        details: { signerKey },
      })
    );
  },
};

// ----------------------------------------------------------------------------
// Pattern #2 — UNKNOWN_SIGNER
// Every signature on the tx must come from an allowlisted key.
// ----------------------------------------------------------------------------
const UNKNOWN_SIGNER: RelayerCheckPattern = {
  id: "UNKNOWN_SIGNER",
  title: "Signer not on allowlist",
  description:
    "The transaction envelope contains a signature whose signer key is not in the authorized allowlist.",
  defaultSeverity: "HIGH",
  references: [
    "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
  ],
  check: (_tx, ctx) => {
    if (ctx.unknownSignerKeys.length === 0) return [];
    return ctx.unknownSignerKeys.map((signerKey) =>
      makeFinding({
        ruleId: "UNKNOWN_SIGNER",
        severity: "HIGH",
        status: "UNAUTHORIZED",
        message: `Signer ${signerKey} is not on the authorized allowlist.`,
        remediation:
          "Add the signer to VERO_RELAYER_AUTHORIZED_SIGNERS (the env var consumed by the audit-guard runtime, see anomaly-detector), or reject the envelope.",
        details: { signerKey },
      })
    );
  },
};

// ----------------------------------------------------------------------------
// Pattern #3 — MISSING_SIGNATURES
// If the envelope has zero signatures at all, we cannot authenticate
// it. CRITICAL — relay is forbidden regardless of any other rules.
// ----------------------------------------------------------------------------
const MISSING_SIGNATURES: RelayerCheckPattern = {
  id: "MISSING_SIGNATURES",
  title: "Transaction has no signatures",
  description:
    "The transaction envelope arrived with an empty signature array — the relayer cannot authenticate it.",
  defaultSeverity: "CRITICAL",
  check: (tx) => {
    if (!Array.isArray(tx.signatures) || tx.signatures.length !== 0) {
      return [];
    }
    return [
      makeFinding({
        ruleId: "MISSING_SIGNATURES",
        severity: "CRITICAL",
        status: "UNAUTHORIZED",
        message:
          "Transaction envelope contains no signatures — refusing to relay.",
        remediation:
          "Investigate where the envelope was constructed; the relayer should never see unsigned transactions.",
      }),
    ];
  },
};

// ----------------------------------------------------------------------------
// Pattern #4 — INSUFFICIENT_SIGNATURES
// The configured multi-sig threshold has not been met. Only fires when
// the operator has set a positive integer threshold.
// ----------------------------------------------------------------------------
const INSUFFICIENT_SIGNATURES: RelayerCheckPattern = {
  id: "INSUFFICIENT_SIGNATURES",
  title: "Multi-sig threshold not met",
  description:
    "The unique signer count on the envelope is below the configured multi-sig threshold.",
  defaultSeverity: "HIGH",
  check: (_tx, ctx, options) => {
    const threshold = options.multiSigThreshold;
    if (typeof threshold !== "number") return [];
    if (ctx.uniqueSignerKeys.length >= threshold) return [];
    return [
      makeFinding({
        ruleId: "INSUFFICIENT_SIGNATURES",
        severity:
          ctx.uniqueSignerKeys.length === 0 ? "CRITICAL" : "HIGH",
        status: "UNAUTHORIZED",
        message: `Multi-sig threshold not met: ${ctx.uniqueSignerKeys.length} unique signer(s) on the envelope, threshold is ${threshold}.`,
        remediation:
          "Require the originating workflow to collect the missing signatures before submitting.",
        details: {
          observed: ctx.uniqueSignerKeys.length,
          threshold,
        },
      }),
    ];
  },
};

// ----------------------------------------------------------------------------
// Pattern #5 — DUPLICATE_SIGNATURE
// The same signer key appears on the envelope more than once. This is
// typically allowed by Stellar (it costs extra fees, but it's not an
// error), so we surface it as a LOW-severity REQUIRES_REVIEW — useful
// for fee analysis and detecting misbehaving SDKs.
// ----------------------------------------------------------------------------
const DUPLICATE_SIGNATURE: RelayerCheckPattern = {
  id: "DUPLICATE_SIGNATURE",
  title: "Duplicate signatures on envelope",
  description:
    "At least one signer contributed more than one signature to the envelope. This is permitted but usually unintended.",
  defaultSeverity: "LOW",
  check: (_tx, ctx) => {
    if (ctx.signerKeys.length <= ctx.uniqueSignerKeys.length) return [];
    const counts = new Map<string, number>();
    for (const k of ctx.signerKeys) {
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    const dupes = [...counts.entries()].filter(([, n]) => n > 1);
    return [
      makeFinding({
        ruleId: "DUPLICATE_SIGNATURE",
        severity: "LOW",
        status: "REQUIRES_REVIEW",
        message: `Envelope has duplicate signatures from: ${dupes
          .map(([k, n]) => `${k} (x${n})`)
          .join(", ")}.`,
        remediation:
          "Audit the originating signer — duplicate signatures waste fees and may indicate a misconfigured SDK.",
        details: { duplicates: Object.fromEntries(dupes) },
      }),
    ];
  },
};

// ----------------------------------------------------------------------------
// Pattern #6 — MALFORMED_SIGNATURE_ENTRY
// A signature object is present but is missing `signerKey` or
// `signatureValue` (or has them as empty strings). The tx cannot be
// reliably authenticated, so we refuse to relay.
// ----------------------------------------------------------------------------
const MALFORMED_SIGNATURE_ENTRY: RelayerCheckPattern = {
  id: "MALFORMED_SIGNATURE_ENTRY",
  title: "Malformed signature entry",
  description:
    "A signature object on the envelope is missing the signerKey or signatureValue (or has an empty value).",
  defaultSeverity: "HIGH",
  check: (tx) => {
    if (!Array.isArray(tx.signatures) || tx.signatures.length === 0) {
      return [];
    }
    const findings: RelayerFinding[] = [];
    tx.signatures.forEach((sig, i) => {
      const reasonParts: string[] = [];
      if (
        typeof sig?.signerKey !== "string" ||
        sig.signerKey.trim().length === 0
      ) {
        reasonParts.push("missing signerKey");
      }
      if (
        typeof sig?.signatureValue !== "string" ||
        sig.signatureValue.trim().length === 0
      ) {
        reasonParts.push("missing signatureValue");
      }
      if (reasonParts.length === 0) return;
      findings.push(
        makeFinding({
          ruleId: "MALFORMED_SIGNATURE_ENTRY",
          severity: "HIGH",
          status: "UNAUTHORIZED",
          message: `Signature #${i + 1} is malformed: ${reasonParts.join(", ")}.`,
          remediation:
            "Inspect the originator — the envelope parser should never produce malformed signature entries.",
          details: { index: i, reasons: reasonParts },
        })
      );
    });
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #7 — INVALID_HASH_FORMAT
// The tx hash doesn't look like a 64-char lower-case hex string.
// Inconclusive (Stellar SDKs may produce upper-case hex) — surface as
// REQUIRES_REVIEW.
// ----------------------------------------------------------------------------
const INVALID_HASH_FORMAT: RelayerCheckPattern = {
  id: "INVALID_HASH_FORMAT",
  title: "Tx hash does not match Stellar shape",
  description:
    "The transaction hash does not match the 64-char lower-case hex shape that Stellar tx hashes use.",
  defaultSeverity: "MEDIUM",
  check: (_tx, ctx) => {
    if (ctx.hashLooksValid) return [];
    return [
      makeFinding({
        ruleId: "INVALID_HASH_FORMAT",
        severity: "MEDIUM",
        status: "REQUIRES_REVIEW",
        message: `Tx hash "${ctx.hash}" does not match the 64-char lower-case hex shape.`,
        remediation:
          "If your SDK returns raw Buffer hex, normalise to lower-case before submitting to the relayer.",
        details: { hash: ctx.hash },
      }),
    ];
  },
};

// ----------------------------------------------------------------------------
// Pattern #8 — REPLAY_DETECTED
// Hash is already in the caller-supplied replay cache. CRITICAL — never
// relay the same envelope twice; in Stellar this can lead to double-spends
// if the source account is shared.
// ----------------------------------------------------------------------------
const REPLAY_DETECTED: RelayerCheckPattern = {
  id: "REPLAY_DETECTED",
  title: "Transaction replay detected",
  description:
    "The transaction hash matches an entry in the caller-supplied replay cache.",
  defaultSeverity: "CRITICAL",
  references: [
    "https://developers.stellar.org/docs/learn/encyclopedia/security/security-tips",
  ],
  check: (_tx, _ctx, options) => {
    const cache = options.knownHashes;
    if (!cache || !(cache instanceof Set) || cache.size === 0) return [];
    return [
      makeFinding({
        ruleId: "REPLAY_DETECTED",
        severity: "CRITICAL",
        status: "UNAUTHORIZED",
        message: "Transaction hash was already seen — refusing to relay.",
        remediation:
          "Drop the cache entry only after the envelope is intentionally resubmitted by an admin.",
      }),
    ];
  },
};

// ----------------------------------------------------------------------------
// Pattern #9 — UNTRUSTED_SOURCE_ACCOUNT
// Operator opted into source_account whitelist via
// `options.trustedSourceAccounts`. CRITICAL — the source account is the
// fee payer so a wrong source can poison accounting.
// ----------------------------------------------------------------------------
const UNTRUSTED_SOURCE_ACCOUNT: RelayerCheckPattern = {
  id: "UNTRUSTED_SOURCE_ACCOUNT",
  title: "Source account is not on the trusted-sources list",
  description:
    "The configuration enabled a trusted source-account allowlist but the transaction's source is not in that set.",
  defaultSeverity: "HIGH",
  check: (_tx, ctx, options) => {
    const trusted = options.trustedSourceAccounts ?? [];
    if (trusted.length === 0) return [];
    const trustedSet = new Set(trusted);
    if (trustedSet.has(ctx.sourceAccount)) return [];
    return [
      makeFinding({
        ruleId: "UNTRUSTED_SOURCE_ACCOUNT",
        severity: "HIGH",
        status: "UNAUTHORIZED",
        message: `Source account ${ctx.sourceAccount} is not on the trusted-sources list.`,
        remediation:
          "If the source is legitimate, add it to VERO_RELAYER_TRUSTED_SOURCES. If not, drop the envelope.",
        details: { sourceAccount: ctx.sourceAccount },
      }),
    ];
  },
};

// ----------------------------------------------------------------------------
// Pattern #10 — UNSUPPORTED_OPERATION
// Operator supplied an allowlist of operation types via
// `options.allowedOperationTypes`. CRITICAL — the relayer should reject
// any operation outside the configured surface.
// ----------------------------------------------------------------------------
const UNSUPPORTED_OPERATION: RelayerCheckPattern = {
  id: "UNSUPPORTED_OPERATION",
  title: "Operation type is not allowed by policy",
  description:
    "The transaction contains an operation whose type is not in the operator-supplied allowlist.",
  defaultSeverity: "HIGH",
  references: [
    "https://developers.stellar.org/docs/learn/encyclopedia/transactions/list-of-operations",
  ],
  check: (tx, _ctx, options) => {
    const allowed = options.allowedOperationTypes ?? [];
    if (allowed.length === 0) return [];
    if (!Array.isArray(tx.operations) || tx.operations.length === 0) {
      return [];
    }
    const allowedSet = new Set(allowed);
    const unsupported = tx.operations
      .map((op, i) => ({ op, i }))
      .filter(({ op }) => !allowedSet.has(op?.type ?? ""));
    if (unsupported.length === 0) return [];
    return unsupported.map(({ op, i }) =>
      makeFinding({
        ruleId: "UNSUPPORTED_OPERATION",
        severity: "HIGH",
        status: "UNAUTHORIZED",
        message: `Operation #${i + 1} has type "${op?.type ?? "<missing>"}" which is not in the allowlist.`,
        remediation:
          "Add the operation type to VERO_RELAYER_ALLOWED_OPERATIONS, or remove the operation from the envelope.",
        details: { index: i, type: op?.type ?? null },
      })
    );
  },
};

// ----------------------------------------------------------------------------
// Pattern #11 — FEE_OVER_LIMIT
// Operator supplied a per-op fee ceiling. REQUIRES_REVIEW (we don't
// want to deny here, but we want a human to confirm before burn).
// ----------------------------------------------------------------------------
const FEE_OVER_LIMIT: RelayerCheckPattern = {
  id: "FEE_OVER_LIMIT",
  title: "Per-operation fee exceeds configured ceiling",
  description:
    "The transaction fee divided by the operation count exceeds the operator-supplied per-operation ceiling.",
  defaultSeverity: "MEDIUM",
  check: (tx, _ctx, options) => {
    const ceiling = options.maxFeePerOp;
    if (typeof ceiling !== "number" || !Number.isFinite(ceiling)) return [];
    if (typeof tx.fee !== "number" || !Number.isFinite(tx.fee)) return [];
    const opCount = Array.isArray(tx.operations) ? tx.operations.length : 0;
    if (opCount === 0) return [];
    const perOp = tx.fee / opCount;
    if (perOp <= ceiling) return [];
    return [
      makeFinding({
        ruleId: "FEE_OVER_LIMIT",
        severity: "MEDIUM",
        status: "REQUIRES_REVIEW",
        message: `Per-operation fee ${perOp} stroops exceeds ceiling ${ceiling} (${opCount} op(s), total fee ${tx.fee}).`,
        remediation:
          "Confirm operational intent (large fees can indicate priority in congestion) before relaying.",
        details: { fee: tx.fee, opCount, perOp, ceiling },
      }),
    ];
  },
};

/** Complete library, exposed for callers that want to iterate. */
export const RELAYER_PATTERNS: readonly RelayerCheckPattern[] =
  Object.freeze([
    DENYLISTED_SIGNER,
    UNKNOWN_SIGNER,
    MISSING_SIGNATURES,
    INSUFFICIENT_SIGNATURES,
    DUPLICATE_SIGNATURE,
    MALFORMED_SIGNATURE_ENTRY,
    INVALID_HASH_FORMAT,
    REPLAY_DETECTED,
    UNTRUSTED_SOURCE_ACCOUNT,
    UNSUPPORTED_OPERATION,
    FEE_OVER_LIMIT,
  ]);

export const RELAYER_PATTERN_IDS = RELAYER_PATTERNS.map((p) => p.id);
