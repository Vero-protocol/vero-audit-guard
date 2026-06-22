/**
 * Relayer Tx Scanner
 *
 * Issue #25: feat: relayer unauthorized tx scan
 *
 * Validates a single relayer-bound Stellar transaction against a
 * configured authorization policy: an allowlist of signers, an optional
 * denylist, an optional multi-sig threshold, an optional list of
 * trusted source accounts, and an optional replay cache. Each pattern
 * contributes zero or more findings; the scanner rolls them up into a
 * single tri-state `AuthorizationStatus`:
 *
 *   - AUTHORIZED      — relay as normal.
 *   - REQUIRES_REVIEW — ambiguous (HIGH/MEDIUM signals); human in the
 *                       loop before relaying.
 *   - UNAUTHORIZED    — hard deny (denylisted signer, replay, hash
 *                       shape, missing signatures, etc.).
 *
 * The scanner is a thin orchestrator — the per-rule logic lives in
 * `relayer-patterns.ts` so rules can be tested and composed.
 */

import { performance } from "perf_hooks";

import {
  RELAYER_PATTERNS,
  RelayerCheckPattern,
  RelayerContext,
} from "./relayer-patterns";

// ----------------------------------------------------------------------------
// Public types
// ----------------------------------------------------------------------------

export type AuthorizationStatus =
  | "AUTHORIZED"
  | "REQUIRES_REVIEW"
  | "UNAUTHORIZED";

export type RelayerSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Minimal fenced representation of a transaction handed to the relayer. */
export interface RelayerTransaction {
  /** Stellar tx hash, hex encoded (64 chars, lower-case recommended). */
  hash: string;
  /** Source account (`G...` StrKey). */
  sourceAccount: string;
  /** Account sequence number as a decimal string (Stellar uses int64). */
  sequenceNumber: string;
  /** Fee in stroops. */
  fee?: number;
  /** Decoded operations on the transaction envelope. */
  operations?: RelayerOperation[];
  /** Signatures attached to the transaction envelope. */
  signatures: RelayerSignature[];
  /** Optional memo (text / hash / id / return). */
  memo?: string;
  /** Optional network identifier (`PUBLIC` / `TESTNET`). */
  network?: string;
}

export interface RelayerOperation {
  type: string; // e.g. "payment", "invokeHostFunction", "manageData"
  destination?: string;
  amount?: string;
  asset?: string;
}

export interface RelayerSignature {
  /** StrKey `G...` public key of the signer. */
  signerKey: string;
  /** Base64 or hex signature value. */
  signatureValue: string;
  /** Optional hint (4-byte suffix commonly used in Stellar envelopes). */
  hint?: string;
}

/**
 * Authorization policy the receiver wants to enforce. At minimum the
 * caller MUST supply `authorizedSigners`. Every other field is opt-in
 * — if left unset the scanner treats that gate as "no constraint".
 */
export interface RelayerScanOptions {
  /** Allowlist of signer keys. Required, non-empty post-normalization. */
  authorizedSigners: string[];
  /** Signers that MUST NOT appear anywhere on the transaction. */
  denylistedSigners?: string[];
  /** Required number of unique signers (multi-sig threshold). */
  multiSigThreshold?: number;
  /** If set, source_account must be in this list. */
  trustedSourceAccounts?: string[];
  /** Hashes seen previously; a match triggers REPLAY_DETECTED. */
  knownHashes?: Set<string>;
  /** Operation types permitted; absent = all permitted. */
  allowedOperationTypes?: string[];
  /** Maximum per-operation fee ceiling (in stroops). */
  maxFeePerOp?: number;
  /** Optional memo regex the tx must match. */
  memoPattern?: RegExp;
  /** Restrict scanning to a subset of pattern ids. */
  patterns?: string[];
}

export interface RelayerFinding {
  ruleId: string;
  severity: RelayerSeverity;
  status: AuthorizationStatus;
  message: string;
  remediation: string;
  /** Optional structured bag (e.g. signerKey, fee). */
  details?: Record<string, unknown>;
}

export interface RelayerScanResult {
  /** Rolled-up status across all patterns. */
  status: AuthorizationStatus;
  txHash: string;
  findings: RelayerFinding[];
  count: number;
  /** Signer counts the IRP runbook references (signal vs. noise). */
  authorizedSignerCount: number;
  uniqueSignerCount: number;
  unknownSignerCount: number;
  denylistedSignerCount: number;
  summary: string;
  scannedAt: string;
  durationMs: number;
  patternIds: string[];
}

// ----------------------------------------------------------------------------
// Internal constants
// ----------------------------------------------------------------------------

/** A Stellar transaction hash is 32 bytes hex-encoded (64 lower-case chars). */
const STELLAR_TX_HASH_RE = /^[0-9a-f]{64}$/;

/** A Stellar StrKey `G...` Ed25519 public key is 56 chars of base32 (A-Z 2-7). */
const STELLAR_ACCOUNT_RE = /^G[A-Z2-7]{55}$/;

/** Upper bound on signatures per tx; defends against pathological inputs. */
const MAX_SIGNATURES = 256;

const STATUS_RANK: Record<AuthorizationStatus, number> = {
  AUTHORIZED: 0,
  REQUIRES_REVIEW: 1,
  UNAUTHORIZED: 2,
};

const SEVERITY_RANK: Record<RelayerSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export class RelayerTxScanner {
  private readonly patterns: RelayerCheckPattern[];

  constructor(
    patterns: RelayerCheckPattern[] = RELAYER_PATTERNS as RelayerCheckPattern[]
  ) {
    this.patterns = patterns;
  }

  /**
   * Scan a single relayer transaction. Throws on a structurally invalid
   * transaction (e.g. missing required fields); pattern-level failures
   * are isolated and reported in the result instead of bubbling up.
   */
  public scan(
    tx: RelayerTransaction,
    options: RelayerScanOptions
  ): RelayerScanResult {
    const start = performance.now();

    this.assertTxShape(tx);
    const normalized = this.normalizeOptions(options);
    const ctx = this.buildContext(tx, normalized);

    const active = normalized.patterns
      ? this.patterns.filter((p) => normalized.patterns!.includes(p.id))
      : this.patterns;

    const findings: RelayerFinding[] = [];
    for (const pattern of active) {
      try {
        const result = pattern.check(tx, ctx, normalized) ?? [];
        for (const f of result) findings.push(f);
      } catch (err) {
        // A buggy pattern must not poison the whole scan — skip and log.
        // eslint-disable-next-line no-console
        console.warn(
          `[RelayerTxScanner] pattern ${pattern.id} threw: ${(err as Error).message}`
        );
      }
    }

    // Sort: CRITICAL first, then by status rank, then by rule id for
    // a stable diff across runs.
    findings.sort((a, b) => {
      const sa = SEVERITY_RANK[a.severity] ?? 0;
      const sb = SEVERITY_RANK[b.severity] ?? 0;
      if (sa !== sb) return sb - sa;
      const ra = STATUS_RANK[a.status] ?? 0;
      const rb = STATUS_RANK[b.status] ?? 0;
      if (ra !== rb) return rb - ra;
      return a.ruleId.localeCompare(b.ruleId);
    });

    const hasHardDeny = findings.some(
      (f) => f.status === "UNAUTHORIZED" || f.severity === "CRITICAL"
    );
    const hasAmbiguous = findings.some(
      (f) => f.severity === "HIGH" || f.severity === "MEDIUM"
    );
    const status: AuthorizationStatus = hasHardDeny
      ? "UNAUTHORIZED"
      : hasAmbiguous
        ? "REQUIRES_REVIEW"
        : "AUTHORIZED";

    const summary =
      status === "AUTHORIZED"
        ? `✅ Transaction cleared all authorization gates (${findings.length} finding(s))`
        : status === "REQUIRES_REVIEW"
          ? `⚠️  Transaction needs human review (${findings.length} finding(s))`
          : `❌ Transaction UNAUTHORIZED (${findings.length} finding(s)) — DO NOT RELAY`;

    return {
      status,
      txHash: tx.hash,
      findings,
      count: findings.length,
      authorizedSignerCount: ctx.authorizedSignerKeys.length,
      uniqueSignerCount: ctx.uniqueSignerKeys.length,
      unknownSignerCount: ctx.unknownSignerKeys.length,
      denylistedSignerCount: ctx.denylistedSignerKeys.length,
      summary,
      scannedAt: new Date().toISOString(),
      durationMs: Math.round(performance.now() - start),
      patternIds: active.map((p) => p.id),
    };
  }

  /** Render a markdown report for humans (PR comments, IRP). */
  public generateReport(result: RelayerScanResult): string {
    const emoji =
      result.status === "AUTHORIZED"
        ? "✅"
        : result.status === "REQUIRES_REVIEW"
          ? "⚠️"
          : "❌";

    let report = `## ${emoji} Relayer Tx Scan\n\n`;
    report += `**Tx hash:** \`${result.txHash}\`\n\n`;
    report += `**Status:** ${result.status}\n\n`;
    report += `**Scanned at:** ${result.scannedAt} (${result.durationMs}ms)\n\n`;
    report += `${result.summary}\n\n`;
    report += `**Patterns evaluated:** ${result.patternIds.length}\n\n`;
    report +=
      `**Signers observed:** ${result.uniqueSignerCount} unique ` +
      `(${result.authorizedSignerCount} authorized, ` +
      `${result.unknownSignerCount} unknown, ` +
      `${result.denylistedSignerCount} denylisted)\n\n`;

    if (result.findings.length === 0) {
      report += `_No authorization findings._\n`;
      return report;
    }

    report += `### Findings\n\n`;
    for (const f of result.findings) {
      report += `- **${f.ruleId}** [${f.severity}] → \`${f.status}\`\n`;
      report += `  ${f.message}\n`;
      if (f.details && Object.keys(f.details).length > 0) {
        report += `  _Details:_ \`${JSON.stringify(f.details)}\`\n`;
      }
      report += `  _Remediation:_ ${f.remediation}\n\n`;
    }

    if (result.status === "UNAUTHORIZED") {
      report += `---\n\n`;
      report +=
        `🚫 **Do not relay.** Quarantine the envelope, alert SecOps, ` +
        `and open an IRP. Refer to \`INCIDENT_RESPONSE.md\` for the P0 runbook.\n`;
    } else if (result.status === "REQUIRES_REVIEW") {
      report += `---\n\n`;
      report +=
        `⚠️  **Human review required** before relaying. Confirm ` +
        `operational intent with the originating team and document the ` +
        `decision in the audit trail.\n`;
    }

    return report;
  }

  /** Patterns this scanner runs (read-only). */
  public get patternIds(): string[] {
    return this.patterns.map((p) => p.id);
  }

  // --------------------------------------------------------------------------
  // Internals
  // --------------------------------------------------------------------------

  /**
   * Throw on structurally invalid input. Patterns only run when this
   * passes; the throw is loud so callers will not relay anyway.
   */
  private assertTxShape(tx: RelayerTransaction): void {
    if (!tx || typeof tx !== "object") {
      throw new Error("RelayerTxScanner.scan: transaction must be an object");
    }
    if (typeof tx.hash !== "string" || tx.hash.length === 0) {
      throw new Error(
        "RelayerTxScanner.scan: transaction.hash is required (string)"
      );
    }
    if (
      typeof tx.sourceAccount !== "string" ||
      tx.sourceAccount.length === 0
    ) {
      throw new Error(
        "RelayerTxScanner.scan: transaction.sourceAccount is required (string)"
      );
    }
    if (
      typeof tx.sequenceNumber !== "string" ||
      tx.sequenceNumber.length === 0
    ) {
      throw new Error(
        "RelayerTxScanner.scan: transaction.sequenceNumber is required (string)"
      );
    }
    if (!Array.isArray(tx.signatures)) {
      throw new Error(
        "RelayerTxScanner.scan: transaction.signatures must be an array"
      );
    }
    if (tx.signatures.length > MAX_SIGNATURES) {
      throw new Error(
        `RelayerTxScanner.scan: too many signatures (${tx.signatures.length} > ${MAX_SIGNATURES})`
      );
    }
  }

  /**
   * Normalize user-supplied options: uppercase + dedupe signer keys,
   * validate types, drop empties. Throws on bad shape so callers fail
   * fast in their own error pipeline.
   */
  private normalizeOptions(
    options: RelayerScanOptions
  ): RelayerScanOptions {
    if (!options || typeof options !== "object") {
      throw new Error("RelayerTxScanner.scan: options must be an object");
    }
    if (
      !Array.isArray(options.authorizedSigners) ||
      options.authorizedSigners.length === 0
    ) {
      throw new Error(
        "RelayerTxScanner.scan: options.authorizedSigners must be a non-empty array"
      );
    }
    const authorized = options.authorizedSigners
      .map(normalizeSignerKey)
      .filter((s): s is string => Boolean(s));
    if (authorized.length === 0) {
      throw new Error(
        "RelayerTxScanner.scan: options.authorizedSigners contains no usable keys"
      );
    }
    const denylisted = (options.denylistedSigners ?? [])
      .map(normalizeSignerKey)
      .filter((s): s is string => Boolean(s));
    const trustedSources = (options.trustedSourceAccounts ?? [])
      .map(normalizeSignerKey)
      .filter((s): s is string => Boolean(s));

    const multiSigThreshold =
      typeof options.multiSigThreshold === "number" &&
      options.multiSigThreshold > 0 &&
      Number.isInteger(options.multiSigThreshold)
        ? options.multiSigThreshold
        : undefined;

    return {
      ...options,
      authorizedSigners: uniqueValues(authorized),
      denylistedSigners: uniqueValues(denylisted),
      trustedSourceAccounts: uniqueValues(trustedSources),
      multiSigThreshold,
    };
  }

  private buildContext(
    tx: RelayerTransaction,
    options: RelayerScanOptions
  ): RelayerContext {
    const authorizedSet = new Set(options.authorizedSigners);
    const denylistSet = new Set(options.denylistedSigners ?? []);

    const signerKeysRaw = (tx.signatures ?? [])
      .map((s) => normalizeSignerKey(s?.signerKey))
      .filter((s): s is string => Boolean(s));
    const uniqueSignerKeys = uniqueValues(signerKeysRaw);

    const denylistedSignerKeys = uniqueSignerKeys.filter((k) =>
      denylistSet.has(k)
    );
    const authorizedSignerKeys = uniqueSignerKeys.filter(
      (k) => authorizedSet.has(k) && !denylistSet.has(k)
    );
    const unknownSignerKeys = uniqueSignerKeys.filter(
      (k) => !authorizedSet.has(k) && !denylistSet.has(k)
    );

    return {
      hash: tx.hash,
      sourceAccount: normalizeSignerKey(tx.sourceAccount) ?? "",
      uniqueSignerKeys,
      signerKeys: signerKeysRaw,
      authorizedSignerKeys,
      unknownSignerKeys,
      denylistedSignerKeys,
      authorizedSet,
      denylistSet,
      hashLooksValid: STELLAR_TX_HASH_RE.test((tx.hash ?? "").toLowerCase()),
      sourceLooksValid: STELLAR_ACCOUNT_RE.test(
        (tx.sourceAccount ?? "").toUpperCase()
      ),
    };
  }
}

export default RelayerTxScanner;

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/**
 * Normalize a signer key: strip whitespace, uppercase (Stellar StrKey
 * is uppercase base32, so this is the canonical form for comparison).
 * Returns null for non-strings or empty input.
 */
export function normalizeSignerKey(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim().toUpperCase();
  return trimmed.length === 0 ? null : trimmed;
}

/** Dedup helper; preserves first-encounter order. */
function uniqueValues<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}
