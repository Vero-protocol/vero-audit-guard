/**
 * Relayer TX Scanner
 *
 * Detects unauthorized foreign signers on relayed transactions.
 * Verifies that every signer on a TX is on a configured allowlist
 * (and not on the denylist), supports multi-sig threshold checks, and
 * emits structured findings with severity so the incident-response
 * pipeline can consume them.
 *
 * Issue #25: feat: relayer unauthorized tx scan
 */

import * as fs from "fs";
import * as path from "path";
import { PolicyViolation } from "./policy-engine";

/**
 * Generic representation of a transaction. The shape is intentionally
 * tolerant because relayers see TXs from many sources (Horizon, JSON-RPC,
 * Soroban, etc.) and not all fields are always present.
 */
export interface TxData {
  /** Hash / ID of the transaction (optional; surfaces in reports if present). */
  txHash?: string;
  /** Account that submitted (source of the TX envelope). */
  sourceAccount: string;
  /** Sequence number of the source account. */
  sequence: string;
  /** List of signer public keys on the TX. */
  signers: string[];
  /** Operations in the TX envelope. Kept as `unknown` to remain chain-agnostic. */
  operations: unknown[];
  /** Optional memo text. */
  memo?: string;
  /** Optional fee string. */
  fee?: string;
  /** ISO-8601 timestamp when the relayer observed the TX. */
  submittedAt?: string;
  /** Origin label of where the TX was seen — e.g. "horizon", "soroban-rpc". */
  source?: string;
}

/**
 * Whitelist configuration. All addresses are matched case-insensitively.
 *
 * - `authorizedSigners` is the allowlist — only these may sign.
 * - `denylist` is the hard ban list — any match is CRITICAL regardless of allowlist.
 * - `multisigThreshold` requires N *authorized* (non-denylisted) signers.
 * - `sourceAccounts` is an optional trusted source-account list (produces warnings only).
 */
export interface WhitelistConfig {
  authorizedSigners: string[];
  denylist: string[];
  multisigThreshold?: number;
  sourceAccounts?: string[];
  /** Path the config was loaded from — surfaces in errors. */
  configPath?: string;
}

/** Result of scanning a single TX. */
export interface TxScanResult {
  status: "AUTHORIZED" | "UNAUTHORIZED" | "REQUIRES_REVIEW";
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
  /** Signers not in allowlist and not in denylist. */
  unauthorizedSigners: string[];
  /** Signers present in the denylist (always CRITICAL). */
  denylistedSigners: string[];
  /** Number of authorized (allow-listed, non-deny-listed) signers. */
  authorizedSignerCount: number;
  summary: string;
  /** ISO-8601 timestamp the scan ran. */
  scanTimestamp: string;
  /** TX hash from the input, if provided. */
  txHash?: string;
}

/** Rule identifiers emitted by the scanner. */
export const RELAYER_RULES = {
  EMPTY_SIGNERS: "EMPTY_SIGNERS",
  DENYLISTED_SIGNER: "DENYLISTED_SIGNER",
  UNAUTHORIZED_SIGNER: "UNAUTHORIZED_SIGNER",
  MULTISIG_THRESHOLD_NOT_MET: "MULTISIG_THRESHOLD_NOT_MET",
  UNVERIFIED_SOURCE_ACCOUNT: "UNVERIFIED_SOURCE_ACCOUNT",
} as const;

/** Environment variables that override config-file values. */
const ENV_AUTHORIZED = "RELAYER_AUTHORIZED_SIGNERS";
const ENV_DENYLIST = "RELAYER_DENYLIST";
const ENV_THRESHOLD = "RELAYER_MULTISIG_THRESHOLD";
const ENV_CONFIG_PATH = "RELAYER_CONFIG";

/** Normalize a single address/signer for case-insensitive comparison. */
function normalizeAddress(s: string | null | undefined): string {
  return (s ?? "").toString().trim().toLowerCase();
}

/**
 * Parse a comma-separated env var into a trimmed, non-empty list.
 * Returns `undefined` if no value is present so the caller can decide
 * whether to fall back to file-based config.
 */
function readCsvEnv(name: string): string[] | undefined {
  const raw = process.env[name];
  if (!raw || raw.trim() === "") return undefined;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function readIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw || raw.trim() === "") return undefined;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

/**
 * The scanner that screens relayed transactions.
 *
 * It is intentionally side-effect-free: `scan()` returns a structured
 * result that downstream consumers (incident-logger, archiver, alerting)
 * can persist. The scanner never throws for "policy violations" — only
 * for malformed configuration.
 */
export class RelayerTxScanner {
  private readonly authorized: Set<string>;
  private readonly denylist: Set<string>;
  private readonly sourceAccounts?: Set<string>;
  private readonly multisigThreshold?: number;
  private readonly configPath?: string;

  constructor(config: WhitelistConfig) {
    this.authorized = new Set(
      (config.authorizedSigners ?? []).map(normalizeAddress).filter(Boolean)
    );
    this.denylist = new Set(
      (config.denylist ?? []).map(normalizeAddress).filter(Boolean)
    );
    this.sourceAccounts =
      config.sourceAccounts && config.sourceAccounts.length > 0
        ? new Set(config.sourceAccounts.map(normalizeAddress).filter(Boolean))
        : undefined;
    if (config.multisigThreshold !== undefined) {
      if (!Number.isInteger(config.multisigThreshold) || config.multisigThreshold < 1) {
        throw new Error(
          `multisigThreshold must be a positive integer; got: ${config.multisigThreshold}`
        );
      }
      this.multisigThreshold = config.multisigThreshold;
    }
    this.configPath = config.configPath;
  }

  /** Build a scanner from a JSON config file with optional env overrides. */
  static fromConfigFile(configPath: string, envOverrides = true): RelayerTxScanner {
    if (!fs.existsSync(configPath)) {
      throw new Error(`Relayer config file not found: ${configPath}`);
    }
    let raw: Partial<WhitelistConfig>;
    try {
      raw = JSON.parse(fs.readFileSync(configPath, "utf-8")) as Partial<WhitelistConfig>;
    } catch (err) {
      throw new Error(
        `Failed to parse relayer config at ${configPath}: ${(err as Error).message}`
      );
    }
    const cfg: WhitelistConfig = {
      authorizedSigners: raw.authorizedSigners ?? [],
      denylist: raw.denylist ?? [],
      multisigThreshold: raw.multisigThreshold,
      sourceAccounts: raw.sourceAccounts,
      configPath,
    };
    if (envOverrides) {
      const auth = readCsvEnv(ENV_AUTHORIZED);
      if (auth) cfg.authorizedSigners = auth;
      const deny = readCsvEnv(ENV_DENYLIST);
      if (deny) cfg.denylist = deny;
      const t = readIntEnv(ENV_THRESHOLD);
      if (t !== undefined) cfg.multisigThreshold = t;
    }
    return new RelayerTxScanner(cfg);
  }

  /**
   * Auto-discover a config from a predictable set of locations:
   *  1. `$RELAYER_CONFIG` env var (if set)
   *  2. `./relayer.config.json`
   *  3. `./config/relayer.config.json`
   *
   * If no file is found, returns a scanner with empty allowlist/denylist —
   * which means all TXs will be flagged as unauthorized. This is the safe
   * default (fail closed).
   */
  static discover(): RelayerTxScanner {
    if (process.env[ENV_CONFIG_PATH]) {
      return RelayerTxScanner.fromConfigFile(process.env[ENV_CONFIG_PATH] as string);
    }    const candidates = [
      path.join(process.cwd(), "relayer.config.json"),
      path.join(process.cwd(), "config", "relayer.config.json"),
    ];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        return RelayerTxScanner.fromConfigFile(candidate, false);
      }
    }
    return new RelayerTxScanner({
      authorizedSigners: [],
      denylist: [],
      configPath: "(default — no config file found; fail-closed mode)",
    });
  }

  /**
   * Scan a TX envelope and return a structured result.
   * Never throws on policy violations; only on deliberately-invalid input
   * (e.g. non-array signer list).
   */
  public scan(tx: TxData): TxScanResult {
    const violations: PolicyViolation[] = [];
    const warnings: PolicyViolation[] = [];

    if (!tx || typeof tx !== "object") {
      throw new Error("RelayerTxScanner.scan: tx must be an object");
    }
    if (!Array.isArray(tx.signers)) {
      throw new Error("RelayerTxScanner.scan: tx.signers must be an array");
    }

    const scanTimestamp = new Date().toISOString();
    const signers = tx.signers
      .map((s) => normalizeAddress(s as string))
      .filter((s) => s.length > 0);

    // Empty signers → CRITICAL. This is the strongest possible signal that
    // something is fundamentally wrong with the TX envelope.
    if (signers.length === 0) {
      violations.push({
        rule: RELAYER_RULES.EMPTY_SIGNERS,
        severity: "CRITICAL",
        message: "❌ Transaction has no signers",
        detail:
          "Every relayed TX must be signed by at least one account; empty signer set is rejected for safety.",
      });
      return {
        status: "UNAUTHORIZED",
        violations,
        warnings,
        unauthorizedSigners: [],
        denylistedSigners: [],
        authorizedSignerCount: 0,
        summary: "❌ Empty signer set rejected",
        scanTimestamp,
        txHash: tx.txHash,
      };
    }

    const denylistedSigners = signers.filter((s) => this.denylist.has(s));
    if (denylistedSigners.length > 0) {
      violations.push({
        rule: RELAYER_RULES.DENYLISTED_SIGNER,
        severity: "CRITICAL",
        message: "🚫 Denylisted signer detected on TX",
        detail: `Signers ${denylistedSigners.join(", ")} are on the denylist. This TX MUST be rejected and the incident logged.`,
      });
    }

    const unauthorizedSigners = signers.filter(
      (s) => !this.denylist.has(s) && !this.authorized.has(s)
    );
    if (unauthorizedSigners.length > 0) {
      violations.push({
        rule: RELAYER_RULES.UNAUTHORIZED_SIGNER,
        severity: "HIGH",
        message: "🚨 Foreign signer detected on TX",
        detail: `Signers ${unauthorizedSigners.join(", ")} are not in the authorised whitelist. This is an access-control violation.`,
      });
    }

    const authorizedSignerCount = signers.filter(
      (s) => !this.denylist.has(s) && this.authorized.has(s)
    ).length;

    // Optional: warn if source account is not in the trusted-list.
    if (this.sourceAccounts && tx.sourceAccount) {
      const sourceLower = normalizeAddress(tx.sourceAccount);
      if (sourceLower && !this.sourceAccounts.has(sourceLower)) {
        warnings.push({
          rule: RELAYER_RULES.UNVERIFIED_SOURCE_ACCOUNT,
          severity: "MEDIUM",
          message: "⚠️  Source account not in trusted-source list",
          detail: `TX source ${tx.sourceAccount} is not in the trusted source accounts. Review before processing.`,
        });
      }
    }

    if (
      this.multisigThreshold !== undefined &&
      authorizedSignerCount < this.multisigThreshold
    ) {
      const detail = `TX has ${authorizedSignerCount} authorized signer(s); requires ${this.multisigThreshold}. Shortfall: ${
        this.multisigThreshold - authorizedSignerCount
      }.`;
      if (violations.length === 0) {
        // No other violation — threshold miss is only a warning.
        warnings.push({
          rule: RELAYER_RULES.MULTISIG_THRESHOLD_NOT_MET,
          severity: "MEDIUM",
          message: "⚠️  Multi-sig threshold not met",
          detail,
        });
      } else {
        // Combined with a foreign signer → multi-sig miss is an access violation.
        violations.push({
          rule: RELAYER_RULES.MULTISIG_THRESHOLD_NOT_MET,
          severity: "HIGH",
          message: "🚨 Multi-sig threshold not met",
          detail,
        });
      }
    }

    const status: TxScanResult["status"] =
      violations.length > 0
        ? "UNAUTHORIZED"
        : warnings.length > 0
          ? "REQUIRES_REVIEW"
          : "AUTHORIZED";

    const summary =
      status === "AUTHORIZED"
        ? "✅ TX authorized: all signers in allowlist"
        : status === "REQUIRES_REVIEW"
          ? `⚠️  TX requires review (${warnings.length} warning(s))`
          : `❌ TX rejected: ${denylistedSigners.length + unauthorizedSigners.length} unauthorized signer(s)`;

    return {
      status,
      violations,
      warnings,
      unauthorizedSigners,
      denylistedSigners,
      authorizedSignerCount,
      summary: summary.trim(),
      scanTimestamp,
      txHash: tx.txHash,
    };
  }

  /** Render a markdown report for human/incident-response consumption. */
  public generateReport(result: TxScanResult): string {
    const emoji =
      result.status === "AUTHORIZED"
        ? "✅"
        : result.status === "REQUIRES_REVIEW"
          ? "⚠️"
          : "❌";
    let report = `## ${emoji} Relayer TX Scan\n\n`;
    if (result.txHash) {
      report += `**TX Hash:** \`${result.txHash}\`\n\n`;
    }
    report += `**Status:** ${result.status}\n\n`;
    report += `**Scanned at:** ${result.scanTimestamp}\n\n`;
    report += `${result.summary}\n\n`;
    if (result.denylistedSigners.length > 0) {
      report += `**Denylisted signers:** ${result.denylistedSigners.join(", ")}\n\n`;
    }
    if (result.unauthorizedSigners.length > 0) {
      report += `**Unauthorized signers:** ${result.unauthorizedSigners.join(", ")}\n\n`;
    }
    report += `**Authorized signer count:** ${result.authorizedSignerCount}\n\n`;
    if (result.violations.length > 0) {
      report += `### ❌ Violations\n\n`;
      for (const v of result.violations) {
        report += `- **${v.rule}** [${v.severity}]\n  ${v.message}\n  _${v.detail}_\n\n`;
      }
    }
    if (result.warnings.length > 0) {
      report += `### ⚠️  Warnings\n\n`;
      for (const w of result.warnings) {
        report += `- **${w.rule}** [${w.severity}]\n  ${w.message}\n  _${w.detail}_\n\n`;
      }
    }
    if (this.configPath) {
      report += `---\n_Config source: \`${this.configPath}\`_\n`;
    }
    return report;
  }

  /** Convenience: read-only access to the allowlist (for tests & diagnostics). */
  public get authorizedSigners(): string[] {
    return Array.from(this.authorized);
  }

  /** Convenience: read-only access to the denylist (for tests & diagnostics). */
  public get denylistSigners(): string[] {
    return Array.from(this.denylist);
  }
}

export default RelayerTxScanner;
