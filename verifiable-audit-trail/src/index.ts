/**
 * Vero Verifiable Audit Trail
 * Computes SHA-256 digests for audit reports, anchors them on Stellar, and
 * verifies local report bytes against a specific on-chain transaction.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import {
  Keypair,
  Networks,
  TransactionBuilder,
  Operation,
  Memo,
  Asset,
  Horizon,
} from "@stellar/stellar-sdk";
import { logSecurityIncident } from "./incident-logger";

export {
  appendIncidentLog,
  logSecurityIncident,
  type IncidentSeverity,
  type IncidentStatus,
  type SecurityIncidentInput,
  type SecurityIncidentLogEntry,
} from "./incident-logger";

const { Server } = Horizon;

const DEFAULT_HORIZON_URL = "https://horizon-testnet.stellar.org";
const DEFAULT_HORIZON_TIMEOUT_MS = 10_000;
const MAX_HORIZON_TIMEOUT_MS = 120_000;
const LEGACY_MEMO_PATTERN = /^vero:[0-9a-f]{22}$/;
const TRANSACTION_HASH_PATTERN = /^[0-9a-f]{64}$/i;

export type VerificationProtocol = "memo-hash" | "legacy-memo-text";
export type VerificationFailureReason =
  | "ANCHOR_NOT_FOUND"
  | "TRANSACTION_FAILED"
  | "TRANSACTION_HASH_MISMATCH"
  | "ANCHOR_ACCOUNT_MISMATCH"
  | "MEMO_MISSING_OR_INVALID"
  | "HASH_MISMATCH"
  | "LEGACY_MEMO_DISABLED"
  | "REPORT_CHANGED_DURING_VERIFICATION";

export interface HorizonTransactionRecord {
  hash: string;
  successful: boolean;
  source_account: string;
  memo_type: string;
  memo?: string;
}

export interface HorizonTransactionLookup {
  transactions(): {
    transaction(transactionHash: string): {
      call(): Promise<HorizonTransactionRecord>;
    };
  };
}

export interface VerifyReportOptions {
  reportPath: string;
  transactionHash: string;
  expectedAnchorAccount: string;
  allowLegacyMemoText?: boolean;
  lookupTimeoutMs?: number;
  server?: HorizonTransactionLookup;
}

export interface VerificationSuccess {
  verified: true;
  protocol: VerificationProtocol;
  reportPath: string;
  transactionHash: string;
  anchorAccount: string;
  localHash: string;
}

export interface VerificationFailure {
  verified: false;
  reason: VerificationFailureReason;
  detail: string;
  reportPath: string;
  transactionHash: string;
  anchorAccount: string;
  localHash: string;
  anchoredHash?: string;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;

export function hashFile(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
}

export function legacyMemoIdentifierFromSha256Hex(sha256Hex: string): string {
  assertSha256Hex(sha256Hex);
  return `vero:${sha256Hex.slice(0, 22)}`;
}

export function decodeMemoHash(memo: string | null | undefined): string | null {
  if (!memo || !/^[A-Za-z0-9+/]{43}=$/.test(memo)) {
    return null;
  }

  const bytes = Buffer.from(memo, "base64");
  if (bytes.length !== 32 || bytes.toString("base64") !== memo) {
    return null;
  }

  return bytes.toString("hex");
}

function assertSha256Hex(hash: string): void {
  if (!TRANSACTION_HASH_PATTERN.test(hash)) {
    throw new Error("SHA-256 hash must be exactly 64 hexadecimal characters");
  }
}

function normalizeTransactionHash(transactionHash: string): string {
  if (!TRANSACTION_HASH_PATTERN.test(transactionHash)) {
    throw new Error("Transaction hash must be exactly 64 hexadecimal characters");
  }
  return transactionHash.toLowerCase();
}

function normalizeAnchorAccount(account: string): string {
  try {
    return Keypair.fromPublicKey(account).publicKey();
  } catch {
    throw new Error("Anchor account must be a valid Stellar public key");
  }
}

function resolveHorizonUrl(): string {
  return process.env.HORIZON_URL ?? DEFAULT_HORIZON_URL;
}

function resolveHorizonTimeoutMs(override?: number): number {
  const rawValue = override ?? process.env.HORIZON_TIMEOUT_MS ?? DEFAULT_HORIZON_TIMEOUT_MS;
  const timeoutMs = typeof rawValue === "number" ? rawValue : Number(rawValue);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_HORIZON_TIMEOUT_MS) {
    throw new Error(
      `HORIZON_TIMEOUT_MS must be an integer between 1 and ${MAX_HORIZON_TIMEOUT_MS}`
    );
  }
  return timeoutMs;
}

function horizonTransactionUrl(transactionHash: string): string {
  let horizonUrl: URL;
  try {
    horizonUrl = new URL(resolveHorizonUrl());
  } catch {
    throw new Error("HORIZON_URL must be a valid absolute URL");
  }

  if (horizonUrl.protocol !== "https:") {
    throw new Error("HORIZON_URL must use HTTPS");
  }
  if (horizonUrl.username || horizonUrl.password) {
    throw new Error("HORIZON_URL must not include credentials");
  }

  horizonUrl.pathname = `${horizonUrl.pathname.replace(/\/+$/, "")}/transactions/${transactionHash}`;
  horizonUrl.search = "";
  horizonUrl.hash = "";
  return horizonUrl.toString();
}

function resolveNetworkPassphrase(): string {
  const network = process.env.STELLAR_NETWORK ?? "testnet";
  if (network === "mainnet") return Networks.PUBLIC;
  if (network === "testnet") return Networks.TESTNET;
  throw new Error('STELLAR_NETWORK must be either "testnet" or "mainnet"');
}

function isNotFoundError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;

  const candidate = error as {
    response?: { status?: number };
    status?: number;
  };
  return candidate.response?.status === 404 || candidate.status === 404;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function hashesMatch(expectedHex: string, actualHex: string): boolean {
  const expected = Buffer.from(expectedHex, "hex");
  const actual = Buffer.from(actualHex, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

async function lookupHorizonTransaction(
  transactionHash: string,
  timeoutMs: number,
  server?: HorizonTransactionLookup
): Promise<HorizonTransactionRecord> {
  if (server) {
    return withTimeout(
      server.transactions().transaction(transactionHash).call(),
      timeoutMs
    );
  }

  const response = await Horizon.AxiosClient.get<HorizonTransactionRecord>(
    horizonTransactionUrl(transactionHash),
    {
      timeout: timeoutMs,
      signal: AbortSignal.timeout(timeoutMs),
      maxContentLength: 1_000_000,
      maxBodyLength: 1_000_000,
    }
  );
  return response.data;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Horizon transaction lookup timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

function verificationFailure(
  options: VerifyReportOptions,
  localHash: string,
  transactionHash: string,
  anchorAccount: string,
  reason: VerificationFailureReason,
  detail: string,
  anchoredHash?: string
): VerificationFailure {
  return {
    verified: false,
    reason,
    detail,
    reportPath: options.reportPath,
    transactionHash,
    anchorAccount,
    localHash,
    ...(anchoredHash ? { anchoredHash } : {}),
  };
}

export async function verifyReport(options: VerifyReportOptions): Promise<VerificationResult> {
  const transactionHash = normalizeTransactionHash(options.transactionHash);
  const anchorAccount = normalizeAnchorAccount(options.expectedAnchorAccount);
  const initialLocalHash = hashFile(options.reportPath);
  const timeoutMs = resolveHorizonTimeoutMs(options.lookupTimeoutMs);

  let transaction: HorizonTransactionRecord;
  try {
    transaction = await lookupHorizonTransaction(transactionHash, timeoutMs, options.server);
  } catch (error) {
    if (isNotFoundError(error)) {
      return verificationFailure(
        options,
        initialLocalHash,
        transactionHash,
        anchorAccount,
        "ANCHOR_NOT_FOUND",
        `No Stellar transaction was found for ${transactionHash}`
      );
    }
    throw new Error(`Horizon transaction lookup failed: ${errorMessage(error)}`);
  }

  const localHash = hashFile(options.reportPath);
  if (!hashesMatch(initialLocalHash, localHash)) {
    return verificationFailure(
      options,
      localHash,
      transactionHash,
      anchorAccount,
      "REPORT_CHANGED_DURING_VERIFICATION",
      "The local report changed while Horizon verification was in progress"
    );
  }

  if (transaction.successful !== true) {
    return verificationFailure(
      options,
      localHash,
      transactionHash,
      anchorAccount,
      "TRANSACTION_FAILED",
      "The referenced Stellar transaction was not successful"
    );
  }

  if (
    !TRANSACTION_HASH_PATTERN.test(transaction.hash) ||
    transaction.hash.toLowerCase() !== transactionHash
  ) {
    return verificationFailure(
      options,
      localHash,
      transactionHash,
      anchorAccount,
      "TRANSACTION_HASH_MISMATCH",
      "Horizon returned a transaction hash different from the requested hash"
    );
  }

  if (transaction.source_account !== anchorAccount) {
    return verificationFailure(
      options,
      localHash,
      transactionHash,
      anchorAccount,
      "ANCHOR_ACCOUNT_MISMATCH",
      `Transaction source ${transaction.source_account} does not match the trusted anchor account`
    );
  }

  if (transaction.memo_type === "hash") {
    const anchoredHash = decodeMemoHash(transaction.memo);
    if (!anchoredHash) {
      return verificationFailure(
        options,
        localHash,
        transactionHash,
        anchorAccount,
        "MEMO_MISSING_OR_INVALID",
        "The transaction MEMO_HASH is missing or is not a canonical 32-byte Base64 value"
      );
    }

    if (!hashesMatch(localHash, anchoredHash)) {
      return verificationFailure(
        options,
        localHash,
        transactionHash,
        anchorAccount,
        "HASH_MISMATCH",
        "The local report SHA-256 does not match the anchored MEMO_HASH",
        anchoredHash
      );
    }

    return {
      verified: true,
      protocol: "memo-hash",
      reportPath: options.reportPath,
      transactionHash,
      anchorAccount,
      localHash,
    };
  }

  if (transaction.memo_type === "text" && LEGACY_MEMO_PATTERN.test(transaction.memo ?? "")) {
    if (!options.allowLegacyMemoText) {
      return verificationFailure(
        options,
        localHash,
        transactionHash,
        anchorAccount,
        "LEGACY_MEMO_DISABLED",
        "The transaction uses a truncated legacy MEMO_TEXT; opt in explicitly to verify it"
      );
    }

    const expectedLegacyMemo = legacyMemoIdentifierFromSha256Hex(localHash);
    if (transaction.memo !== expectedLegacyMemo) {
      return verificationFailure(
        options,
        localHash,
        transactionHash,
        anchorAccount,
        "HASH_MISMATCH",
        "The local report hash prefix does not match the legacy anchored memo"
      );
    }

    return {
      verified: true,
      protocol: "legacy-memo-text",
      reportPath: options.reportPath,
      transactionHash,
      anchorAccount,
      localHash,
    };
  }

  return verificationFailure(
    options,
    localHash,
    transactionHash,
    anchorAccount,
    "MEMO_MISSING_OR_INVALID",
    `Unsupported or malformed transaction memo type: ${transaction.memo_type}`
  );
}

export async function anchorHash(hash: string, _label: string): Promise<string> {
  assertSha256Hex(hash);
  const secretKey = process.env.AUDIT_KEYPAIR_SECRET;
  if (!secretKey) throw new Error("AUDIT_KEYPAIR_SECRET env var not set");

  const keypair = Keypair.fromSecret(secretKey);
  const configuredAnchorAccount = process.env.AUDIT_ANCHOR_ACCOUNT;
  if (configuredAnchorAccount) {
    const expectedAccount = normalizeAnchorAccount(configuredAnchorAccount);
    if (expectedAccount !== keypair.publicKey()) {
      throw new Error("AUDIT_ANCHOR_ACCOUNT does not match AUDIT_KEYPAIR_SECRET");
    }
  }

  const server = new Server(resolveHorizonUrl());
  const account = await server.loadAccount(keypair.publicKey());
  const tx = new TransactionBuilder(account, {
    fee: "100",
    networkPassphrase: resolveNetworkPassphrase(),
  })
    .addOperation(
      Operation.payment({
        destination: keypair.publicKey(),
        asset: Asset.native(),
        amount: "0.0000001",
      })
    )
    .addMemo(Memo.hash(hash))
    .setTimeout(30)
    .build();

  tx.sign(keypair);
  const result = await server.submitTransaction(tx);
  return result.hash;
}

export async function auditAndAnchor(reportDir: string): Promise<void> {
  const files = fs.readdirSync(reportDir).filter((file) => file.endsWith(".json"));
  if (files.length === 0) {
    console.log("[audit-trail] No reports to anchor.");
    return;
  }

  for (const file of files) {
    const fullPath = path.join(reportDir, file);
    const hash = hashFile(fullPath);
    console.log(`[audit-trail] ${file} → SHA-256: ${hash}`);

    if (process.env.AUDIT_KEYPAIR_SECRET) {
      const txHash = await anchorHash(hash, file);
      console.log(`[audit-trail] Anchored on-chain. TX: ${txHash}`);
    } else {
      console.log("[audit-trail] Dry-run mode (no AUDIT_KEYPAIR_SECRET). Hash computed only.");
    }
  }
}

interface VerifyCliArguments {
  reportPath: string;
  transactionHash: string;
  anchorAccount: string;
  allowLegacyMemoText: boolean;
}

export interface RunCliDependencies {
  server?: HorizonTransactionLookup;
  lookupTimeoutMs?: number;
}

function usage(): string {
  return [
    "Usage:",
    "  node dist/index.js anchor <reports-directory>",
    "  node dist/index.js verify <report-file> --tx <transaction-hash> [--account <G...>] [--allow-legacy-memo-text]",
    "  node dist/index.js <reports-directory>  # backward-compatible anchor mode",
  ].join("\n");
}

function parseVerifyArguments(args: string[]): VerifyCliArguments {
  const reportPath = args[0];
  if (!reportPath || reportPath.startsWith("--")) {
    throw new Error("verify requires a report file");
  }

  let transactionHash: string | undefined;
  let anchorAccount: string | undefined;
  let allowLegacyMemoText = false;

  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--allow-legacy-memo-text") {
      if (allowLegacyMemoText) throw new Error("--allow-legacy-memo-text was provided more than once");
      allowLegacyMemoText = true;
      continue;
    }

    if (argument === "--tx" || argument === "--account") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${argument} requires a value`);
      }
      if (argument === "--tx") {
        if (transactionHash) throw new Error("--tx was provided more than once");
        transactionHash = value;
      } else {
        if (anchorAccount) throw new Error("--account was provided more than once");
        anchorAccount = value;
      }
      index += 1;
      continue;
    }

    throw new Error(`Unknown verify argument: ${argument}`);
  }

  if (!transactionHash) throw new Error("verify requires --tx <transaction-hash>");
  const configuredAnchorAccount = process.env.AUDIT_ANCHOR_ACCOUNT;
  if (anchorAccount && configuredAnchorAccount) {
    const cliAccount = normalizeAnchorAccount(anchorAccount);
    const environmentAccount = normalizeAnchorAccount(configuredAnchorAccount);
    if (cliAccount !== environmentAccount) {
      throw new Error("--account does not match the configured AUDIT_ANCHOR_ACCOUNT");
    }
  }

  const expectedAnchorAccount = anchorAccount ?? configuredAnchorAccount;
  if (!expectedAnchorAccount) {
    throw new Error("verify requires --account <G...> or AUDIT_ANCHOR_ACCOUNT");
  }

  return {
    reportPath,
    transactionHash,
    anchorAccount: expectedAnchorAccount,
    allowLegacyMemoText,
  };
}

function emitIntegrityIncident(result: VerificationFailure): void {
  const incident = logSecurityIncident({
    title: `Audit trail verification failed: ${result.reason}`,
    detail: result.detail,
    severity: "CRITICAL",
    source: "verifiable-audit-trail",
    metadata: {
      report: path.basename(result.reportPath),
      transactionHash: result.transactionHash,
      anchorAccount: result.anchorAccount,
      localHash: result.localHash,
      ...(result.anchoredHash ? { anchoredHash: result.anchoredHash } : {}),
    },
  });
  console.error(`[audit-trail] Integrity incident: ${JSON.stringify(incident)}`);
}

export async function runCli(
  args: string[] = process.argv.slice(2),
  dependencies: RunCliDependencies = {}
): Promise<number> {
  try {
    if (args[0] === "anchor") {
      if (args.length !== 2) throw new Error("anchor requires exactly one reports directory");
      await auditAndAnchor(args[1]);
      return 0;
    }

    if (args[0] === "verify") {
      const parsed = parseVerifyArguments(args.slice(1));
      const result = await verifyReport({
        reportPath: parsed.reportPath,
        transactionHash: parsed.transactionHash,
        expectedAnchorAccount: parsed.anchorAccount,
        allowLegacyMemoText: parsed.allowLegacyMemoText,
        lookupTimeoutMs: dependencies.lookupTimeoutMs,
        server: dependencies.server,
      });

      if (!result.verified) {
        emitIntegrityIncident(result);
        return 2;
      }

      const legacyWarning = result.protocol === "legacy-memo-text"
        ? " WARNING: verified using the truncated legacy MEMO_TEXT format."
        : "";
      console.log(
        `[audit-trail] VERIFIED: ${path.basename(result.reportPath)} matches ${result.transactionHash}.${legacyWarning}`
      );
      return 0;
    }

    if (args.length <= 1) {
      await auditAndAnchor(args[0] ?? "../reports");
      return 0;
    }

    throw new Error("Unknown command or too many arguments");
  } catch (error) {
    console.error(`[audit-trail] Fatal: ${errorMessage(error)}`);
    console.error(usage());
    return 1;
  }
}

if (require.main === module) {
  runCli().then((exitCode) => {
    process.exitCode = exitCode;
  });
}
