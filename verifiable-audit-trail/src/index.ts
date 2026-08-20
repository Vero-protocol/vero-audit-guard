/**
 * Vero Verifiable Audit Trail
 * Computes SHA-256 of audit report files and submits them as Stellar
 * transaction memos (or Soroban contract calls) for on-chain immutability.
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

export {
  appendIncidentLog,
  logSecurityIncident,
  type IncidentSeverity,
  type IncidentStatus,
  type SecurityIncidentInput,
  type SecurityIncidentLogEntry,
} from "./incident-logger";


const { Server } = Horizon;

const HORIZON_URL = process.env.HORIZON_URL ?? "https://horizon-testnet.stellar.org";
const NETWORK_PASSPHRASE = process.env.STELLAR_NETWORK === "mainnet"
  ? Networks.PUBLIC
  : Networks.TESTNET;

function hashFile(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
}

function memoIdentifierFromSha256Hex(sha256Hex: string): string {
  // Must match `anchorHash()` memo format
  return `vero:${sha256Hex.slice(0, 22)}`;
}

function memoIdentifierFromFile(filePath: string): string {
  const sha256Hex = hashFile(filePath);
  return memoIdentifierFromSha256Hex(sha256Hex);
}

function extractMemoIdentifier(memoText: string | null | undefined): string | null {
  if (!memoText) return null;
  if (!memoText.startsWith("vero:")) return null;
  // Keep full identifier as stored
  return memoText;
}


async function anchorHash(hash: string, label: string): Promise<string> {
  const secretKey = process.env.AUDIT_KEYPAIR_SECRET;
  if (!secretKey) throw new Error("AUDIT_KEYPAIR_SECRET env var not set");

  const keypair = Keypair.fromSecret(secretKey);
  const server = new Server(HORIZON_URL);
  const account = await server.loadAccount(keypair.publicKey());

  // Store hash in tx memo (28 chars max — use first 28 hex chars as identifier)
  const memoText = `vero:${hash.slice(0, 22)}`;

  const tx = new TransactionBuilder(account, {
    fee: "100",
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(
      Operation.payment({
        destination: keypair.publicKey(), // self-payment as anchor
        asset: Asset.native(),
        amount: "0.0000001",
      })
    )
    .addMemo(Memo.text(memoText))
    .setTimeout(30)
    .build();

  tx.sign(keypair);
  const result = await server.submitTransaction(tx);
  return result.hash;
}

export async function auditAndAnchor(reportDir: string): Promise<void> {
  const files = fs.readdirSync(reportDir).filter((f) => f.endsWith(".json"));
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

if (require.main === module) {
  const reportsDir = process.argv[2] ?? "../reports";
  auditAndAnchor(reportsDir).catch((e) => {
    console.error("[audit-trail] Fatal:", e.message);
    process.exit(1);
  });
}
