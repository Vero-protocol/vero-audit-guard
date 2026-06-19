/**
 * Audit Trail Service
 * Handles on-chain anchoring of audit results on the Stellar ledger
 */

import * as crypto from "crypto";
import {
  Keypair,
  Networks,
  TransactionBuilder,
  Operation,
  Memo,
  Asset,
  Horizon,
} from "@stellar/stellar-sdk";
import { EvaluationResult } from "./policy-engine";

const { Server } = Horizon;

export class AuditTrail {
  private horizonUrl: string;
  private networkPassphrase: string;

  constructor() {
    this.horizonUrl = process.env.HORIZON_URL ?? "https://horizon-testnet.stellar.org";
    this.networkPassphrase = process.env.STELLAR_NETWORK === "mainnet"
      ? Networks.PUBLIC
      : Networks.TESTNET;
  }

  /**
   * Compute SHA-256 hash of evaluation result
   */
  public computeHash(result: EvaluationResult): string {
    const payload = JSON.stringify(result);
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  /**
   * Anchor hash on Stellar ledger
   */
  public async anchor(result: EvaluationResult): Promise<string> {
    const secretKey = process.env.AUDIT_KEYPAIR_SECRET;
    if (!secretKey) {
      throw new Error("AUDIT_KEYPAIR_SECRET environment variable not set");
    }

    const hash = this.computeHash(result);
    const keypair = Keypair.fromSecret(secretKey);
    const server = new Server(this.horizonUrl);

    try {
      const account = await server.loadAccount(keypair.publicKey());

      // Use MEMO_HASH for full 256-bit collision resistance
      // hash is a 64-character hex string (32 bytes)

      const tx = new TransactionBuilder(account, {
        fee: "100",
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(
          Operation.payment({
            destination: keypair.publicKey(), // self-payment as anchor
            asset: Asset.native(),
            amount: "0.0000001",
          })
        )
        .addMemo(Memo.hash(hash))
        .setTimeout(30)
        .build();

      tx.sign(keypair);
      const submitResult = await server.submitTransaction(tx);
      return submitResult.hash;
    } catch (error: any) {
      const message = error.response?.data?.extras?.result_codes?.transaction || error.message;
      throw new Error(`Failed to anchor audit hash on-chain: ${message}`);
    }
  }
}

export default AuditTrail;
