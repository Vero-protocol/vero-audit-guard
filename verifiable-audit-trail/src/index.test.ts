import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Account, Horizon, Keypair } from "@stellar/stellar-sdk";

jest.mock("@stellar/stellar-sdk", () => {
  const actual = jest.requireActual("@stellar/stellar-sdk");
  return {
    ...actual,
    Horizon: {
      ...actual.Horizon,
      Server: jest.fn(),
      AxiosClient: { get: jest.fn() },
    },
  };
});

import {
  auditAndAnchor,
  decodeMemoHash,
  hashFile,
  legacyMemoIdentifierFromSha256Hex,
  runCli,
  verifyReport,
} from "./index";

const MockServer = Horizon.Server as unknown as jest.Mock;
const MockAxiosGet = Horizon.AxiosClient.get as unknown as jest.Mock;
const TRANSACTION_HASH = "ab".repeat(32);

describe("verifiable audit trail", () => {
  const originalEnv = process.env;
  let reportDir: string;
  let reportPath: string;
  let anchorKeypair: Keypair;
  let loadAccount: jest.Mock;
  let submitTransaction: jest.Mock;
  let lookupTransaction: jest.Mock;
  let callTransaction: jest.Mock;

  function memoHashFor(filePath: string): string {
    return Buffer.from(hashFile(filePath), "hex").toString("base64");
  }

  function transactionRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      hash: TRANSACTION_HASH,
      successful: true,
      source_account: anchorKeypair.publicKey(),
      memo_type: "hash",
      memo: memoHashFor(reportPath),
      ...overrides,
    };
  }

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.AUDIT_KEYPAIR_SECRET;
    delete process.env.AUDIT_ANCHOR_ACCOUNT;
    delete process.env.HORIZON_URL;
    delete process.env.STELLAR_NETWORK;

    reportDir = fs.mkdtempSync(path.join(os.tmpdir(), "vero-audit-trail-test-"));
    reportPath = path.join(reportDir, "latest.json");
    fs.writeFileSync(reportPath, JSON.stringify({ status: "ok" }), "utf8");
    anchorKeypair = Keypair.random();

    loadAccount = jest.fn();
    submitTransaction = jest.fn().mockResolvedValue({ hash: TRANSACTION_HASH });
    callTransaction = jest.fn();
    lookupTransaction = jest.fn().mockReturnValue({ call: callTransaction });
    MockAxiosGet.mockImplementation(async () => ({ data: await callTransaction() }));
    MockServer.mockImplementation(() => ({
      loadAccount,
      submitTransaction,
      transactions: jest.fn().mockReturnValue({ transaction: lookupTransaction }),
    }));
  });

  afterEach(() => {
    process.env = originalEnv;
    fs.rmSync(reportDir, { recursive: true, force: true });
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  describe("anchoring", () => {
    it("computes report hashes in dry-run mode without contacting Horizon", async () => {
      await auditAndAnchor(reportDir);

      expect(MockServer).not.toHaveBeenCalled();
      expect(loadAccount).not.toHaveBeenCalled();
      expect(submitTransaction).not.toHaveBeenCalled();
    });

    it("anchors the complete SHA-256 digest as MEMO_HASH", async () => {
      const account = new Account(anchorKeypair.publicKey(), "1");
      process.env.AUDIT_KEYPAIR_SECRET = anchorKeypair.secret();
      process.env.AUDIT_ANCHOR_ACCOUNT = anchorKeypair.publicKey();
      loadAccount.mockResolvedValue(account);

      await auditAndAnchor(reportDir);

      expect(MockServer).toHaveBeenCalledWith("https://horizon-testnet.stellar.org");
      expect(loadAccount).toHaveBeenCalledWith(anchorKeypair.publicKey());
      expect(submitTransaction).toHaveBeenCalledTimes(1);
      const submittedTransaction = submitTransaction.mock.calls[0][0];
      expect(submittedTransaction.memo.type).toBe("hash");
      expect(submittedTransaction.memo.value).toHaveLength(32);
      expect(submittedTransaction.memo.value.toString("hex")).toBe(hashFile(reportPath));
    });

    it("rejects an anchor account that does not match the signing secret", async () => {
      process.env.AUDIT_KEYPAIR_SECRET = anchorKeypair.secret();
      process.env.AUDIT_ANCHOR_ACCOUNT = Keypair.random().publicKey();

      await expect(auditAndAnchor(reportDir)).rejects.toThrow(
        "AUDIT_ANCHOR_ACCOUNT does not match AUDIT_KEYPAIR_SECRET"
      );
      expect(loadAccount).not.toHaveBeenCalled();
      expect(submitTransaction).not.toHaveBeenCalled();
    });

    it("ignores non-JSON files and returns for an empty report directory", async () => {
      fs.rmSync(reportPath);
      fs.writeFileSync(path.join(reportDir, "README.txt"), "ignored", "utf8");

      await expect(auditAndAnchor(reportDir)).resolves.toBeUndefined();

      expect(MockServer).not.toHaveBeenCalled();
    });
  });

  describe("verification", () => {
    it("verifies a matching local report against its full anchored hash", async () => {
      callTransaction.mockResolvedValue(transactionRecord());

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH.toUpperCase(),
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(MockAxiosGet).toHaveBeenCalledWith(
        `https://horizon-testnet.stellar.org/transactions/${TRANSACTION_HASH}`,
        expect.objectContaining({
          timeout: 10_000,
          signal: expect.any(AbortSignal),
        })
      );
      expect(result).toMatchObject({
        verified: true,
        protocol: "memo-hash",
        localHash: hashFile(reportPath),
      });
    });

    it("normalizes trailing slashes in a configured Horizon base URL", async () => {
      process.env.HORIZON_URL = "https://horizon.example/base///?ignored=true#ignored";
      callTransaction.mockResolvedValue(transactionRecord());

      await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(MockAxiosGet).toHaveBeenCalledWith(
        `https://horizon.example/base/transactions/${TRANSACTION_HASH}`,
        expect.any(Object)
      );
    });

    it("detects tampering when the local report no longer matches the anchor", async () => {
      const anchoredMemo = memoHashFor(reportPath);
      fs.writeFileSync(reportPath, JSON.stringify({ status: "tampered" }), "utf8");
      callTransaction.mockResolvedValue(transactionRecord({ memo: anchoredMemo }));

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(result).toMatchObject({
        verified: false,
        reason: "HASH_MISMATCH",
      });
    });

    it("fails when the referenced anchor does not exist", async () => {
      callTransaction.mockRejectedValue({ response: { status: 404 } });

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(result).toMatchObject({ verified: false, reason: "ANCHOR_NOT_FOUND" });
    });

    it("rejects a matching memo from an untrusted source account", async () => {
      callTransaction.mockResolvedValue(
        transactionRecord({ source_account: Keypair.random().publicKey() })
      );

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(result).toMatchObject({
        verified: false,
        reason: "ANCHOR_ACCOUNT_MISMATCH",
      });
    });

    it.each([
      [{ successful: false }, "TRANSACTION_FAILED"],
      [{ hash: "cd".repeat(32) }, "TRANSACTION_HASH_MISMATCH"],
      [{ memo: "not-base64" }, "MEMO_MISSING_OR_INVALID"],
      [{ memo_type: "id", memo: "42" }, "MEMO_MISSING_OR_INVALID"],
    ])("rejects invalid transaction evidence %#", async (overrides, expectedReason) => {
      callTransaction.mockResolvedValue(transactionRecord(overrides));

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(result).toMatchObject({ verified: false, reason: expectedReason });
    });

    it("fails closed on Horizon operational errors without labelling them as tampering", async () => {
      callTransaction.mockRejectedValue(new Error("gateway timeout"));

      await expect(
        verifyReport({
          reportPath,
          transactionHash: TRANSACTION_HASH,
          expectedAnchorAccount: anchorKeypair.publicKey(),
        })
      ).rejects.toThrow("Horizon transaction lookup failed: gateway timeout");
    });

    it("requires explicit opt-in before accepting a matching legacy memo", async () => {
      callTransaction.mockResolvedValue(
        transactionRecord({
          memo_type: "text",
          memo: legacyMemoIdentifierFromSha256Hex(hashFile(reportPath)),
        })
      );

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(result).toMatchObject({ verified: false, reason: "LEGACY_MEMO_DISABLED" });
    });

    it("verifies a legacy memo only when explicitly enabled", async () => {
      callTransaction.mockResolvedValue(
        transactionRecord({
          memo_type: "text",
          memo: legacyMemoIdentifierFromSha256Hex(hashFile(reportPath)),
        })
      );

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
        allowLegacyMemoText: true,
      });

      expect(result).toMatchObject({ verified: true, protocol: "legacy-memo-text" });
    });

    it("rejects malformed legacy memos even when legacy support is enabled", async () => {
      callTransaction.mockResolvedValue(
        transactionRecord({ memo_type: "text", memo: "vero:not-a-valid-hash" })
      );

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
        allowLegacyMemoText: true,
      });

      expect(result).toMatchObject({ verified: false, reason: "MEMO_MISSING_OR_INVALID" });
    });

    it("rejects non-boolean successful values from remote responses", async () => {
      callTransaction.mockResolvedValue(transactionRecord({ successful: "false" }));

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(result).toMatchObject({ verified: false, reason: "TRANSACTION_FAILED" });
    });

    it("detects when a report changes while Horizon lookup is in progress", async () => {
      const anchoredMemo = memoHashFor(reportPath);
      callTransaction.mockImplementation(async () => {
        fs.writeFileSync(reportPath, "changed-during-verification", "utf8");
        return transactionRecord({ memo: anchoredMemo });
      });

      const result = await verifyReport({
        reportPath,
        transactionHash: TRANSACTION_HASH,
        expectedAnchorAccount: anchorKeypair.publicKey(),
      });

      expect(result).toMatchObject({
        verified: false,
        reason: "REPORT_CHANGED_DURING_VERIFICATION",
      });
    });

    it("bounds injected Horizon lookups with an operational timeout", async () => {
      callTransaction.mockReturnValue(new Promise(() => undefined));
      const server = {
        transactions: () => ({ transaction: lookupTransaction }),
      };

      await expect(
        verifyReport({
          reportPath,
          transactionHash: TRANSACTION_HASH,
          expectedAnchorAccount: anchorKeypair.publicKey(),
          lookupTimeoutMs: 5,
          server,
        })
      ).rejects.toThrow("Horizon transaction lookup timed out after 5ms");
    });
  });

  describe("CLI", () => {
    it("returns zero for a successful verify operation", async () => {
      callTransaction.mockResolvedValue(transactionRecord());
      const output = jest.spyOn(console, "log").mockImplementation(() => undefined);

      const exitCode = await runCli([
        "verify",
        reportPath,
        "--tx",
        TRANSACTION_HASH,
        "--account",
        anchorKeypair.publicKey(),
      ]);

      expect(exitCode).toBe(0);
      expect(output).toHaveBeenCalledWith(expect.stringContaining("VERIFIED"));
    });

    it("returns an integrity exit code and emits an incident for tampering", async () => {
      const anchoredMemo = memoHashFor(reportPath);
      fs.writeFileSync(reportPath, "tampered", "utf8");
      callTransaction.mockResolvedValue(transactionRecord({ memo: anchoredMemo }));
      const errorOutput = jest.spyOn(console, "error").mockImplementation(() => undefined);

      const exitCode = await runCli([
        "verify",
        reportPath,
        "--tx",
        TRANSACTION_HASH,
        "--account",
        anchorKeypair.publicKey(),
      ]);

      expect(exitCode).toBe(2);
      expect(errorOutput).toHaveBeenCalledWith(expect.stringContaining("Integrity incident"));
      expect(errorOutput).toHaveBeenCalledWith(expect.stringContaining("HASH_MISMATCH"));
    });

    it("uses AUDIT_ANCHOR_ACCOUNT when --account is omitted", async () => {
      process.env.AUDIT_ANCHOR_ACCOUNT = anchorKeypair.publicKey();
      callTransaction.mockResolvedValue(transactionRecord());
      jest.spyOn(console, "log").mockImplementation(() => undefined);

      const exitCode = await runCli([
        "verify",
        reportPath,
        "--tx",
        TRANSACTION_HASH,
      ]);

      expect(exitCode).toBe(0);
    });

    it("rejects a CLI account that conflicts with the configured trust anchor", async () => {
      process.env.AUDIT_ANCHOR_ACCOUNT = anchorKeypair.publicKey();
      const errorOutput = jest.spyOn(console, "error").mockImplementation(() => undefined);

      const exitCode = await runCli([
        "verify",
        reportPath,
        "--tx",
        TRANSACTION_HASH,
        "--account",
        Keypair.random().publicKey(),
      ]);

      expect(exitCode).toBe(1);
      expect(errorOutput).toHaveBeenCalledWith(
        expect.stringContaining("--account does not match")
      );
      expect(MockAxiosGet).not.toHaveBeenCalled();
    });

    it("rejects incomplete or unknown verify arguments as operational errors", async () => {
      const errorOutput = jest.spyOn(console, "error").mockImplementation(() => undefined);

      await expect(runCli(["verify", reportPath])).resolves.toBe(1);
      await expect(
        runCli([
          "verify",
          reportPath,
          "--tx",
          TRANSACTION_HASH,
          "--account",
          anchorKeypair.publicKey(),
          "--unexpected",
        ])
      ).resolves.toBe(1);

      expect(errorOutput).toHaveBeenCalledWith(expect.stringContaining("Usage:"));
      expect(callTransaction).not.toHaveBeenCalled();
    });

    it("keeps the historical directory-only invocation working", async () => {
      const output = jest.spyOn(console, "log").mockImplementation(() => undefined);

      const exitCode = await runCli([reportDir]);

      expect(exitCode).toBe(0);
      expect(output).toHaveBeenCalledWith(expect.stringContaining("Dry-run mode"));
    });
  });

  describe("memo decoding", () => {
    it("accepts only canonical Base64 encoding of exactly 32 bytes", () => {
      const digest = "01".repeat(32);
      const canonical = Buffer.from(digest, "hex").toString("base64");

      expect(decodeMemoHash(canonical)).toBe(digest);
      expect(decodeMemoHash(canonical.replace(/=$/, ""))).toBeNull();
      expect(decodeMemoHash(Buffer.alloc(31).toString("base64"))).toBeNull();
      expect(decodeMemoHash(undefined)).toBeNull();
    });
  });
});
