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
    },
  };
});

import { auditAndAnchor } from "./index";

const MockServer = Horizon.Server as unknown as jest.Mock;

describe("verifiable audit trail entrypoint", () => {
  const originalEnv = process.env;
  let reportDir: string;
  let loadAccount: jest.Mock;
  let submitTransaction: jest.Mock;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.AUDIT_KEYPAIR_SECRET;
    reportDir = fs.mkdtempSync(path.join(os.tmpdir(), "vero-audit-trail-test-"));
    loadAccount = jest.fn();
    submitTransaction = jest.fn().mockResolvedValue({ hash: "mock-transaction-hash" });
    MockServer.mockImplementation(() => ({ loadAccount, submitTransaction }));
  });

  afterEach(() => {
    process.env = originalEnv;
    fs.rmSync(reportDir, { recursive: true, force: true });
    jest.clearAllMocks();
  });

  it("computes report hashes in dry-run mode without contacting Horizon", async () => {
    const reportPath = path.join(reportDir, "latest.json");
    fs.writeFileSync(reportPath, JSON.stringify({ status: "ok" }), "utf8");

    await auditAndAnchor(reportDir);

    expect(MockServer).not.toHaveBeenCalled();
    expect(loadAccount).not.toHaveBeenCalled();
    expect(submitTransaction).not.toHaveBeenCalled();
  });

  it("anchors JSON reports through a mocked Horizon server", async () => {
    const keypair = Keypair.random();
    const account = new Account(keypair.publicKey(), "1");
    process.env.AUDIT_KEYPAIR_SECRET = keypair.secret();
    const reportPath = path.join(reportDir, "latest.json");
    fs.writeFileSync(reportPath, JSON.stringify({ finding: "none" }), "utf8");
    loadAccount.mockResolvedValue(account);

    await auditAndAnchor(reportDir);

    expect(MockServer).toHaveBeenCalledWith("https://horizon-testnet.stellar.org");
    expect(loadAccount).toHaveBeenCalledWith(keypair.publicKey());
    expect(submitTransaction).toHaveBeenCalledTimes(1);
    expect(submitTransaction.mock.calls[0][0]).toBeDefined();
  });

  it("ignores non-JSON files and returns for an empty report directory", async () => {
    fs.writeFileSync(path.join(reportDir, "README.txt"), "ignored", "utf8");

    await expect(auditAndAnchor(reportDir)).resolves.toBeUndefined();

    expect(MockServer).not.toHaveBeenCalled();
  });
});
