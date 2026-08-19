jest.mock("../src/webhook", () => ({
  sendAlert: jest.fn().mockResolvedValue(undefined),
}));

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { sendAlert } from "../src/webhook";
import {
  NonceAnomalyWatcher,
  type ChainDataProvider,
} from "./nonce-anomaly-watcher";

const mockSendAlert = sendAlert as jest.MockedFunction<typeof sendAlert>;

describe("NonceAnomalyWatcher", () => {
  const originalCwd = process.cwd();
  let reportDir: string;
  let provider: ChainDataProvider;

  beforeEach(() => {
    reportDir = fs.mkdtempSync(path.join(os.tmpdir(), "nonce-watcher-test-"));
    process.chdir(reportDir);
    jest.clearAllMocks();
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(reportDir, { recursive: true, force: true });
  });

  it("does not alert when engine and chain nonces match", async () => {
    provider = { getChainNonce: jest.fn().mockResolvedValue({ nonce: 7, ledgerNumber: 101 }) };
    const watcher = new NonceAnomalyWatcher(provider);
    watcher.registerEngineNonce("GACCOUNT", 7);

    await watcher.syncNonces();

    expect(mockSendAlert).not.toHaveBeenCalled();
    expect(watcher.getAlerts("GACCOUNT")).toHaveLength(0);
    expect(watcher.getState("GACCOUNT")).toMatchObject({
      engineNonce: 7,
      chainNonce: 7,
      driftCount: 0,
      maxDrift: 0,
    });
  });

  it.each([
    [1, "MEDIUM"],
    [2, "HIGH"],
    [10, "CRITICAL"],
  ] as const)("classifies drift of %i as %s", async (drift, severity) => {
    provider = { getChainNonce: jest.fn().mockResolvedValue({ nonce: 100 - drift, ledgerNumber: 202 }) };
    const watcher = new NonceAnomalyWatcher(provider);
    watcher.registerEngineNonce("GACCOUNT", 100);

    await watcher.syncNonces();

    expect(mockSendAlert).toHaveBeenCalledWith({
      repository: "GACCOUNT",
      alert: `nonce_anomaly drift=${drift} engine=100 chain=${100 - drift} severity=${severity} ledger=202`,
      timestamp: expect.any(String),
    });
    expect(watcher.getState("GACCOUNT")).toMatchObject({
      chainNonce: 100 - drift,
      lastSyncedLedger: 202,
      driftCount: 1,
      maxDrift: drift,
    });
  });

  it("records an alert and audit log even when webhook delivery fails", async () => {
    mockSendAlert.mockRejectedValueOnce(new Error("webhook unavailable"));
    provider = { getChainNonce: jest.fn().mockResolvedValue({ nonce: 88, ledgerNumber: 303 }) };
    const watcher = new NonceAnomalyWatcher(provider);
    watcher.registerEngineNonce("GACCOUNT", 90);

    await watcher.syncNonces();

    expect(watcher.getAlerts("GACCOUNT")).toHaveLength(1);
    const logPath = path.join(reportDir, "reports", "nonce-anomaly-log.jsonl");
    expect(fs.readFileSync(logPath, "utf8")).toContain('"drift":2');
  });

  it("keeps monitoring when the chain provider rejects a sync", async () => {
    const getChainNonce = jest.fn().mockRejectedValue(new Error("provider unavailable"));
    provider = { getChainNonce };
    const watcher = new NonceAnomalyWatcher(provider);
    watcher.registerEngineNonce("GACCOUNT", 90);

    await expect(watcher.syncNonces()).resolves.toBeUndefined();

    expect(getChainNonce).toHaveBeenCalledWith("GACCOUNT");
    expect(watcher.getAlerts("GACCOUNT")).toHaveLength(0);
  });

  it("stops its interval when monitoring is stopped", () => {
    jest.useFakeTimers();
    provider = { getChainNonce: jest.fn().mockResolvedValue({ nonce: 7, ledgerNumber: 101 }) };
    const watcher = new NonceAnomalyWatcher(provider);
    watcher.registerEngineNonce("GACCOUNT", 7);

    watcher.start();
    watcher.stop();
    jest.advanceTimersByTime(60_000);

    expect(provider.getChainNonce).toHaveBeenCalledTimes(1);
    jest.useRealTimers();
  });
});
