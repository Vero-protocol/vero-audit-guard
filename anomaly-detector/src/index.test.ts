import { runOnce, resetState, RelayerMetrics, threatFetcher } from "../src/index";

const now = Date.now();
const ADDR = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

const base: RelayerMetrics = {
  address: ADDR,
  nonce: 100,
  failedTxCount: 0,
  timestamp: now,
};

beforeEach(() => {
  resetState();
  threatFetcher.clearMockThreats();
  threatFetcher.clearCache();
});

describe("anomaly-detector", () => {
  it("flags a threat feed match", async () => {
    threatFetcher.setMockThreats([ADDR]);
    const alerts = await runOnce([base]);
    expect(alerts.some((a) => a.type === "THREAT_FEED_MATCH" && a.severity === "CRITICAL")).toBe(true);
  });

  it("flags a nonce spike", async () => {
    // Prime the baseline nonce, then send a spike
    await runOnce([{ ...base, nonce: 100 }]);
    const alerts = await runOnce([{ ...base, nonce: 200 }]); // delta 100 > threshold 50
    expect(alerts.some((a) => a.type === "NONCE_SPIKE")).toBe(true);
  });

  it("flags a failed tx burst", async () => {
    const alerts = await runOnce([{ ...base, failedTxCount: 15 }]);
    expect(alerts.some((a) => a.type === "FAILED_TX_BURST")).toBe(true);
  });

  it("returns no alerts for healthy metrics (small nonce delta)", async () => {
    await runOnce([{ ...base, nonce: 100 }]); // prime
    const alerts = await runOnce([{ ...base, nonce: 110, failedTxCount: 0 }]); // delta 10 < 50
    const spikeOrBurst = alerts.filter(
      (a) => a.type === "NONCE_SPIKE" || a.type === "FAILED_TX_BURST"
    );
    expect(spikeOrBurst.length).toBe(0);
  });
  it("detects nonce reuse", async () => {
    // First, set a baseline nonce
    await runOnce([{ ...base, nonce: 100 }]);
    // Then send a lower or equal nonce to trigger reuse detection
    const alerts = await runOnce([{ ...base, nonce: 90 }]);
    expect(alerts.some((a) => a.type === "NONCE_REUSE")).toBe(true);
  });
});

