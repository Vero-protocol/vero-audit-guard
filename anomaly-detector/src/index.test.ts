import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  runOnce,
  resetState,
  RelayerMetrics,
  threatFetcher,
  persistNonceMap,
} from "../src/index";

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
  
  describe("nonce-db atomic persist (Issue #307)", () => {
    let tmpDir: string;
    let dbPath: string;
  
    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nonce-db-"));
      dbPath = path.join(tmpDir, "nonce-db.json");
    });
  
    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });
  
    it("merges concurrent logical writers instead of last-writer-wins clobber", () => {
      // Each call only knows about its own address — the old saveNonces
      // pattern (write full local map) would erase the other addresses.
      const writers = 16;
      const iterations = 30;
  
      for (let round = 1; round <= iterations; round++) {
        for (let i = 0; i < writers; i++) {
          persistNonceMap(dbPath, { [`ADDR_${i}`]: round });
        }
      }
  
      const raw = fs.readFileSync(dbPath, "utf-8");
      const finalState = JSON.parse(raw) as Record<string, number>;
  
      expect(Object.keys(finalState).sort()).toEqual(
        Array.from({ length: writers }, (_, i) => `ADDR_${i}`).sort()
      );
      for (let i = 0; i < writers; i++) {
        expect(finalState[`ADDR_${i}`]).toBe(iterations);
      }
    });
  
    it("keeps the higher nonce when two writers update the same address", () => {
      persistNonceMap(dbPath, { SHARED: 5 });
      persistNonceMap(dbPath, { SHARED: 3 }); // stale writer
      persistNonceMap(dbPath, { SHARED: 9 });
  
      const finalState = JSON.parse(
        fs.readFileSync(dbPath, "utf-8")
      ) as Record<string, number>;
      expect(finalState.SHARED).toBe(9);
    });
  });
});

