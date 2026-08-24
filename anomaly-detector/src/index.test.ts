import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  runOnce,
  resetState,
  RelayerMetrics,
  threatFetcher,
  persistNonceMap,
  acquireNonceDbLock,
  lockPathFor,
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
  
    it("merges concurrent logical writers instead of last-writer-wins clobber", async () => {
      // Each call only knows about its own address — the old saveNonces
      // pattern (write full local map) would erase the other addresses.
      const writers = 16;
      const iterations = 30;
  
      for (let round = 1; round <= iterations; round++) {
        for (let i = 0; i < writers; i++) {
          await persistNonceMap(dbPath, { [`ADDR_${i}`]: round });
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

    it("keeps the higher nonce when two writers update the same address", async () => {
      await persistNonceMap(dbPath, { SHARED: 5 });
      await persistNonceMap(dbPath, { SHARED: 3 }); // stale writer
      await persistNonceMap(dbPath, { SHARED: 9 });

      const finalState = JSON.parse(
        fs.readFileSync(dbPath, "utf-8")
      ) as Record<string, number>;
      expect(finalState.SHARED).toBe(9);
    });
  });

  describe("nonce-db async lock (Issue #346)", () => {
    let tmpDir: string;
    let dbPath: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nonce-db-lock-"));
      dbPath = path.join(tmpDir, "nonce-db.json");
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("yields to the event loop while the lock is contended (no busy-wait)", async () => {
      const lockDir = lockPathFor(dbPath);
      fs.mkdirSync(lockDir); // simulate a lock held by another process

      const acquire = acquireNonceDbLock(dbPath, 2000, 60_000, 50);
      const started = Date.now();
      // A 100ms timer must fire while acquire is still retrying.
      await new Promise((resolve) => setTimeout(resolve, 100));
      const timerLatency = Date.now() - started;

      // Generous bounds: fires on schedule, but not delayed by a busy-wait
      // (a synchronous spin would hold the loop until the lock is released).
      expect(timerLatency).toBeGreaterThanOrEqual(80);
      expect(timerLatency).toBeLessThan(200);

      fs.rmSync(lockDir, { recursive: true, force: true });
      await expect(acquire).resolves.toBe(lockDir);
    });

    it("reclaims a lock directory older than the max age", async () => {
      const lockDir = lockPathFor(dbPath);
      fs.mkdirSync(lockDir);
      fs.writeFileSync(
        path.join(lockDir, "owner.json"),
        JSON.stringify({ pid: 424242, acquiredAt: Date.now() - 120_000 }),
        "utf-8"
      );

      const merged = await persistNonceMap(dbPath, { STALE_OWNER: 11 });
      expect(merged.STALE_OWNER).toBe(11);
      expect(fs.existsSync(lockDir)).toBe(false); // released after the write
    });

    it("reclaims an orphaned lock directory (no owner metadata) by mtime", async () => {
      const lockDir = lockPathFor(dbPath);
      fs.mkdirSync(lockDir);
      const ancient = new Date(Date.now() - 120_000);
      fs.utimesSync(lockDir, ancient, ancient);

      const merged = await persistNonceMap(dbPath, { ORPHANED: 4 });
      expect(merged.ORPHANED).toBe(4);
      expect(fs.existsSync(lockDir)).toBe(false);
    });

    it("does not reclaim a fresh lock held by another process", async () => {
      const lockDir = lockPathFor(dbPath);
      fs.mkdirSync(lockDir);
      fs.writeFileSync(
        path.join(lockDir, "owner.json"),
        JSON.stringify({ pid: 424242, acquiredAt: Date.now() }),
        "utf-8"
      );

      await expect(
        acquireNonceDbLock(dbPath, 100, 60_000, 10)
      ).rejects.toThrow(/Timed out after/);
    });

    it("surfaces a persistence failure as an alert, not just a console line", async () => {
      const lockDir = lockPathFor(path.join(__dirname, "nonce-db.json"));
      const originalTimeout = process.env.NONCE_DB_LOCK_TIMEOUT_MS;
      process.env.NONCE_DB_LOCK_TIMEOUT_MS = "150";
      try {
        fs.mkdirSync(lockDir, { recursive: true });
        fs.writeFileSync(
          path.join(lockDir, "owner.json"),
          JSON.stringify({ pid: 424242, acquiredAt: Date.now() }),
          "utf-8"
        );

        const alerts = await runOnce([base]);
        expect(
          alerts.some((a) => a.type === "NONCE_DB_PERSIST_FAILURE")
        ).toBe(true);
      } finally {
        fs.rmSync(lockDir, { recursive: true, force: true });
        if (originalTimeout === undefined) {
          delete process.env.NONCE_DB_LOCK_TIMEOUT_MS;
        } else {
          process.env.NONCE_DB_LOCK_TIMEOUT_MS = originalTimeout;
        }
      }
    });
  });
});

