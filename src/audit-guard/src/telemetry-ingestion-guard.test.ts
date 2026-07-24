/**
 * Regression tests for TelemetryIngestionGuard — VAG-012
 *
 * Coverage targets
 * ----------------
 * ✔ Happy path: events accepted within rate limit
 * ✔ Token-bucket exhaustion (rate limiting)
 * ✔ Bucket refill over time
 * ✔ Bounded queue — drop-oldest backpressure
 * ✔ Malformed / adversarial events (null, missing fields, bad timestamp, non-object)
 * ✔ Burst traffic scenario
 * ✔ Sustained overload scenario
 * ✔ Batch ingestion (ingestBatch)
 * ✔ drain() behaviour
 * ✔ Metrics counters accuracy
 * ✔ No on-chain imports / no halt authority (static check)
 * ✔ logStatus() does not throw
 */

import TelemetryIngestionGuard, {
  TelemetryIngestionGuardOptions,
  TelemetryEvent,
} from "./telemetry-ingestion-guard";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(id: string, overrides: Partial<TelemetryEvent> = {}): TelemetryEvent {
  return {
    id,
    timestamp: new Date().toISOString(),
    payload: { value: 42 },
    ...overrides,
  };
}

/**
 * Build a guard with a controllable clock so time-based tests are
 * deterministic without real sleeps.
 */
function buildGuard(
  opts: Omit<TelemetryIngestionGuardOptions, "_nowFn"> = {},
  startTime = 1_000_000
): { guard: TelemetryIngestionGuard; advanceMs: (ms: number) => void } {
  let now = startTime;
  const guard = new TelemetryIngestionGuard({
    ...opts,
    _nowFn: () => now,
  });
  return {
    guard,
    advanceMs: (ms: number) => {
      now += ms;
    },
  };
}

// ---------------------------------------------------------------------------
// Happy-path acceptance
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — happy path", () => {
  it("accepts events within the token budget", () => {
    const { guard } = buildGuard({ bucketCapacity: 5, refillRatePerSecond: 10 });
    for (let i = 0; i < 5; i++) {
      const result = guard.ingest(makeEvent(`evt-${i}`));
      expect(result.outcome).toBe("ACCEPTED");
    }
    expect(guard.queueDepth).toBe(5);
  });

  it("returns decreasing tokensRemaining as events are accepted", () => {
    const { guard } = buildGuard({ bucketCapacity: 10, refillRatePerSecond: 100 });
    const r1 = guard.ingest(makeEvent("a"));
    const r2 = guard.ingest(makeEvent("b"));
    expect(r1.outcome).toBe("ACCEPTED");
    expect(r2.outcome).toBe("ACCEPTED");
    expect(r1.tokensRemaining).toBeGreaterThan(r2.tokensRemaining);
  });

  it("drain() removes and returns queued events in FIFO order", () => {
    const { guard } = buildGuard({ bucketCapacity: 20, refillRatePerSecond: 100 });
    guard.ingest(makeEvent("first"));
    guard.ingest(makeEvent("second"));
    guard.ingest(makeEvent("third"));

    const batch = guard.drain(2);
    expect(batch).toHaveLength(2);
    expect(batch[0].id).toBe("first");
    expect(batch[1].id).toBe("second");
    expect(guard.queueDepth).toBe(1);
  });

  it("drain() with no argument drains the entire queue", () => {
    const { guard } = buildGuard({ bucketCapacity: 50, refillRatePerSecond: 100 });
    for (let i = 0; i < 10; i++) guard.ingest(makeEvent(`e${i}`));
    const all = guard.drain();
    expect(all).toHaveLength(10);
    expect(guard.queueDepth).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Rate limiting (token-bucket exhaustion)
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — rate limiting", () => {
  it("returns RATE_LIMITED once the bucket is exhausted", () => {
    const { guard } = buildGuard({ bucketCapacity: 3, refillRatePerSecond: 1 });
    // Exhaust
    for (let i = 0; i < 3; i++) guard.ingest(makeEvent(`ok-${i}`));
    // Next event is rate-limited
    const result = guard.ingest(makeEvent("blocked"));
    expect(result.outcome).toBe("RATE_LIMITED");
    expect(result.tokensRemaining).toBe(0);
    // Rate-limited events must NOT appear in the queue
    expect(guard.queueDepth).toBe(3);
  });

  it("accepts events again after tokens have refilled", () => {
    const { guard, advanceMs } = buildGuard({
      bucketCapacity: 2,
      refillRatePerSecond: 10, // 10 tokens/s → 1 token per 100 ms
    });
    guard.ingest(makeEvent("a"));
    guard.ingest(makeEvent("b"));
    const blocked = guard.ingest(makeEvent("c"));
    expect(blocked.outcome).toBe("RATE_LIMITED");

    // Advance 200 ms → 2 new tokens added
    advanceMs(200);
    const r = guard.ingest(makeEvent("d"));
    expect(r.outcome).toBe("ACCEPTED");
  });

  it("counts rate-limited events in metrics", () => {
    const { guard } = buildGuard({ bucketCapacity: 1, refillRatePerSecond: 0.001 });
    guard.ingest(makeEvent("ok"));
    guard.ingest(makeEvent("rl-1"));
    guard.ingest(makeEvent("rl-2"));
    const m = guard.getMetrics();
    expect(m.totalRateLimited).toBe(2);
    expect(m.totalAccepted).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Backpressure — bounded queue with drop-oldest
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — backpressure / bounded queue", () => {
  it("drops the oldest event when the queue is full", () => {
    const { guard } = buildGuard({
      bucketCapacity: 1000,
      refillRatePerSecond: 10000,
      maxQueueDepth: 3,
    });
    guard.ingest(makeEvent("old-1"));
    guard.ingest(makeEvent("old-2"));
    guard.ingest(makeEvent("old-3"));

    // Queue is now full — ingesting a 4th should drop "old-1"
    const result = guard.ingest(makeEvent("new-1"));
    expect(result.outcome).toBe("QUEUE_FULL_DROP");
    expect(result.droppedEventId).toBe("old-1");
    expect(result.queueDepth).toBe(3);

    // "old-1" must no longer be in the queue
    const queued = guard.drain();
    const ids = queued.map((e) => e.id);
    expect(ids).not.toContain("old-1");
    expect(ids).toContain("new-1");
  });

  it("keeps the queue at maxQueueDepth under sustained overload", () => {
    const { guard } = buildGuard({
      bucketCapacity: 10_000,
      refillRatePerSecond: 100_000,
      maxQueueDepth: 10,
    });
    for (let i = 0; i < 100; i++) {
      guard.ingest(makeEvent(`ev-${i}`));
    }
    expect(guard.queueDepth).toBe(10);
    expect(guard.getMetrics().totalDropped).toBe(90);
  });

  it("counts dropped events in metrics", () => {
    const { guard } = buildGuard({
      bucketCapacity: 10_000,
      refillRatePerSecond: 100_000,
      maxQueueDepth: 5,
    });
    for (let i = 0; i < 8; i++) guard.ingest(makeEvent(`e${i}`));
    expect(guard.getMetrics().totalDropped).toBe(3);
  });

  it("drain then refill does not lose events beyond capacity", () => {
    const { guard } = buildGuard({
      bucketCapacity: 10_000,
      refillRatePerSecond: 100_000,
      maxQueueDepth: 5,
    });
    // Fill
    for (let i = 0; i < 5; i++) guard.ingest(makeEvent(`fill-${i}`));
    // Drain all
    guard.drain();
    expect(guard.queueDepth).toBe(0);
    // Refill — no drops expected now
    for (let i = 0; i < 5; i++) guard.ingest(makeEvent(`new-${i}`));
    expect(guard.queueDepth).toBe(5);
    expect(guard.getMetrics().totalDropped).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Malformed / adversarial event validation
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — malformed events", () => {
  let guard: TelemetryIngestionGuard;

  beforeEach(() => {
    ({ guard } = buildGuard({ bucketCapacity: 100, refillRatePerSecond: 1000 }));
  });

  it("rejects null", () => {
    const result = guard.ingest(null);
    expect(result.outcome).toBe("MALFORMED");
    expect(result.validationError).toBeDefined();
    expect(guard.queueDepth).toBe(0);
  });

  it("rejects undefined", () => {
    const result = guard.ingest(undefined);
    expect(result.outcome).toBe("MALFORMED");
    expect(guard.queueDepth).toBe(0);
  });

  it("rejects a plain string", () => {
    const result = guard.ingest("not an object");
    expect(result.outcome).toBe("MALFORMED");
  });

  it("rejects an array", () => {
    const result = guard.ingest([1, 2, 3]);
    expect(result.outcome).toBe("MALFORMED");
  });

  it("rejects an event with a missing id", () => {
    const result = guard.ingest({ timestamp: new Date().toISOString(), payload: {} });
    expect(result.outcome).toBe("MALFORMED");
    expect(result.validationError).toMatch(/id/i);
  });

  it("rejects an event with an empty id", () => {
    const result = guard.ingest({ id: "   ", timestamp: new Date().toISOString(), payload: {} });
    expect(result.outcome).toBe("MALFORMED");
  });

  it("rejects an event with a missing timestamp", () => {
    const result = guard.ingest({ id: "x", payload: {} });
    expect(result.outcome).toBe("MALFORMED");
    expect(result.validationError).toMatch(/timestamp/i);
  });

  it("rejects an event with a non-date timestamp", () => {
    const result = guard.ingest({ id: "x", timestamp: "not-a-date", payload: {} });
    expect(result.outcome).toBe("MALFORMED");
    expect(result.validationError).toMatch(/timestamp/i);
  });

  it("rejects an event with a missing payload field", () => {
    const result = guard.ingest({ id: "x", timestamp: new Date().toISOString() });
    expect(result.outcome).toBe("MALFORMED");
    expect(result.validationError).toMatch(/payload/i);
  });

  it("counts malformed events in metrics", () => {
    guard.ingest(null);
    guard.ingest(undefined);
    guard.ingest("bad");
    expect(guard.getMetrics().totalMalformed).toBe(3);
    expect(guard.getMetrics().totalAccepted).toBe(0);
  });

  it("does not consume a token for malformed events", () => {
    const { guard: g } = buildGuard({ bucketCapacity: 2, refillRatePerSecond: 0.001 });
    g.ingest(null);
    g.ingest(null);
    g.ingest(null);
    // Tokens should still be available for valid events
    const result = g.ingest(makeEvent("valid"));
    expect(result.outcome).toBe("ACCEPTED");
  });
});

// ---------------------------------------------------------------------------
// Burst traffic scenario
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — burst traffic", () => {
  it("accepts exactly bucketCapacity events in a burst then rate-limits the rest", () => {
    const capacity = 20;
    const { guard } = buildGuard({ bucketCapacity: capacity, refillRatePerSecond: 1 });
    const results = Array.from({ length: 30 }, (_, i) =>
      guard.ingest(makeEvent(`evt-${i}`))
    );

    const accepted = results.filter((r) => r.outcome === "ACCEPTED").length;
    const rateLimited = results.filter((r) => r.outcome === "RATE_LIMITED").length;

    expect(accepted).toBe(capacity);
    expect(rateLimited).toBe(30 - capacity);
    // Rate-limited events must not have been queued
    expect(guard.queueDepth).toBe(capacity);
  });

  it("burst + queue overflow produces QUEUE_FULL_DROP for excess events beyond queue depth", () => {
    const queueDepth = 5;
    const { guard } = buildGuard({
      bucketCapacity: 20,
      refillRatePerSecond: 1_000,
      maxQueueDepth: queueDepth,
    });
    const results = Array.from({ length: 15 }, (_, i) =>
      guard.ingest(makeEvent(`e${i}`))
    );

    const dropped = results.filter((r) => r.outcome === "QUEUE_FULL_DROP");
    expect(dropped.length).toBe(10);
    expect(guard.queueDepth).toBe(queueDepth);
  });
});

// ---------------------------------------------------------------------------
// Sustained overload scenario
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — sustained overload", () => {
  it("stabilizes at maxQueueDepth under sustained high-rate ingestion", () => {
    const { guard } = buildGuard({
      bucketCapacity: 50_000,
      refillRatePerSecond: 1_000_000,
      maxQueueDepth: 20,
    });

    for (let round = 0; round < 10; round++) {
      // Ingest 50 events per round
      for (let i = 0; i < 50; i++) {
        guard.ingest(makeEvent(`r${round}-e${i}`));
      }
      // Consumer drains 5 events per round (slower than producer)
      guard.drain(5);
    }

    // Queue should never exceed maxQueueDepth
    expect(guard.queueDepth).toBeLessThanOrEqual(20);
    // Drops must have occurred
    expect(guard.getMetrics().totalDropped).toBeGreaterThan(0);
  });

  it("under sustained rate limiting queue depth stays bounded", () => {
    const { guard } = buildGuard({
      bucketCapacity: 5,
      refillRatePerSecond: 0.001, // essentially no refill
      maxQueueDepth: 10,
    });
    for (let i = 0; i < 1000; i++) {
      guard.ingest(makeEvent(`e${i}`));
    }
    // Only 5 events fit (bucket capacity), queue never exceeds 5
    expect(guard.queueDepth).toBeLessThanOrEqual(5);
    expect(guard.getMetrics().totalRateLimited).toBeGreaterThan(900);
  });
});

// ---------------------------------------------------------------------------
// Batch ingestion
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — ingestBatch", () => {
  it("processes each event in the batch independently", () => {
    const { guard } = buildGuard({ bucketCapacity: 10, refillRatePerSecond: 1_000 });
    const events = Array.from({ length: 5 }, (_, i) => makeEvent(`b${i}`));
    const results = guard.ingestBatch(events);
    expect(results).toHaveLength(5);
    expect(results.every((r) => r.outcome === "ACCEPTED")).toBe(true);
  });

  it("flags mixed valid/invalid items in a batch", () => {
    const { guard } = buildGuard({ bucketCapacity: 100, refillRatePerSecond: 1_000 });
    const mixed = [makeEvent("good"), null, makeEvent("also-good"), "bad"];
    const results = guard.ingestBatch(mixed);
    expect(results[0].outcome).toBe("ACCEPTED");
    expect(results[1].outcome).toBe("MALFORMED");
    expect(results[2].outcome).toBe("ACCEPTED");
    expect(results[3].outcome).toBe("MALFORMED");
  });

  it("returns an empty array for a non-array batch", () => {
    const { guard } = buildGuard();
    // @ts-expect-error — intentional adversarial call
    const results = guard.ingestBatch("not an array");
    expect(results).toEqual([]);
  });

  it("handles an empty batch without error", () => {
    const { guard } = buildGuard();
    const results = guard.ingestBatch([]);
    expect(results).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Metrics accuracy
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — metrics", () => {
  it("accurately tracks all counter types", () => {
    const { guard } = buildGuard({
      bucketCapacity: 3,
      refillRatePerSecond: 0.001, // effectively static
      maxQueueDepth: 2,
    });
    // 3 accepted (2 fill queue, 3rd drops oldest → QUEUE_FULL_DROP)
    guard.ingest(makeEvent("a")); // ACCEPTED, q=1
    guard.ingest(makeEvent("b")); // ACCEPTED, q=2
    guard.ingest(makeEvent("c")); // QUEUE_FULL_DROP (drops "a"), q=2
    // Tokens now exhausted
    guard.ingest(makeEvent("d")); // RATE_LIMITED
    guard.ingest(null as unknown as TelemetryEvent); // MALFORMED

    const m = guard.getMetrics();
    expect(m.totalAccepted).toBe(3);   // a, b, c all enqueued (even with drop)
    expect(m.totalDropped).toBe(1);    // "a" was dropped
    expect(m.totalRateLimited).toBe(1);
    expect(m.totalMalformed).toBe(1);
  });

  it("getMetrics returns consistent queueDepth and tokensAvailable", () => {
    const { guard } = buildGuard({ bucketCapacity: 10, refillRatePerSecond: 100 });
    guard.ingest(makeEvent("x"));
    const m = guard.getMetrics();
    expect(m.queueDepth).toBe(guard.queueDepth);
    expect(m.tokensAvailable).toBe(guard.tokensAvailable);
  });
});

// ---------------------------------------------------------------------------
// logStatus() — must not throw under any condition
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — logStatus", () => {
  it("does not throw when called on an empty guard", () => {
    const { guard } = buildGuard();
    expect(() => guard.logStatus()).not.toThrow();
  });

  it("does not throw after rate-limiting and drops", () => {
    const { guard } = buildGuard({ bucketCapacity: 1, refillRatePerSecond: 0.001, maxQueueDepth: 1 });
    guard.ingest(makeEvent("a"));
    guard.ingest(makeEvent("b"));
    guard.ingest(makeEvent("c"));
    expect(() => guard.logStatus()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Observational safety assertion (static structural test)
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — observational safety", () => {
  it("does not import or export any on-chain halt mechanism", async () => {
    // Dynamically import the module and verify the exports contain no
    // chain-halting symbols.
    const mod = await import("./telemetry-ingestion-guard");
    const exportedKeys = Object.keys(mod);

    const forbiddenPatterns = [/halt/i, /pause/i, /stop_chain/i, /circuit.*break/i];
    for (const key of exportedKeys) {
      for (const pattern of forbiddenPatterns) {
        expect(key).not.toMatch(pattern);
      }
    }
  });

  it("IngestionResult never contains chain operation fields", () => {
    const { guard } = buildGuard();
    const result = guard.ingest(makeEvent("safe"));
    expect(result).not.toHaveProperty("haltChain");
    expect(result).not.toHaveProperty("pauseChain");
    expect(result).not.toHaveProperty("blockOperation");
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("TelemetryIngestionGuard — edge cases", () => {
  it("_reset() clears queue, counters, and refills bucket", () => {
    const { guard } = buildGuard({ bucketCapacity: 2, refillRatePerSecond: 0.001, maxQueueDepth: 5 });
    guard.ingest(makeEvent("x"));
    guard.ingest(makeEvent("y"));
    guard.ingest(makeEvent("z")); // rate-limited
    guard._reset();

    expect(guard.queueDepth).toBe(0);
    const m = guard.getMetrics();
    expect(m.totalAccepted).toBe(0);
    expect(m.totalRateLimited).toBe(0);
    // After reset, bucket should be full again
    const r = guard.ingest(makeEvent("after-reset"));
    expect(r.outcome).toBe("ACCEPTED");
  });

  it("accepts a payload of null (null is a valid payload value)", () => {
    const { guard } = buildGuard();
    const result = guard.ingest({ id: "x", timestamp: new Date().toISOString(), payload: null });
    expect(result.outcome).toBe("ACCEPTED");
  });

  it("accepts a payload of 0 (falsy but valid)", () => {
    const { guard } = buildGuard();
    const result = guard.ingest({ id: "x", timestamp: new Date().toISOString(), payload: 0 });
    expect(result.outcome).toBe("ACCEPTED");
  });

  it("accepts extra unknown fields on the event object", () => {
    const { guard } = buildGuard();
    const result = guard.ingest({
      id: "x",
      timestamp: new Date().toISOString(),
      payload: {},
      extra: "ignored-field",
    });
    expect(result.outcome).toBe("ACCEPTED");
  });

  it("drain(0) returns an empty array without modifying the queue", () => {
    const { guard } = buildGuard({ bucketCapacity: 10, refillRatePerSecond: 100 });
    guard.ingest(makeEvent("a"));
    const drained = guard.drain(0);
    expect(drained).toHaveLength(0);
    expect(guard.queueDepth).toBe(1);
  });
});
