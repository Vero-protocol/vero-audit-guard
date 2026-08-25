import { RateLimitMonitor } from "./rate-limit-monitor";

describe("RateLimitMonitor", () => {
  it("allows traffic at or below the configured threshold", () => {
    const monitor = new RateLimitMonitor({ threshold: 3, windowMs: 1_000 });

    expect(monitor.record("relayer-a", 0)).toMatchObject({ allowed: true, requestCount: 1 });
    expect(monitor.record("relayer-a", 100)).toMatchObject({ allowed: true, requestCount: 2 });
    expect(monitor.record("relayer-a", 200)).toMatchObject({ allowed: true, requestCount: 3 });
  });

  it("flags a burst above the threshold", () => {
    const monitor = new RateLimitMonitor({ threshold: 2, windowMs: 1_000 });

    monitor.record("relayer-a", 0);
    monitor.record("relayer-a", 100);
    const result = monitor.record("relayer-a", 200);

    expect(result.allowed).toBe(false);
    expect(result.finding).toEqual(expect.objectContaining({
      rule: "RATE_LIMIT_BURST",
      severity: "HIGH",
      clientId: "relayer-a",
      requestCount: 3,
      threshold: 2,
    }));
  });

  it("expires requests after the rolling window", () => {
    const monitor = new RateLimitMonitor({ threshold: 1, windowMs: 1_000 });

    expect(monitor.record("relayer-a", 0).allowed).toBe(true);
    expect(monitor.getRequestCount("relayer-a", 1_001)).toBe(0);
    expect(monitor.record("relayer-a", 1_001).allowed).toBe(true);
  });

  it("bounds the map size via LRU cap", () => {
    const monitor = new RateLimitMonitor({ threshold: 10, windowMs: 1_000, maxTrackedClients: 5 });

    for (let i = 0; i < 10; i++) {
      monitor.record(`client-${i}`, 0);
    }

    expect((monitor as any).requests.size).toBe(5);
    expect(monitor.getRequestCount("client-0", 0)).toBe(0);
    expect(monitor.getRequestCount("client-9", 0)).toBe(1);
  });

  it("sweeps expired entries", () => {
    const monitor = new RateLimitMonitor({ threshold: 10, windowMs: 1_000, maxTrackedClients: 100 });

    monitor.record("client-A", 0);
    expect((monitor as any).requests.size).toBe(1);

    // After window, next record should sweep client-A
    monitor.record("client-B", 1_001);
    expect((monitor as any).requests.size).toBe(1);
    expect((monitor as any).requests.has("client-A")).toBe(false);
    expect((monitor as any).requests.has("client-B")).toBe(true);
  });
});
