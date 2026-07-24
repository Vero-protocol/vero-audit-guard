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
});
