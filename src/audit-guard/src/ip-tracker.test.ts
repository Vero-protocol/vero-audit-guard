import { IPTracker } from "./ip-tracker";

describe("IPTracker", () => {
  let tracker: IPTracker;

  beforeEach(() => {
    // Reset the tracker before each test
    tracker = new IPTracker(3);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("should allow requests under the limit", () => {
    expect(tracker.recordRequest("192.168.1.1")).toBe(true);
    expect(tracker.recordRequest("192.168.1.1")).toBe(true);
    expect(tracker.recordRequest("192.168.1.1")).toBe(true);
  });

  it("should ban IP after exceeding the limit", () => {
    expect(tracker.recordRequest("10.0.0.1")).toBe(true);
    expect(tracker.recordRequest("10.0.0.1")).toBe(true);
    expect(tracker.recordRequest("10.0.0.1")).toBe(true);
    
    // 4th request exceeds limit of 3
    expect(tracker.recordRequest("10.0.0.1")).toBe(false);
    expect(tracker.isBanned("10.0.0.1")).toBe(true);
  });

  it("should correctly handle timestamps and clear old requests", () => {
    const ip = "172.16.0.1";
    
    // Mock Date.now to control time
    const now = 1000000000000;
    jest.spyOn(Date, "now").mockImplementation(() => now);
    
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(true);
    
    // Advance time by 61 seconds
    jest.spyOn(Date, "now").mockImplementation(() => now + 61000);
    
    // Previous requests should have expired
    expect(tracker.getRequestCount(ip)).toBe(0);
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(true);
    
    // Should still ban if limit is hit in the new window
    expect(tracker.recordRequest(ip)).toBe(false);
  });

  it("should allow banned IP after ban TTL elapses", () => {
    const ip = "8.8.8.8";
    
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(false); // Banned
    
    // Advance time past TTL (default is 1 hour)
    const future = Date.now() + 3600001;
    jest.spyOn(Date, "now").mockImplementation(() => future);
    
    expect(tracker.isBanned(ip)).toBe(false);
    expect(tracker.recordRequest(ip)).toBe(true);
  });

  it("bounds the map size to the maxTrackedIps cap", () => {
    // 10 max ips
    const cappedTracker = new IPTracker(10, 10, 3600000);
    
    for (let i = 0; i < 20; i++) {
      cappedTracker.recordRequest(`192.168.1.${i}`);
    }
    
    // Size should be exactly 10
    expect((cappedTracker as any).requests.size).toBe(10);
    // The most recent 10 should be present
    expect(cappedTracker.getRequestCount("192.168.1.19")).toBe(1);
    expect(cappedTracker.getRequestCount("192.168.1.0")).toBe(0);
  });

  it("sweeps expired entries amortized", () => {
    const sweepTracker = new IPTracker(10, 100, 3600000);
    
    const now = 1000000000000;
    jest.spyOn(Date, "now").mockImplementation(() => now);
    
    sweepTracker.recordRequest("1.1.1.1");
    expect((sweepTracker as any).requests.size).toBe(1);
    
    jest.spyOn(Date, "now").mockImplementation(() => now + 61000);
    
    // Still 1 before another operation triggers sweep
    sweepTracker.recordRequest("2.2.2.2");
    
    // 1.1.1.1 should be swept, 2.2.2.2 added
    expect((sweepTracker as any).requests.size).toBe(1);
    expect((sweepTracker as any).requests.has("1.1.1.1")).toBe(false);
  });
});
