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

  it("should remain banned even after time passes until unbanned", () => {
    const ip = "8.8.8.8";
    
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(false); // Banned
    
    // Advance time
    const future = Date.now() + 120000;
    jest.spyOn(Date, "now").mockImplementation(() => future);
    
    expect(tracker.isBanned(ip)).toBe(true);
    expect(tracker.recordRequest(ip)).toBe(false);
    
    tracker.unban(ip);
    expect(tracker.isBanned(ip)).toBe(false);
    expect(tracker.recordRequest(ip)).toBe(true);
  });
});
