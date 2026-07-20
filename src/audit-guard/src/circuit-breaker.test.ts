import {
  CircuitBreakerError,
  ProtocolCircuitBreaker,
} from "./circuit-breaker";

describe("ProtocolCircuitBreaker", () => {
  let now: number;

  beforeEach(() => {
    now = 1_000;
  });

  function createBreaker() {
    return new ProtocolCircuitBreaker({
      failureThreshold: 2,
      resetTimeoutMs: 100,
      now: () => now,
    });
  }

  it("opens after the configured number of failures", async () => {
    const breaker = createBreaker();
    const failure = new Error("state transition failed");

    await expect(breaker.execute(() => Promise.reject(failure))).rejects.toBe(failure);
    await expect(breaker.execute(() => Promise.reject(failure))).rejects.toBe(failure);
    expect(breaker.getSnapshot()).toMatchObject({
      state: "OPEN",
      consecutiveFailures: 2,
      lastReason: "state transition failed",
    });
  });

  it("rejects work while open and reports the retry delay", async () => {
    const breaker = createBreaker();
    breaker.trip("manual emergency stop");

    await expect(breaker.execute(() => "blocked")).rejects.toMatchObject({
      name: "CircuitBreakerError",
      retryAfterMs: 100,
    });
  });

  it("allows one half-open probe after the reset timeout", async () => {
    const breaker = createBreaker();
    breaker.trip("temporary protocol failure");
    now += 100;

    let releaseProbe: (() => void) | undefined;
    const probe = breaker.execute(
      () => new Promise<string>((resolve) => (releaseProbe = () => resolve("ok")))
    );
    await expect(breaker.execute(() => "second probe")).rejects.toThrow(
      "protocol circuit is testing recovery"
    );
    releaseProbe!();
    await expect(probe).resolves.toBe("ok");
    expect(breaker.getSnapshot().state).toBe("CLOSED");
  });

  it("does not let an in-flight operation undo a manual trip", async () => {
    const breaker = createBreaker();
    let finish: (() => void) | undefined;
    const operation = breaker.execute(
      () => new Promise<string>((resolve) => (finish = () => resolve("ok")))
    );

    breaker.trip("new critical finding");
    finish!();
    await expect(operation).resolves.toBe("ok");
    expect(breaker.getSnapshot().state).toBe("OPEN");
  });

  it("rejects invalid configuration and reasons", () => {
    expect(() => new ProtocolCircuitBreaker({ failureThreshold: 0 })).toThrow(
      CircuitBreakerError
    );
    expect(() => new ProtocolCircuitBreaker({ resetTimeoutMs: 0 })).toThrow(
      "resetTimeoutMs must be a positive integer"
    );
    const breaker = createBreaker();
    expect(() => breaker.trip(" ")).toThrow("reason must not be empty");
  });

  it("rejects non-callable operations", async () => {
    const breaker = createBreaker();
    await expect(breaker.execute("not an operation" as any)).rejects.toThrow(
      "operation must be a function"
    );
  });

  it("resets state and permits work again", async () => {
    const breaker = createBreaker();
    breaker.trip("operator stop");
    breaker.reset();

    await expect(breaker.execute(() => "resumed")).resolves.toBe("resumed");
    expect(breaker.getSnapshot()).toMatchObject({
      state: "CLOSED",
      consecutiveFailures: 0,
      openedAt: null,
    });
  });
});
