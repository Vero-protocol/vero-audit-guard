import { GasProfiler, GasProfileRequest } from "./gas-profiler";

describe("GasProfiler", () => {
  let profiler: GasProfiler;

  beforeEach(() => {
    profiler = new GasProfiler();
  });

  it("should calculate correct total gas for a simple transaction", () => {
    const request: GasProfileRequest = {
      transactionId: "tx-123",
      operations: [
        { type: "transfer", payloadSize: 200, complexity: "LOW" },
      ],
      signaturesCount: 1,
    };

    const result = profiler.simulate(request);

    expect(result.ok).toBe(true);
    // Base(100) + Signature(500) + Operations(100) + Payload(400) = 1100
    expect(result.totalGas).toBe(1100);
    expect(result.severity).toBe("LOW");
    expect(result.warnings).toHaveLength(0);
  });

  it("should flag HIGH severity for transactions nearing the limit", () => {
    const request: GasProfileRequest = {
      operations: [
        { type: "deploy", payloadSize: 4_000_000, complexity: "HIGH" },
      ],
      signaturesCount: 2,
    };

    const result = profiler.simulate(request);
    
    expect(result.ok).toBe(true);
    // Payload alone is 8,000,000 gas, which is 80% of limit
    expect(result.severity).toBe("HIGH");
    expect(result.warnings).toContain("Total gas is dangerously close to the maximum limit (over 80%)");
  });

  it("should return an error for invalid input", () => {
    // @ts-ignore - intentional invalid input
    const result = profiler.simulate({ operations: "not-an-array", signaturesCount: 1 });
    
    expect(result.ok).toBe(false);
    expect(result.error).toBe("Invalid request: operations must be an array");
  });

  it("should warn about high number of signatures", () => {
    const request: GasProfileRequest = {
      operations: [],
      signaturesCount: 15, // > 10 triggers warning
    };

    const result = profiler.simulate(request);

    expect(result.ok).toBe(true);
    expect(result.warnings).toContain("High number of signatures detected, which increases transaction size and cost");
  });
});
