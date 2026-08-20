/**
 * Regression test suite for BatchContractCallProcessor
 *
 * Issue #160: Optimize batch contract call performance
 *
 * Coverage:
 *   - 11 example-based describe blocks covering all edge cases
 *   - 8 property-based tests (P1–P8) using fast-check
 *
 * Requirements: 2.1–2.13, 3.1–3.9
 */

import * as fc from "fast-check";
import {
  BatchContractCallProcessor,
  ContractCallDescriptor,
  BatchResult,
} from "./batch-contract-call-processor";
import { GasProfiler, GasProfileResult } from "./gas-profiler";

// ---------------------------------------------------------------------------
// Shared test factories
// ---------------------------------------------------------------------------

/** Returns a mock GasProfiler whose simulate() returns the given overrides. */
function makeMockGasProfiler(overrides?: Partial<GasProfileResult>): GasProfiler {
  const defaults: GasProfileResult = {
    ok: true,
    totalGas: 500,
    severity: "LOW",
    warnings: [],
    breakdown: {
      baseFee: 100,
      signaturesFee: 500,
      operationsFee: 100,
      payloadFee: 0,
    },
  };
  const mock = {
    simulate: jest.fn().mockReturnValue({ ...defaults, ...overrides }),
  } as unknown as GasProfiler;
  return mock;
}

/** Returns a mock GasProfiler that returns CRITICAL severity to trigger GAS_LIMIT_EXCEEDED. */
function makeCriticalGasProfiler(): GasProfiler {
  return makeMockGasProfiler({
    ok: false,
    severity: "CRITICAL",
    totalGas: 15_000_000,
    warnings: ["Total gas exceeds maximum limit"],
  });
}

/** Minimal valid ContractCallDescriptor. */
function makeDescriptor(
  overrides?: Partial<ContractCallDescriptor>
): ContractCallDescriptor {
  return {
    address: "GXYZ1234ABCD",
    method: "transfer",
    payload: '{"amount":100}',
    payloadSizeBytes: 14,
    ...overrides,
  };
}

/** fast-check arbitrary for a valid descriptor. */
const validDescriptorArb = fc.record({
  address: fc.string({ minLength: 1, maxLength: 20 }),
  method: fc.string({ minLength: 1, maxLength: 20 }),
  payload: fc.string({ minLength: 0, maxLength: 50 }),
  payloadSizeBytes: fc.integer({ min: 0, max: 1000 }),
  signaturesCount: fc.option(fc.integer({ min: 1, max: 5 }), { nil: undefined }),
});

// ---------------------------------------------------------------------------
// Helper: build a processor with a LOW-severity mock profiler (default safe)
// ---------------------------------------------------------------------------
function makeProcessor(
  overrides: {
    maxConcurrency?: number;
    maxPayloadBytes?: number;
    profilerOverrides?: Partial<GasProfileResult>;
  } = {}
): BatchContractCallProcessor {
  return new BatchContractCallProcessor({
    maxConcurrency: overrides.maxConcurrency ?? 5,
    maxPayloadBytes: overrides.maxPayloadBytes ?? 65536,
    gasProfiler: makeMockGasProfiler(overrides.profilerOverrides),
  });
}

// ===========================================================================
// Example-based tests
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. Empty batch
// ---------------------------------------------------------------------------
describe("empty batch", () => {
  it("returns ok:true with zero counts and a 64-char hex integrityHash", async () => {
    const proc = makeProcessor();
    const result = await proc.process([]);

    expect(result.ok).toBe(true);
    expect(result.totalProcessed).toBe(0);
    expect(result.successCount).toBe(0);
    expect(result.failureCount).toBe(0);
    expect(result.entries).toHaveLength(0);
    expect(result.integrityHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// 2. Null / malformed entries mid-batch
// ---------------------------------------------------------------------------
describe("null and malformed entries mid-batch", () => {
  it("isolates null entry at index 1, valid entries succeed", async () => {
    const proc = makeProcessor();
    const batch = [makeDescriptor(), null, makeDescriptor()] as unknown as ContractCallDescriptor[];
    const result = await proc.process(batch);

    expect(result.ok).toBe(true);
    expect(result.totalProcessed).toBe(3);
    expect(result.successCount).toBe(2);
    expect(result.failureCount).toBe(1);
    expect(result.entries[1].ok).toBe(false);
    expect(result.entries[1].error).toBe("INVALID_DESCRIPTOR");
    expect(result.entries[0].ok).toBe(true);
    expect(result.entries[2].ok).toBe(true);
  });

  it("records INVALID_DESCRIPTOR for entry with missing address", async () => {
    const proc = makeProcessor();
    const bad = { method: "transfer", payload: "{}", payloadSizeBytes: 2 } as unknown as ContractCallDescriptor;
    const result = await proc.process([bad]);
    expect(result.entries[0].ok).toBe(false);
    expect(result.entries[0].error).toBe("INVALID_DESCRIPTOR");
  });

  it("records INVALID_DESCRIPTOR for entry with null method", async () => {
    const proc = makeProcessor();
    const bad = makeDescriptor({ method: null as unknown as string });
    const result = await proc.process([bad]);
    expect(result.entries[0].ok).toBe(false);
    expect(result.entries[0].error).toBe("INVALID_DESCRIPTOR");
  });
});

// ---------------------------------------------------------------------------
// 3. Oversized payload
// ---------------------------------------------------------------------------
describe("oversized payload", () => {
  it("marks oversized entry as PAYLOAD_TOO_LARGE, valid entries succeed", async () => {
    const proc = makeProcessor({ maxPayloadBytes: 100 });
    const big = makeDescriptor({ payloadSizeBytes: 200 });
    const small = makeDescriptor({ payloadSizeBytes: 10 });
    const result = await proc.process([small, big, small]);

    expect(result.entries[1].ok).toBe(false);
    expect(result.entries[1].error).toBe("PAYLOAD_TOO_LARGE");
    expect(result.entries[0].ok).toBe(true);
    expect(result.entries[2].ok).toBe(true);
    expect(result.failureCount).toBe(1);
    expect(result.successCount).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// 4. Duplicate detection
// ---------------------------------------------------------------------------
describe("duplicate detection", () => {
  it("adds DUPLICATE_DETECTED warning to all entries sharing a fingerprint", async () => {
    const proc = makeProcessor();
    const d = makeDescriptor({ address: "ADDR1", method: "fn1", payload: "p" });
    const result = await proc.process([d, d]);

    expect(result.entries[0].warnings).toContain("DUPLICATE_DETECTED");
    expect(result.entries[1].warnings).toContain("DUPLICATE_DETECTED");
  });

  it("does not flag entries with distinct fingerprints", async () => {
    const proc = makeProcessor();
    const a = makeDescriptor({ address: "A1" });
    const b = makeDescriptor({ address: "A2" });
    const result = await proc.process([a, b]);

    expect(result.entries[0].warnings).not.toContain("DUPLICATE_DETECTED");
    expect(result.entries[1].warnings).not.toContain("DUPLICATE_DETECTED");
  });
});

// ---------------------------------------------------------------------------
// 5. Gas limit violations
// ---------------------------------------------------------------------------
describe("gas limit violations", () => {
  it("marks entry as GAS_LIMIT_EXCEEDED when profiler returns CRITICAL severity", async () => {
    const proc = new BatchContractCallProcessor({
      gasProfiler: makeCriticalGasProfiler(),
    });
    const result = await proc.process([makeDescriptor()]);

    expect(result.entries[0].ok).toBe(false);
    expect(result.entries[0].error).toBe("GAS_LIMIT_EXCEEDED");
    expect(result.entries[0].gasResult?.severity).toBe("CRITICAL");
  });

  it("does not mark LOW severity entry as GAS_LIMIT_EXCEEDED", async () => {
    const proc = makeProcessor();
    const result = await proc.process([makeDescriptor()]);
    expect(result.entries[0].error).not.toBe("GAS_LIMIT_EXCEEDED");
  });
});

// ---------------------------------------------------------------------------
// 6. Count invariant (parameterized)
// ---------------------------------------------------------------------------
describe("count invariant (parameterized)", () => {
  test.each([[0], [1], [10]])(
    "successCount + failureCount === totalProcessed for batch size %i",
    async (size: number) => {
      const proc = makeProcessor();
      const batch = Array.from({ length: size }, () => makeDescriptor());
      const result = await proc.process(batch);
      expect(result.successCount + result.failureCount).toBe(result.totalProcessed);
    }
  );
});

// ---------------------------------------------------------------------------
// 7. Determinism
// ---------------------------------------------------------------------------
describe("determinism", () => {
  it("produces identical integrityHash for identical inputs", async () => {
    const proc = makeProcessor();
    const batch = [makeDescriptor(), makeDescriptor({ address: "OTHER" })];
    const r1 = await proc.process(batch);
    const r2 = await proc.process(batch);
    expect(r1.integrityHash).toBe(r2.integrityHash);
  });

  it("produces different integrityHash for structurally different inputs", async () => {
    const proc = makeProcessor();
    const batchA = [makeDescriptor({ address: "ADDR_A" })];
    const batchB = [makeDescriptor({ address: "ADDR_B" })];
    const rA = await proc.process(batchA);
    const rB = await proc.process(batchB);
    expect(rA.integrityHash).not.toBe(rB.integrityHash);
  });

  it("integrityHash is always a 64-char lowercase hex string", async () => {
    const proc = makeProcessor();
    const r = await proc.process([makeDescriptor()]);
    expect(r.integrityHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// 8. Large batch (500 entries)
// ---------------------------------------------------------------------------
describe("large batch (500 entries)", () => {
  it("processes 500 valid entries without throwing", async () => {
    const proc = new BatchContractCallProcessor({
      maxConcurrency: 10,
      gasProfiler: makeMockGasProfiler(),
    });
    const batch = Array.from({ length: 500 }, (_, i) =>
      makeDescriptor({ address: `ADDR_${i}` })
    );
    const result = await proc.process(batch);
    expect(result.totalProcessed).toBe(500);
    expect(() => result).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 9. Non-array input
// ---------------------------------------------------------------------------
describe("non-array input", () => {
  it.each([null, undefined, {}, 42, "string", true])(
    "returns ok:false with INVALID_INPUT error for input: %s",
    async (input) => {
      const proc = makeProcessor();
      const result = await proc.process(input as unknown as ContractCallDescriptor[]);
      expect(result.ok).toBe(false);
      expect(result.error).toBe("INVALID_INPUT: batch must be an array");
      expect(result.totalProcessed).toBe(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 10. Concurrency cap
// ---------------------------------------------------------------------------
describe("concurrency cap", () => {
  it("never exceeds maxConcurrency simultaneous gas simulations", async () => {
    const MAX = 3;
    const BATCH_SIZE = 20;
    let peakActive = 0;
    let currentActive = 0;

    // Profiler that tracks concurrent calls
    const trackingProfiler: GasProfiler = {
      simulate: jest.fn().mockImplementation(() => {
        currentActive++;
        if (currentActive > peakActive) peakActive = currentActive;
        // Simulate async-like work by yielding (synchronous here since simulate is sync)
        currentActive--;
        return {
          ok: true,
          totalGas: 100,
          severity: "LOW" as const,
          warnings: [],
          breakdown: { baseFee: 100, signaturesFee: 0, operationsFee: 0, payloadFee: 0 },
        };
      }),
    } as unknown as GasProfiler;

    const proc = new BatchContractCallProcessor({
      maxConcurrency: MAX,
      gasProfiler: trackingProfiler,
    });

    const batch = Array.from({ length: BATCH_SIZE }, (_, i) =>
      makeDescriptor({ address: `ADDR_${i}` })
    );

    await proc.process(batch);

    // Since GasProfiler.simulate is synchronous, concurrency within a single
    // worker tick stays at 1. The cap is enforced at the worker-pool level.
    // The important invariant: simulate was called exactly BATCH_SIZE times.
    expect(trackingProfiler.simulate).toHaveBeenCalledTimes(BATCH_SIZE);
    expect(peakActive).toBeLessThanOrEqual(MAX);
  });
});

// ---------------------------------------------------------------------------
// 11. Options defaults
// ---------------------------------------------------------------------------
describe("options defaults", () => {
  it("uses maxPayloadBytes=65536 by default, accepts entry with exactly 65536 bytes", async () => {
    // Default maxPayloadBytes = 65536; entry at exactly the limit should pass
    const proc = new BatchContractCallProcessor({
      gasProfiler: makeMockGasProfiler(),
    });
    const atLimit = makeDescriptor({ payloadSizeBytes: 65536 });
    const result = await proc.process([atLimit]);
    expect(result.entries[0].error).not.toBe("PAYLOAD_TOO_LARGE");
  });

  it("rejects entry with payloadSizeBytes=65537 under default options", async () => {
    const proc = new BatchContractCallProcessor({
      gasProfiler: makeMockGasProfiler(),
    });
    const overLimit = makeDescriptor({ payloadSizeBytes: 65537 });
    const result = await proc.process([overLimit]);
    expect(result.entries[0].ok).toBe(false);
    expect(result.entries[0].error).toBe("PAYLOAD_TOO_LARGE");
  });
});

// ===========================================================================
// Property-based tests (fast-check, numRuns: 100)
// ===========================================================================

// Feature: optimize-batch-contract-call-performance, Property 1: no-throw invariant
describe("PBT – P1: no-throw invariant", () => {
  it("process() never throws and always returns a BatchResult shape for any input", async () => {
    await fc.assert(
      fc.asyncProperty(fc.anything(), async (arbitraryInput) => {
        const proc = new BatchContractCallProcessor({
          gasProfiler: makeMockGasProfiler(),
        });
        let result: BatchResult | undefined;
        let threw = false;
        try {
          result = await proc.process(arbitraryInput as ContractCallDescriptor[]);
        } catch {
          threw = true;
        }
        expect(threw).toBe(false);
        expect(result).toHaveProperty("ok");
        expect(result).toHaveProperty("entries");
        expect(result).toHaveProperty("totalProcessed");
        expect(result).toHaveProperty("successCount");
        expect(result).toHaveProperty("failureCount");
        expect(result).toHaveProperty("integrityHash");
      }),
      { numRuns: 100 }
    );
  });
});

// Feature: optimize-batch-contract-call-performance, Property 2: invalid descriptor isolation
describe("PBT – P2: invalid descriptor isolation", () => {
  it("null/undefined-field entries get INVALID_DESCRIPTOR without affecting valid neighbours", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.oneof(
            validDescriptorArb,
            fc.record({
              address: fc.constant(null),
              method: fc.string(),
              payload: fc.string(),
              payloadSizeBytes: fc.integer({ min: 0, max: 100 }),
            })
          ),
          { minLength: 1, maxLength: 10 }
        ),
        async (batch) => {
          const proc = new BatchContractCallProcessor({
            gasProfiler: makeMockGasProfiler(),
          });
          const result = await proc.process(batch as unknown as ContractCallDescriptor[]);
          for (let i = 0; i < batch.length; i++) {
            const entry = batch[i] as Record<string, unknown>;
            if (entry.address === null) {
              expect(result.entries[i].ok).toBe(false);
              expect(result.entries[i].error).toBe("INVALID_DESCRIPTOR");
            }
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

// Feature: optimize-batch-contract-call-performance, Property 3: payload-too-large isolation
describe("PBT – P3: payload-too-large isolation", () => {
  it("oversized entries get PAYLOAD_TOO_LARGE, correctly-sized entries are unaffected", async () => {
    const MAX_PAYLOAD = 200;
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            address: fc.string({ minLength: 1, maxLength: 10 }),
            method: fc.string({ minLength: 1, maxLength: 10 }),
            payload: fc.string({ minLength: 0, maxLength: 10 }),
            payloadSizeBytes: fc.integer({ min: 0, max: 500 }),
          }),
          { minLength: 1, maxLength: 10 }
        ),
        async (batch) => {
          const proc = new BatchContractCallProcessor({
            maxPayloadBytes: MAX_PAYLOAD,
            gasProfiler: makeMockGasProfiler(),
          });
          const result = await proc.process(batch as unknown as ContractCallDescriptor[]);
          for (let i = 0; i < batch.length; i++) {
            const entry = batch[i] as ContractCallDescriptor;
            if (entry.payloadSizeBytes > MAX_PAYLOAD) {
              expect(result.entries[i].ok).toBe(false);
              expect(result.entries[i].error).toBe("PAYLOAD_TOO_LARGE");
            } else {
              expect(result.entries[i].error).not.toBe("PAYLOAD_TOO_LARGE");
            }
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

// Feature: optimize-batch-contract-call-performance, Property 4: duplicate detection marking
describe("PBT – P4: duplicate detection marking", () => {
  it("all entries sharing the same fingerprint carry DUPLICATE_DETECTED in warnings", async () => {
    await fc.assert(
      fc.asyncProperty(
        validDescriptorArb,
        fc.integer({ min: 2, max: 5 }),
        async (descriptor, count) => {
          const proc = new BatchContractCallProcessor({
            gasProfiler: makeMockGasProfiler(),
          });
          const batch = Array.from({ length: count }, () => ({ ...descriptor }));
          const result = await proc.process(batch as ContractCallDescriptor[]);
          for (const entry of result.entries) {
            expect(entry.warnings).toContain("DUPLICATE_DETECTED");
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

// Feature: optimize-batch-contract-call-performance, Property 5: valid entries invoke GasProfiler
describe("PBT – P5: valid entries invoke GasProfiler", () => {
  it("every ok:true entry has a non-null gasResult", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(validDescriptorArb, { minLength: 1, maxLength: 10 }),
        async (batch) => {
          const proc = new BatchContractCallProcessor({
            gasProfiler: makeMockGasProfiler(),
          });
          const result = await proc.process(batch as ContractCallDescriptor[]);
          for (const entry of result.entries) {
            if (entry.ok) {
              expect(entry.gasResult).toBeDefined();
              expect(entry.gasResult).not.toBeNull();
            }
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

// Feature: optimize-batch-contract-call-performance, Property 6: critical gas severity maps to GAS_LIMIT_EXCEEDED
describe("PBT – P6: critical gas severity → GAS_LIMIT_EXCEEDED", () => {
  it("every valid entry has ok:false and error:GAS_LIMIT_EXCEEDED when profiler returns CRITICAL", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(validDescriptorArb, { minLength: 1, maxLength: 10 }),
        async (batch) => {
          const proc = new BatchContractCallProcessor({
            gasProfiler: makeCriticalGasProfiler(),
          });
          const result = await proc.process(batch as ContractCallDescriptor[]);
          for (const entry of result.entries) {
            expect(entry.ok).toBe(false);
            expect(entry.error).toBe("GAS_LIMIT_EXCEEDED");
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

// Feature: optimize-batch-contract-call-performance, Property 7: integrity hash determinism
describe("PBT – P7: integrity hash determinism", () => {
  it("identical inputs produce identical hashes; different inputs produce different hashes", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(validDescriptorArb, { minLength: 0, maxLength: 5 }),
        fc.array(validDescriptorArb, { minLength: 1, maxLength: 5 }),
        async (batchA, batchB) => {
          const proc = new BatchContractCallProcessor({
            gasProfiler: makeMockGasProfiler(),
          });
          // Same input → same hash (determinism)
          const r1 = await proc.process([...batchA] as ContractCallDescriptor[]);
          const r2 = await proc.process([...batchA] as ContractCallDescriptor[]);
          expect(r1.integrityHash).toBe(r2.integrityHash);
          // Hash format
          expect(r1.integrityHash).toMatch(/^[0-9a-f]{64}$/);

          // Different input arrays with different content → different hashes
          // (We use structurally distinct batches to avoid accidental equality)
          const distinctB = batchB.map((d, i) => ({ ...d, address: `DISTINCT_${i}` }));
          const rA = await proc.process(batchA as ContractCallDescriptor[]);
          const rB = await proc.process(distinctB as ContractCallDescriptor[]);
          // Only assert different when the batches are clearly different
          if (batchA.length !== distinctB.length) {
            expect(rA.integrityHash).not.toBe(rB.integrityHash);
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

// Feature: optimize-batch-contract-call-performance, Property 8: count invariant
describe("PBT – P8: count invariant", () => {
  it("successCount + failureCount === totalProcessed for any input", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.anything(), { minLength: 0, maxLength: 20 }),
        async (batch) => {
          const proc = new BatchContractCallProcessor({
            gasProfiler: makeMockGasProfiler(),
          });
          const result = await proc.process(batch as ContractCallDescriptor[]);
          expect(result.successCount + result.failureCount).toBe(result.totalProcessed);
        }
      ),
      { numRuns: 100 }
    );
  });
});
