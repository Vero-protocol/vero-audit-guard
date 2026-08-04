/**
 * Batch Contract Call Processor
 *
 * Issue #160: Optimize batch contract call performance
 *
 * Processes arrays of ContractCallDescriptor entries with:
 *   - Configurable concurrency control (queue-draining worker pool)
 *   - Partial-failure isolation (one failing entry never blocks the rest)
 *   - Duplicate detection via address::method::payload fingerprints
 *   - SHA-256 integrity hash over key-sorted JSON of the entries array
 *
 * ZK-readiness guarantee: process() is a pure function of its inputs.
 * No Date.now(), Math.random(), or global state mutations in core logic.
 */

import { createHash } from "crypto";
import { GasProfiler, GasProfileResult } from "./gas-profiler";

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

/** Describes a single contract call to simulate in a batch. */
export interface ContractCallDescriptor {
  address: string;
  method: string;
  payload: string;
  /** Byte length of the payload — used by GasProfiler. */
  payloadSizeBytes: number;
  /** Number of required signatures; defaults to 1 inside GasProfiler call. */
  signaturesCount?: number;
}

/** Configuration options for a BatchContractCallProcessor instance. */
export interface BatchProcessorOptions {
  /**
   * Maximum number of concurrently executing gas simulations.
   * Default: 5. Minimum enforced: 1.
   */
  maxConcurrency?: number;
  /**
   * Maximum allowed payload size in bytes per entry.
   * Default: 65536 (64 KiB). Minimum enforced: 1.
   */
  maxPayloadBytes?: number;
  /**
   * Injectable GasProfiler instance (for test mocking).
   * Default: new GasProfiler().
   */
  gasProfiler?: GasProfiler;
}

/** Result for a single entry in the batch. */
export interface BatchEntryResult {
  ok: boolean;
  index: number;
  address?: string;
  method?: string;
  /** Populated for structurally valid entries that reached gas simulation. */
  gasResult?: GasProfileResult;
  /** Contains "DUPLICATE_DETECTED" when this entry shares a fingerprint with another. */
  warnings: string[];
  error?: string;
}

/** Aggregated result returned by BatchContractCallProcessor.process(). */
export interface BatchResult {
  /**
   * true for any array input (even with per-entry failures).
   * false only when the top-level input is not an array.
   */
  ok: boolean;
  entries: BatchEntryResult[];
  totalProcessed: number;
  successCount: number;
  failureCount: number;
  /** SHA-256 hex digest over key-sorted JSON of the entries array. */
  integrityHash: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Concurrency helper — queue-draining worker loop
// ---------------------------------------------------------------------------

/**
 * Runs `tasks` with at most `maxConcurrency` active at a time.
 * Workers share a counter; incrementing before `await` is race-free in JS.
 * Preserves result order regardless of completion order.
 */
async function processWithConcurrency<T>(
  tasks: Array<() => Promise<T>>,
  maxConcurrency: number
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < tasks.length) {
      const i = nextIndex++;
      results[i] = await tasks[i]();
    }
  }

  const workerCount = Math.min(maxConcurrency, tasks.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

// ---------------------------------------------------------------------------
// BatchContractCallProcessor
// ---------------------------------------------------------------------------

export class BatchContractCallProcessor {
  private readonly maxConcurrency: number;
  private readonly maxPayloadBytes: number;
  private readonly gasProfiler: GasProfiler;

  constructor(options: BatchProcessorOptions = {}) {
    this.maxConcurrency = Math.max(1, options.maxConcurrency ?? 5);
    this.maxPayloadBytes = Math.max(1, options.maxPayloadBytes ?? 65536);
    this.gasProfiler = options.gasProfiler ?? new GasProfiler();
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Process a batch of ContractCallDescriptors.
   *
   * Never throws — all per-entry failures are captured in BatchEntryResult.
   * Accepts `unknown` so TypeScript callers cannot accidentally skip the
   * non-array guard at the call site.
   */
  public async process(batch: unknown): Promise<BatchResult> {
    // Guard 1: non-array input
    if (!Array.isArray(batch)) {
      return {
        ok: false,
        entries: [],
        totalProcessed: 0,
        successCount: 0,
        failureCount: 0,
        integrityHash: this.computeIntegrityHash([]),
        error: "INVALID_INPUT: batch must be an array",
      };
    }

    // Guard 2: empty array — deterministic short-circuit
    if (batch.length === 0) {
      return {
        ok: true,
        entries: [],
        totalProcessed: 0,
        successCount: 0,
        failureCount: 0,
        integrityHash: this.computeIntegrityHash([]),
      };
    }

    // --- Pre-processing: detect duplicates before touching the pool ----------
    const fingerprintToIndices = new Map<string, number[]>();
    for (let i = 0; i < batch.length; i++) {
      const entry = batch[i];
      if (entry !== null && entry !== undefined && typeof entry === "object") {
        const fp = this.fingerprint(entry as ContractCallDescriptor);
        const existing = fingerprintToIndices.get(fp) ?? [];
        existing.push(i);
        fingerprintToIndices.set(fp, existing);
      }
    }
    const duplicateIndices = new Set<number>();
    for (const indices of fingerprintToIndices.values()) {
      if (indices.length > 1) {
        for (const i of indices) duplicateIndices.add(i);
      }
    }

    // --- Per-entry validation: pre-fail invalid entries, queue valid ones ----
    // entrySlots preserves insertion order across the two paths (sync + async).
    const entrySlots: Array<BatchEntryResult | null> = new Array(batch.length).fill(null);
    const poolTasks: Array<{ slotIndex: number; task: () => Promise<BatchEntryResult> }> = [];

    for (let i = 0; i < batch.length; i++) {
      const entry = batch[i];
      const validationError = this.validateDescriptor(entry as ContractCallDescriptor);

      if (validationError !== null) {
        // Record failure immediately — never reaches gas simulation
        entrySlots[i] = {
          ok: false,
          index: i,
          warnings: duplicateIndices.has(i) ? ["DUPLICATE_DETECTED"] : [],
          error: validationError,
        };
      } else {
        const descriptor = entry as ContractCallDescriptor;
        const isDuplicate = duplicateIndices.has(i);
        const slotIndex = i;
        poolTasks.push({
          slotIndex,
          task: () => this.processEntry(descriptor, slotIndex, isDuplicate),
        });
      }
    }

    // --- Run valid entries through the bounded concurrency pool --------------
    if (poolTasks.length > 0) {
      const poolResults = await processWithConcurrency(
        poolTasks.map((t) => t.task),
        this.maxConcurrency
      );
      for (let j = 0; j < poolTasks.length; j++) {
        entrySlots[poolTasks[j].slotIndex] = poolResults[j];
      }
    }

    const entries = entrySlots as BatchEntryResult[];
    const successCount = entries.filter((e) => e.ok).length;
    const failureCount = entries.filter((e) => !e.ok).length;

    return {
      ok: true,
      entries,
      totalProcessed: entries.length,
      successCount,
      failureCount,
      integrityHash: this.computeIntegrityHash(entries),
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Calls GasProfiler for one validated descriptor.
   * Maps severity:CRITICAL → GAS_LIMIT_EXCEEDED.
   * Wraps unexpected profiler throws in a PROFILER_ERROR result.
   */
  private async processEntry(
    descriptor: ContractCallDescriptor,
    index: number,
    isDuplicate: boolean
  ): Promise<BatchEntryResult> {
    const warnings: string[] = isDuplicate ? ["DUPLICATE_DETECTED"] : [];

    try {
      const gasResult = this.gasProfiler.simulate({
        operations: [
          {
            type: descriptor.method,
            payloadSize: descriptor.payloadSizeBytes,
          },
        ],
        signaturesCount: descriptor.signaturesCount ?? 1,
      });

      if (gasResult.severity === "CRITICAL") {
        return {
          ok: false,
          index,
          address: descriptor.address,
          method: descriptor.method,
          gasResult,
          warnings,
          error: "GAS_LIMIT_EXCEEDED",
        };
      }

      return {
        ok: gasResult.ok,
        index,
        address: descriptor.address,
        method: descriptor.method,
        gasResult,
        warnings,
        error: gasResult.error,
      };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return { ok: false, index, warnings, error: `PROFILER_ERROR: ${msg}` };
    }
  }

  /**
   * SHA-256 over key-sorted JSON of the entries array.
   * Sorting keys guarantees deterministic output regardless of insertion order.
   * Empty array → SHA-256("[]") which is a well-defined 64-char hex string.
   */
  private computeIntegrityHash(entries: BatchEntryResult[]): string {
    const stable = JSON.stringify(entries, (_key, value: unknown) => {
      if (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
      ) {
        const sorted: Record<string, unknown> = {};
        for (const k of Object.keys(value as object).sort()) {
          sorted[k] = (value as Record<string, unknown>)[k];
        }
        return sorted;
      }
      return value;
    });
    return createHash("sha256").update(stable, "utf8").digest("hex");
  }

  /** Deduplication fingerprint for a descriptor. */
  private fingerprint(d: ContractCallDescriptor): string {
    return `${d.address}::${d.method}::${d.payload}`;
  }

  /**
   * Validates a single batch entry before it reaches gas simulation.
   * Returns an error code string on failure, or null if the entry is valid.
   *
   * Validation order:
   *   1. Null / non-object  → INVALID_DESCRIPTOR
   *   2. Missing required fields (address | method | payload)  → INVALID_DESCRIPTOR
   *   3. payloadSizeBytes > maxPayloadBytes  → PAYLOAD_TOO_LARGE
   */
  private validateDescriptor(entry: ContractCallDescriptor): string | null {
    if (entry === null || entry === undefined || typeof entry !== "object") {
      return "INVALID_DESCRIPTOR";
    }

    const d = entry as ContractCallDescriptor;

    if (d.address === null || d.address === undefined) return "INVALID_DESCRIPTOR";
    if (d.method === null || d.method === undefined) return "INVALID_DESCRIPTOR";
    if (d.payload === null || d.payload === undefined) return "INVALID_DESCRIPTOR";

    if (
      typeof d.payloadSizeBytes === "number" &&
      d.payloadSizeBytes > this.maxPayloadBytes
    ) {
      return "PAYLOAD_TOO_LARGE";
    }

    return null;
  }
}

export default BatchContractCallProcessor;
