/**
 * Vero Audit Guard - Policy as Code Engine
 * Main export for the OPA-based policy engine plus the
 * Logic Error Detector (issue #16).
 */

export { default as PolicyEngine } from "./policy-engine";
export type {
  PRData,
  PolicyViolation,
  EvaluationResult,
} from "./policy-engine";

export { default as LogAnalyzer } from "./log-analyzer";
export type {
  LogEntry,
  LogAnomaly,
  LogAnalyzerConfig,
} from "./log-analyzer";

// Re-export for convenience
import PolicyEngine from "./policy-engine";
export { BountyForm } from "./ui/BountyForm";
export default PolicyEngine;
