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

export {
  default as LogicErrorDetector,
} from "./logic-detector";
export type {
  LogicFlawFinding,
  LogicScanResult,
  LogicScanOptions,
  LogicSeverity,
} from "./logic-detector";

export {
  LOGIC_PATTERNS,
  LOGIC_PATTERN_IDS,
} from "./logic-patterns";
export type {
  LogicPattern,
  DetectionContext,
} from "./logic-patterns";

// Re-export the evaluated PolicyEngine as the package-default for
// backwards-compat with existing callers.
import PolicyEngine from "./policy-engine";
export { BountyForm } from "./ui/BountyForm";
export default PolicyEngine;
