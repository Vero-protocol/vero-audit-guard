/**
 * Vero Audit Guard - Policy as Code Engine
 *
 * Public surface for the OPA-based policy engine, the Logic Error
 * Detector (issue #16), and the Relayer Tx Scanner (issue #25).
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

// ----------------------------------------------------------------------------
// Relayer Tx Scanner (issue #25)
// Additive — does not modify the existing LogicErrorDetector surface.
// ----------------------------------------------------------------------------
export {
  default as RelayerTxScanner,
  normalizeSignerKey,
} from "./relayer-scanner";
export type {
  AuthorizationStatus,
  RelayerFinding,
  RelayerOperation,
  RelayerScanOptions,
  RelayerScanResult,
  RelayerSeverity,
  RelayerSignature,
  RelayerTransaction,
} from "./relayer-scanner";

export {
  RELAYER_PATTERNS,
  RELAYER_PATTERN_IDS,
} from "./relayer-patterns";
export type { RelayerCheckPattern, RelayerContext } from "./relayer-patterns";

// Re-export the evaluated PolicyEngine as the package-default for
// backwards-compat with existing callers.
import PolicyEngine from "./policy-engine";
export { BountyForm } from "./ui/BountyForm";
export default PolicyEngine;
