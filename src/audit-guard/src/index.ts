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

export {
  DEFAULT_SEVERITY_THRESHOLD,
  SEVERITY_RANK,
  evaluateSecurityGate,
  evaluateSecurityGateFromJson,
  isBlockingSeverity,
  severityRank,
} from "./security-gate";
export type {
  ScannerFinding,
  ScannerReport,
  ScannerSeverity,
  SecurityGateResult,
} from "./security-gate";
export type {
  LogicPattern,
  DetectionContext,
} from "./logic-patterns";

export {
  default as EventLogScanner,
  generateEventLogReport,
} from "./event-log-scanner";
export type {
  EventLogEntry,
  EventLogIndex,
  EventLogScanResult,
  EventLogScannerOptions,
  EventSeverity,
} from "./event-log-scanner";

export {
  OnCallRoster,
} from "./oncall-roster";
export type {
  OnCallContact,
  OnCallRosterConfig,
  RotationState,
  PagePayload,
} from "./oncall-roster";

// Re-export the evaluated PolicyEngine as the package-default for
// backwards-compat with existing callers.
import PolicyEngine from "./policy-engine";
export default PolicyEngine;
