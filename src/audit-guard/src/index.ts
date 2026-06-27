/**
 * Vero Audit Guard - Policy as Code Engine
 * Main export for the OPA-based policy engine plus the
 * Logic Error Detector (issue #16) and Weak Crypto Scanner (issue #103).
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
export default PolicyEngine;

// Issue #14: Input sanitization monitor
export { default as InputSanitizationMonitor, scanAndReport } from "./input-sanitization-monitor";
export type {
  InputProbe,
  InputFinding,
  InputScanResult,
  InputMonitorOptions,
  InputSeverity,
  ProbeCategory,
  ValidatorFn,
} from "./input-sanitization-monitor";

// Issue #103: Weak cryptographic primitive scanner
export { default as WeakCryptoScanner } from "./crypto-scanner";
export type {
  CryptoFinding,
  CryptoScanResult,
  CryptoScanOptions,
  CryptoSeverity,
} from "./crypto-scanner";
export { CRYPTO_PATTERNS, CRYPTO_PATTERN_IDS } from "./crypto-patterns";
export type { CryptoPattern, CryptoDetectionContext } from "./crypto-patterns";
