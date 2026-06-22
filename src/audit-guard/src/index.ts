/**
 * Vero Audit Guard - Policy as Code Engine
 * Main export for the OPA-based policy engine and the
 * Relayer TX scanner (issue #25).
 */

export { default as PolicyEngine } from "./policy-engine";
export type {
  PRData,
  PolicyViolation,
  EvaluationResult,
} from "./policy-engine";

export {
  default as RelayerTxScanner,
  RELAYER_RULES,
} from "./relayer-scanner";
export type {
  TxData,
  WhitelistConfig,
  TxScanResult,
} from "./relayer-scanner";

// Re-export the evaluated PolicyEngine as the package-default for
// backwards-compat with existing callers.
import PolicyEngine from "./policy-engine";
export { BountyForm } from "./ui/BountyForm";
export default PolicyEngine;
