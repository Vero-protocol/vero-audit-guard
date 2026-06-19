/**
 * Vero Audit Guard - Policy as Code Engine
 * Main export for the OPA policy engine
 */

export { default as PolicyEngine } from "./policy-engine";
export type {
  PRData,
  PolicyViolation,
  EvaluationResult,
} from "./policy-engine";

// Re-export for convenience
import PolicyEngine from "./policy-engine";
export default PolicyEngine;
