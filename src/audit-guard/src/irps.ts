import { OnCallRoster } from "./oncall-roster";

/**
 * IRP (Incident Response Protocol) utilities for the audit guard.
 * Pages the on‑call roster and provides circuit breaker capabilities.
 */

export interface IncidentReport {
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  description: string;
  repository: string;
  findings?: Array<{ rule: string; detail: string }>;
}

let rosterInstance: OnCallRoster | null = null;

function getRoster(): OnCallRoster {
  if (!rosterInstance) {
    rosterInstance = new OnCallRoster();
  }
  return rosterInstance;
}

export function resetRoster(): void {
  rosterInstance = null;
}

/**
 * Escalate an incident by paging the on‑call roster.
 * Returns the list of contacts that were notified.
 */
export async function escalateIncident(incident: IncidentReport): Promise<void> {
  const roster = getRoster();
  const message = `[${incident.severity}] ${incident.title} — ${incident.description}`;
  console.log(`[IRP] Escalating incident: ${message}`);
  await roster.pageCurrentOnCall(message, incident.severity, incident.repository);
  console.log(`[IRP] On‑call roster notified for ${incident.severity} incident.`);
}

/**
 * Trigger a circuit breaker that pauses the protocol and pages the on‑call manager.
 * Used when a CRITICAL finding is detected that requires immediate human intervention.
 */
export async function triggerCircuitBreaker(reason?: string): Promise<void> {
  const msg = reason || "CRITICAL finding — manual intervention required";
  console.log(`[IRP] Circuit breaker triggered: ${msg}`);

  const roster = getRoster();
  await roster.pageCurrentOnCall(msg, "CRITICAL", "vero-audit-guard");

  console.log("[IRP] Circuit breaker engaged — protocol paused.");
  return new Promise((resolve) => setTimeout(resolve, 500));
}
