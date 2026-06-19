import * as crypto from "crypto";
import * as fs from "fs";

export type IncidentSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED";

export interface SecurityIncidentInput {
  title: string;
  detail: string;
  severity: IncidentSeverity;
  source: string;
  occurredAt?: string;
  metadata?: Record<string, unknown>;
}

export interface SecurityIncidentLogEntry extends Required<Omit<SecurityIncidentInput, "metadata">> {
  id: string;
  status: IncidentStatus;
  loggedAt: string;
  fingerprint: string;
  metadata: Record<string, unknown>;
}

function requireText(value: string, field: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${field} is required`);
  }
  return trimmed;
}

function buildFingerprint(input: Omit<SecurityIncidentLogEntry, "id" | "fingerprint">): string {
  const payload = JSON.stringify({
    title: input.title,
    detail: input.detail,
    severity: input.severity,
    source: input.source,
    occurredAt: input.occurredAt,
    metadata: input.metadata,
  });

  return crypto.createHash("sha256").update(payload).digest("hex");
}

export function logSecurityIncident(
  incident: SecurityIncidentInput,
  now: Date = new Date()
): SecurityIncidentLogEntry {
  const entryWithoutIds = {
    title: requireText(incident.title, "title"),
    detail: requireText(incident.detail, "detail"),
    severity: incident.severity,
    source: requireText(incident.source, "source"),
    occurredAt: incident.occurredAt ?? now.toISOString(),
    loggedAt: now.toISOString(),
    status: "OPEN" as IncidentStatus,
    metadata: incident.metadata ?? {},
  };
  const fingerprint = buildFingerprint(entryWithoutIds);

  return {
    ...entryWithoutIds,
    id: `ir_${fingerprint.slice(0, 16)}`,
    fingerprint,
  };
}

export function appendIncidentLog(filePath: string, entry: SecurityIncidentLogEntry): void {
  fs.appendFileSync(filePath, `${JSON.stringify(entry)}\n`, "utf8");
}