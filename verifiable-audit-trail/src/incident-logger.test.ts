import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { appendIncidentLog, logSecurityIncident } from "./incident-logger";

describe("incident logger", () => {
  const now = new Date("2026-06-19T12:00:00.000Z");

  it("normalizes incident response events with stable accountability fields", () => {
    const entry = logSecurityIncident(
      {
        title: "Relayer key rotation",
        detail: "Unexpected signer used by relayer service",
        severity: "HIGH",
        source: "anomaly-detector",
        metadata: { address: "GABC", runbook: "IRP-P1" },
      },
      now
    );

    expect(entry.id).toMatch(/^ir_[0-9a-f]{16}$/);
    expect(entry.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.status).toBe("OPEN");
    expect(entry.occurredAt).toBe(now.toISOString());
    expect(entry.loggedAt).toBe(now.toISOString());
    expect(entry.metadata).toEqual({ address: "GABC", runbook: "IRP-P1" });
  });

  it("rejects empty incident details before writing audit history", () => {
    expect(() =>
      logSecurityIncident(
        {
          title: " ",
          detail: "Missing title should fail",
          severity: "LOW",
          source: "runbook",
        },
        now
      )
    ).toThrow("title is required");
  });

  it("appends JSONL incident records for later audit anchoring", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vero-ir-"));
    const filePath = path.join(dir, "incidents.jsonl");
    const entry = logSecurityIncident(
      {
        title: "Emergency pause invoked",
        detail: "P0 runbook step recorded for accountability",
        severity: "CRITICAL",
        source: "incident-response",
        occurredAt: "2026-06-19T11:59:00.000Z",
      },
      now
    );

    appendIncidentLog(filePath, entry);

    const lines = fs.readFileSync(filePath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({
      id: entry.id,
      severity: "CRITICAL",
      source: "incident-response",
      status: "OPEN",
    });
  });
});