import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import EventLogScanner from "./event-log-scanner";

describe("EventLogScanner", () => {
  const scanner = new EventLogScanner();

  it("indexes parsed JSONL events by type, actor, and repository", () => {
    const result = scanner.scanText(
      [
        JSON.stringify({
          id: "evt-1",
          timestamp: "2026-06-22T00:00:00.000Z",
          event_type: "build_started",
          actor: "alice",
          repository: "vero/audit-guard",
        }),
        JSON.stringify({
          id: "evt-2",
          timestamp: "2026-06-22T00:01:00.000Z",
          event_type: "build_finished",
          actor: "alice",
          repository: "vero/audit-guard",
        }),
      ].join("\n"),
      { source: "relay-events.log", scannedAt: "2026-06-22T00:02:00.000Z" }
    );

    expect(result.totalEvents).toBe(2);
    expect(result.index.byType.build_started).toHaveLength(1);
    expect(result.index.byActor.alice).toHaveLength(2);
    expect(result.index.byRepository["vero/audit-guard"]).toHaveLength(2);
    expect(result.scannedAt).toBe("2026-06-22T00:02:00.000Z");
  });

  it("filters sensitive access events and records matched signals", () => {
    const result = scanner.scanText(
      JSON.stringify({
        timestamp: "2026-06-22T00:03:00.000Z",
        eventType: "unauthorized_access",
        actor: "mallory",
        repository: "vero/audit-guard",
        message: "access denied for admin settings",
      })
    );

    expect(result.sensitiveCount).toBe(1);
    expect(result.sensitiveEvents[0].severity).toBe("HIGH");
    expect(result.sensitiveEvents[0].matchedSignals).toEqual(
      expect.arrayContaining(["unauthorized_access", "access denied", "admin"])
    );
  });

  it("parses key=value log lines without dropping visibility", () => {
    const result = scanner.scanText(
      "timestamp=2026-06-22T00:04:00.000Z event=permission_change user=bob repository=vero/audit-guard"
    );

    expect(result.totalEvents).toBe(1);
    expect(result.events[0].eventType).toBe("permission_change");
    expect(result.events[0].actor).toBe("bob");
    expect(result.sensitiveCount).toBe(1);
  });

  it("keeps malformed text lines as searchable events", () => {
    const result = scanner.scanText("plain relay line mentioning token exposure");

    expect(result.totalEvents).toBe(1);
    expect(result.events[0].eventType).toBe("unknown");
    expect(result.events[0].message).toContain("token exposure");
    expect(result.sensitiveCount).toBe(1);
  });

  it("scans a log file and emits a markdown report", () => {
    const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "vero-events-"));
    const logPath = path.join(rootDir, "relay-events.log");
    fs.writeFileSync(
      logPath,
      `${JSON.stringify({ eventType: "secret_access", actor: "bot" })}\n`,
      "utf8"
    );

    try {
      const result = scanner.scanFile(logPath);
      const report = scanner.generateReport(result);

      expect(result.source).toBe(logPath);
      expect(result.sensitiveCount).toBe(1);
      expect(report).toContain("# Event Log Scan");
      expect(report).toContain("secret_access");
    } finally {
      fs.rmSync(rootDir, { recursive: true, force: true });
    }
  });
});
