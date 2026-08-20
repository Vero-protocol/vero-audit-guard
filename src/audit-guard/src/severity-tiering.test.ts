import SeverityTieringEngine, { ConfirmedEvent } from "./severity-tiering";
import OnCallRoster from "./oncall-roster";
import DashboardClient from "./dashboard-client";

jest.mock("./dashboard-client");
jest.mock("./oncall-roster");

describe("SeverityTieringEngine", () => {
  let engine: SeverityTieringEngine;

  beforeEach(() => {
    jest.clearAllMocks();
    engine = new SeverityTieringEngine();
  });

  describe("Observational-Only Invariant", () => {
    test("verifies logic is strictly observational-only with no on-chain halt authority", () => {
      expect(engine.verifyObservationalOnly()).toBe(true);
    });
  });

  describe("Happy Path Event Classification", () => {
    test("classifies routine event as LOW severity", () => {
      const event: ConfirmedEvent = {
        id: "ev-1",
        eventType: "routine_audit_log",
        source: "event-scanner",
        timestamp: 1000,
        confirmed: true,
      };
      expect(engine.classifyEvent(event)).toBe("LOW");
    });

    test("classifies gas spike event as MEDIUM severity", () => {
      const event: ConfirmedEvent = {
        id: "ev-2",
        eventType: "gas_spike_detected",
        source: "profiler",
        timestamp: 1001,
        confirmed: true,
      };
      expect(engine.classifyEvent(event)).toBe("MEDIUM");
    });

    test("classifies unauthorized access attempt as HIGH severity", () => {
      const event: ConfirmedEvent = {
        id: "ev-3",
        eventType: "unauthorized_access",
        source: "auth-service",
        timestamp: 1002,
        confirmed: true,
      };
      expect(engine.classifyEvent(event)).toBe("HIGH");
    });

    test("classifies token leak as CRITICAL severity", () => {
      const event: ConfirmedEvent = {
        id: "ev-4",
        eventType: "token_leak_detected",
        source: "scanner",
        timestamp: 1003,
        confirmed: true,
      };
      expect(engine.classifyEvent(event)).toBe("CRITICAL");
    });
  });

  describe("Escalation Target Routing", () => {
    test("drives LOW severity escalation to telemetry log only", () => {
      const event: ConfirmedEvent = {
        id: "ev-10",
        eventType: "routine_metric",
        source: "scanner",
        timestamp: 1000,
        confirmed: true,
      };
      const action = engine.evaluateAndEscalate(event);
      expect(action.calculatedTier).toBe("LOW");
      expect(action.escalationTargets).toEqual(["telemetry_log"]);
      expect(action.requiresAck).toBe(false);
      expect(action.observationalOnly).toBe(true);
    });

    test("drives CRITICAL severity escalation to all on-call roles and dashboard", () => {
      const event: ConfirmedEvent = {
        id: "ev-11",
        eventType: "private_key_exposure",
        source: "scanner",
        timestamp: 1000,
        confirmed: true,
      };
      const action = engine.evaluateAndEscalate(event);
      expect(action.calculatedTier).toBe("CRITICAL");
      expect(action.escalationTargets).toEqual([
        "telemetry_log",
        "dashboard_alert",
        "all_on_call_roles",
      ]);
      expect(action.requiresAck).toBe(true);
      expect(action.retryCount).toBe(5);
      expect(action.observationalOnly).toBe(true);
    });
  });

  describe("Burst Window & Value Escalations", () => {
    test("escalates LOW to MEDIUM after burst window threshold met", () => {
      const ev1: ConfirmedEvent = {
        id: "burst-1",
        eventType: "routine_ping",
        source: "healthcheck",
        timestamp: 1000,
        confirmed: true,
      };
      const ev2: ConfirmedEvent = {
        id: "burst-2",
        eventType: "routine_ping",
        source: "healthcheck",
        timestamp: 1010,
        confirmed: true,
      };
      const ev3: ConfirmedEvent = {
        id: "burst-3",
        eventType: "routine_ping",
        source: "healthcheck",
        timestamp: 1020,
        confirmed: true,
      };

      expect(engine.classifyEvent(ev1)).toBe("LOW");
      expect(engine.classifyEvent(ev2)).toBe("LOW");
      expect(engine.classifyEvent(ev3)).toBe("MEDIUM");
    });

    test("escalates high-value transactions to HIGH severity", () => {
      const event: ConfirmedEvent = {
        id: "ev-value",
        eventType: "token_transfer",
        source: "bridge",
        timestamp: 1000,
        confirmed: true,
        value: 5000000,
      };
      expect(engine.classifyEvent(event)).toBe("HIGH");
    });
  });

  describe("Non-Happy-Path & Adversarial Inputs", () => {
    test("rejects unconfirmed events and surfaces failure alert into telemetry stream", () => {
      const unconfirmed: ConfirmedEvent = {
        id: "ev-unconfirmed",
        eventType: "routine_ping",
        source: "scanner",
        timestamp: 1000,
        confirmed: false,
      };

      expect(() => engine.evaluateAndEscalate(unconfirmed)).toThrow(
        "Event must be confirmed to evaluate severity tiering"
      );

      const stream = engine.getTelemetryStream();
      expect(stream.length).toBe(1);
      expect(stream[0].recordType).toBe("failure_surfaced");
      expect(stream[0].detail).toContain("Event processing failed");
    });

    test("throws error for empty event ID", () => {
      const emptyId: ConfirmedEvent = {
        id: "",
        eventType: "routine_ping",
        source: "scanner",
        timestamp: 1000,
        confirmed: true,
      };

      expect(() => engine.evaluateAndEscalate(emptyId)).toThrow(
        "Event ID cannot be empty"
      );
    });

    test("throws error for negative timestamp", () => {
      const badTime: ConfirmedEvent = {
        id: "ev-badtime",
        eventType: "routine_ping",
        source: "scanner",
        timestamp: -100,
        confirmed: true,
      };

      expect(() => engine.evaluateAndEscalate(badTime)).toThrow(
        "Invalid event timestamp"
      );
    });

    test("rejects adversarial payload with script injection", () => {
      const injectEv: ConfirmedEvent = {
        id: "ev-inject",
        eventType: "routine_ping",
        source: "scanner",
        timestamp: 1000,
        confirmed: true,
        message: "<script>alert('xss')</script>",
      };

      expect(() => engine.evaluateAndEscalate(injectEv)).toThrow(
        "Adversarial payload detected"
      );
    });

    test("rejects adversarial payload with null byte injection", () => {
      const nullByteEv: ConfirmedEvent = {
        id: "ev-nullbyte",
        eventType: "routine_ping",
        source: "scanner",
        timestamp: 1000,
        confirmed: true,
        actor: "admin\0user",
      };

      expect(() => engine.evaluateAndEscalate(nullByteEv)).toThrow(
        "Adversarial payload detected"
      );
    });

    test("rejects oversized payload", () => {
      const hugeEv: ConfirmedEvent = {
        id: "ev-huge",
        eventType: "routine_ping",
        source: "scanner",
        timestamp: 1000,
        confirmed: true,
        message: "X".repeat(70000),
      };

      expect(() => engine.evaluateAndEscalate(hugeEv)).toThrow(
        "Adversarial payload detected"
      );
    });
  });

  describe("Dispatch Escalation Integration", () => {
    test("dispatches dashboard alert and on-call page for HIGH tier action", async () => {
      const mockDashboard = new DashboardClient("http://dash.local", "token") as jest.Mocked<DashboardClient>;
      mockDashboard.sendAlert.mockResolvedValue(true);

      const mockOnCall = new OnCallRoster() as jest.Mocked<OnCallRoster>;
      mockOnCall.pageCurrentOnCall.mockResolvedValue();

      const event: ConfirmedEvent = {
        id: "ev-dispatch",
        eventType: "unauthorized_access",
        source: "auth",
        timestamp: 1000,
        confirmed: true,
      };

      const action = engine.evaluateAndEscalate(event);
      const ok = await engine.dispatchEscalation(action, mockOnCall, mockDashboard);

      expect(ok).toBe(true);
      expect(mockDashboard.sendAlert).toHaveBeenCalledTimes(1);
      expect(mockOnCall.pageCurrentOnCall).toHaveBeenCalledTimes(1);
    });

    test("handles dashboard push failure and on-call error gracefully", async () => {
      const mockDashboard = new DashboardClient("http://dash.local", "token") as jest.Mocked<DashboardClient>;
      mockDashboard.sendAlert.mockResolvedValue(false);

      const mockOnCall = new OnCallRoster() as jest.Mocked<OnCallRoster>;
      mockOnCall.pageCurrentOnCall.mockRejectedValue(new Error("Network timeout"));

      const event: ConfirmedEvent = {
        id: "ev-dispatch-fail",
        eventType: "unauthorized_access",
        source: "auth",
        timestamp: 1000,
        confirmed: true,
      };

      const action = engine.evaluateAndEscalate(event);
      const ok = await engine.dispatchEscalation(action, mockOnCall, mockDashboard);

      expect(ok).toBe(false);
      const stream = engine.getTelemetryStream();
      expect(stream.some((s) => s.recordType === "failure_surfaced")).toBe(true);
    });

    test("drives MEDIUM severity escalation to telemetry log and dashboard", () => {
      const event: ConfirmedEvent = {
        id: "ev-med",
        eventType: "gas_spike_detected",
        source: "profiler",
        timestamp: 1000,
        confirmed: true,
      };
      const action = engine.evaluateAndEscalate(event);
      expect(action.calculatedTier).toBe("MEDIUM");
      expect(action.escalationTargets).toEqual(["telemetry_log", "dashboard_alert"]);
      expect(action.retryCount).toBe(2);
    });
  });
});
