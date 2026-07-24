/**
 * Anomaly Alert Dispatcher — Test Suite
 *
 * Coverage targets:
 *   - Happy-path: single dispatch, batch dispatch, no-client fallback
 *   - Non-happy-path: delivery failures (boolean false + thrown errors)
 *   - Adversarial inputs: null, empty strings, wrong types, oversized metadata
 *   - Error hierarchy: each DispatchError subclass and its properties
 *   - Shutdown guard: dispatcher rejects calls after shutdown()
 *   - Telemetry counters: delivered / failed counts remain consistent
 */

import DashboardClient from "./dashboard-client";
import AnomalyAlertDispatcher, {
  AnomalyAlertInput,
  AlertValidationError,
  DashboardDeliveryError,
  DispatcherShutdownError,
  DispatchTimeoutError,
  DispatcherError,
} from "./anomaly-alert-dispatcher";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAlert(overrides: Partial<AnomalyAlertInput> = {}): AnomalyAlertInput {
  return {
    type: "NONCE_SPIKE",
    severity: "HIGH",
    message: "Nonce jumped by 75 (prev: 100, now: 175)",
    detail: "Address 0xABCDEF triggered a nonce spike above threshold",
    metadata: { address: "0xABCDEF", delta: 75 },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock factory
// ---------------------------------------------------------------------------

function buildMockClient(
  sendAlertImpl?: (alert: import("./dashboard-client").DashboardAlert) => Promise<boolean>
): jest.Mocked<DashboardClient> {
  const instance = new DashboardClient("https://dash.test/alerts", "tok");
  const impl = sendAlertImpl ?? ((_alert: import("./dashboard-client").DashboardAlert) => Promise.resolve(true));
  instance.sendAlert = jest.fn(impl) as jest.Mocked<DashboardClient>["sendAlert"];
  return instance as jest.Mocked<DashboardClient>;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("AnomalyAlertDispatcher", () => {
  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  describe("happy path", () => {
    it("dispatches a valid alert and returns delivered=true", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });

      const result = await dispatcher.dispatch(makeAlert());

      expect(result.delivered).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.dispatchedAt).toBeTruthy();
      expect(dispatcher.deliveredCount).toBe(1);
      expect(dispatcher.failedCount).toBe(0);
    });

    it("populates the DashboardAlert with correct source=anomaly-detector", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });

      await dispatcher.dispatch(
        makeAlert({ type: "FAILED_TX_BURST", severity: "CRITICAL" })
      );

      expect(client.sendAlert).toHaveBeenCalledWith(
        expect.objectContaining({
          source: "anomaly-detector",
          type: "FAILED_TX_BURST",
          severity: "CRITICAL",
        })
      );
    });

    it("preserves an explicit ISO timestamp from the input", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });
      const ts = "2026-01-15T08:00:00.000Z";

      await dispatcher.dispatch(makeAlert({ timestamp: ts }));

      expect(client.sendAlert).toHaveBeenCalledWith(
        expect.objectContaining({ timestamp: ts })
      );
    });

    it("defaults timestamp to current ISO string when omitted", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });
      const before = new Date().toISOString();

      await dispatcher.dispatch(makeAlert({ timestamp: undefined }));

      const call = (client.sendAlert as jest.Mock).mock.calls[0][0];
      const after = new Date().toISOString();
      expect(call.timestamp >= before).toBe(true);
      expect(call.timestamp <= after).toBe(true);
    });

    it("dispatches with empty metadata gracefully", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });

      const result = await dispatcher.dispatch(
        makeAlert({ metadata: undefined })
      );

      expect(result.delivered).toBe(true);
      expect(client.sendAlert).toHaveBeenCalledWith(
        expect.objectContaining({ metadata: {} })
      );
    });

    it("dispatches all LOW / MEDIUM / HIGH / CRITICAL severity levels", async () => {
      const severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

      for (const severity of severities) {
        const client = buildMockClient();
        const dispatcher = new AnomalyAlertDispatcher({ client });

        const result = await dispatcher.dispatch(makeAlert({ severity }));
        expect(result.delivered).toBe(true);
        expect(client.sendAlert).toHaveBeenCalledWith(
          expect.objectContaining({ severity })
        );
      }
    });
  });

  // -------------------------------------------------------------------------
  // Batch dispatch
  // -------------------------------------------------------------------------

  describe("dispatchBatch", () => {
    it("delivers all alerts in a valid batch", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });

      const batch: AnomalyAlertInput[] = [
        makeAlert({ type: "NONCE_SPIKE" }),
        makeAlert({ type: "FAILED_TX_BURST", severity: "CRITICAL" }),
        makeAlert({ type: "UNAUTHORIZED_ADDRESS", severity: "HIGH" }),
      ];

      const results = await dispatcher.dispatchBatch(batch);

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.delivered)).toBe(true);
      expect(dispatcher.deliveredCount).toBe(3);
    });

    it("continues after a per-item validation failure", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });

      const batch: AnomalyAlertInput[] = [
        makeAlert({ type: "GOOD_ALERT" }),
        makeAlert({ type: "" }), // invalid — empty type
        makeAlert({ type: "ALSO_GOOD" }),
      ];

      const results = await dispatcher.dispatchBatch(batch);

      expect(results).toHaveLength(3);
      expect(results[0].delivered).toBe(true);
      expect(results[1].delivered).toBe(false);
      expect(results[1].error).toBeInstanceOf(AlertValidationError);
      expect(results[2].delivered).toBe(true);
    });

    it("reports partial delivery when some items fail at the client level", async () => {
      let callCount = 0;
      const client = buildMockClient(async (_alert) => {
        callCount++;
        return callCount % 2 === 0 ? false : true; // even calls fail
      });
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: true });

      const results = await dispatcher.dispatchBatch([
        makeAlert({ type: "A" }),
        makeAlert({ type: "B" }),
        makeAlert({ type: "C" }),
      ]);

      expect(results.filter((r) => r.delivered)).toHaveLength(2);
      expect(results.filter((r) => !r.delivered)).toHaveLength(1);
    });

    it("throws DispatcherShutdownError when called after shutdown", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });
      dispatcher.shutdown();

      await expect(
        dispatcher.dispatchBatch([makeAlert()])
      ).rejects.toBeInstanceOf(DispatcherShutdownError);
    });

    it("throws AlertValidationError for non-array input", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });

      await expect(
        // @ts-expect-error — deliberate adversarial input
        dispatcher.dispatchBatch("not-an-array")
      ).rejects.toBeInstanceOf(AlertValidationError);
    });
  });

  // -------------------------------------------------------------------------
  // Non-happy-path: delivery failures
  // -------------------------------------------------------------------------

  describe("delivery failures (nonBlocking=true, default)", () => {
    it("returns delivered=false with DashboardDeliveryError when client returns false", async () => {
      const client = buildMockClient((_alert) => Promise.resolve(false));
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: true });

      const result = await dispatcher.dispatch(makeAlert());

      expect(result.delivered).toBe(false);
      expect(result.error).toBeInstanceOf(DashboardDeliveryError);
      expect(dispatcher.failedCount).toBe(1);
    });

    it("returns delivered=false and does NOT throw when client throws in non-blocking mode", async () => {
      const client = buildMockClient((_alert) =>
        Promise.reject(new Error("Network timeout"))
      );
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: true });

      const result = await dispatcher.dispatch(makeAlert());

      expect(result.delivered).toBe(false);
      expect(result.error).toBeInstanceOf(DashboardDeliveryError);
      expect(dispatcher.failedCount).toBe(1);
    });

    it("wraps the original error as cause on DashboardDeliveryError", async () => {
      const underlying = new Error("Connection refused");
      const client = buildMockClient((_alert) => Promise.reject(underlying));
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: true });

      const result = await dispatcher.dispatch(makeAlert({ type: "TEST" }));

      expect(result.error).toBeInstanceOf(DashboardDeliveryError);
      const err = result.error as DashboardDeliveryError;
      expect(err.cause).toBe(underlying);
      expect(err.alertType).toBe("TEST");
    });
  });

  describe("delivery failures (nonBlocking=false)", () => {
    it("throws DashboardDeliveryError when client returns false", async () => {
      const client = buildMockClient((_alert) => Promise.resolve(false));
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: false });

      await expect(dispatcher.dispatch(makeAlert())).rejects.toBeInstanceOf(
        DashboardDeliveryError
      );
    });

    it("throws DashboardDeliveryError when client throws", async () => {
      const client = buildMockClient((_alert) =>
        Promise.reject(new Error("DNS failure"))
      );
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: false });

      await expect(dispatcher.dispatch(makeAlert())).rejects.toBeInstanceOf(
        DashboardDeliveryError
      );
    });
  });

  // -------------------------------------------------------------------------
  // No client / no URL configured
  // -------------------------------------------------------------------------

  describe("no dashboard client configured", () => {
    it("returns delivered=false without throwing when no URL is provided", async () => {
      const dispatcher = new AnomalyAlertDispatcher({
        dashboardUrl: "",
        dashboardToken: "",
      });

      const result = await dispatcher.dispatch(makeAlert());

      expect(result.delivered).toBe(false);
      expect(result.error).toBeUndefined();
    });

    it("increments failedCount when no client is available", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ dashboardUrl: "" });

      await dispatcher.dispatch(makeAlert());
      await dispatcher.dispatch(makeAlert());

      expect(dispatcher.failedCount).toBe(2);
      expect(dispatcher.deliveredCount).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Adversarial / invalid input
  // -------------------------------------------------------------------------

  describe("adversarial inputs — AlertValidationError", () => {
    const client = buildMockClient();

    it("throws AlertValidationError for empty type string", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(makeAlert({ type: "" }))
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for whitespace-only type", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(makeAlert({ type: "   " }))
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for unknown severity", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(
          // @ts-expect-error — deliberate bad severity
          makeAlert({ severity: "EXTREME" })
        )
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for null severity", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(
          // @ts-expect-error — deliberate null
          makeAlert({ severity: null })
        )
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for empty message", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(makeAlert({ message: "" }))
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for empty detail", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(makeAlert({ detail: "" }))
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for non-string message", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(
          // @ts-expect-error — deliberate bad type
          makeAlert({ message: 12345 })
        )
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for malformed ISO timestamp", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(makeAlert({ timestamp: "not-a-date" }))
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for array as metadata", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(
          // @ts-expect-error — deliberate bad metadata
          makeAlert({ metadata: [1, 2, 3] })
        )
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for null as metadata", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(
          // @ts-expect-error — deliberate null
          makeAlert({ metadata: null })
        )
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("throws AlertValidationError for string as metadata", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      await expect(
        dispatcher.dispatch(
          // @ts-expect-error — deliberate bad metadata
          makeAlert({ metadata: "should-be-object" })
        )
      ).rejects.toBeInstanceOf(AlertValidationError);
    });

    it("exposes field and received on AlertValidationError", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });
      let caught: AlertValidationError | undefined;
      try {
        await dispatcher.dispatch(makeAlert({ type: "" }));
      } catch (err) {
        caught = err as AlertValidationError;
      }

      expect(caught).toBeInstanceOf(AlertValidationError);
      expect(caught?.field).toBe("type");
      expect(caught?.received).toBe("");
      expect(caught?.code).toBe("ALERT_VALIDATION_FAILED");
    });

    it("does NOT call client.sendAlert on validation failure", async () => {
      const mockClient = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client: mockClient });

      try {
        await dispatcher.dispatch(makeAlert({ type: "" }));
      } catch {
        // expected
      }

      expect(mockClient.sendAlert).not.toHaveBeenCalled();
    });

    it("increments failedCount on validation failure", async () => {
      const dispatcher = new AnomalyAlertDispatcher({ client });

      try {
        await dispatcher.dispatch(makeAlert({ type: "" }));
      } catch {
        // expected
      }

      expect(dispatcher.failedCount).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Shutdown guard
  // -------------------------------------------------------------------------

  describe("shutdown guard", () => {
    it("throws DispatcherShutdownError after shutdown()", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });
      dispatcher.shutdown();

      await expect(dispatcher.dispatch(makeAlert())).rejects.toBeInstanceOf(
        DispatcherShutdownError
      );
    });

    it("sets isShutdown=true after shutdown()", () => {
      const dispatcher = new AnomalyAlertDispatcher({ client: buildMockClient() });
      expect(dispatcher.isShutdown).toBe(false);
      dispatcher.shutdown();
      expect(dispatcher.isShutdown).toBe(true);
    });

    it("does not call client.sendAlert after shutdown", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });
      dispatcher.shutdown();

      try {
        await dispatcher.dispatch(makeAlert());
      } catch {
        // expected DispatcherShutdownError
      }

      expect(client.sendAlert).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Error class hierarchy
  // -------------------------------------------------------------------------

  describe("error class hierarchy", () => {
    it("DashboardDeliveryError extends DispatcherError", () => {
      const err = new DashboardDeliveryError("TEST_TYPE", 503);
      expect(err).toBeInstanceOf(DispatcherError);
      expect(err).toBeInstanceOf(DashboardDeliveryError);
      expect(err.code).toBe("DASHBOARD_DELIVERY_FAILED");
      expect(err.alertType).toBe("TEST_TYPE");
      expect(err.httpStatus).toBe(503);
    });

    it("AlertValidationError extends DispatcherError", () => {
      const err = new AlertValidationError("severity", "EXTREME");
      expect(err).toBeInstanceOf(DispatcherError);
      expect(err).toBeInstanceOf(AlertValidationError);
      expect(err.code).toBe("ALERT_VALIDATION_FAILED");
      expect(err.field).toBe("severity");
      expect(err.received).toBe("EXTREME");
    });

    it("DispatcherShutdownError extends DispatcherError", () => {
      const err = new DispatcherShutdownError();
      expect(err).toBeInstanceOf(DispatcherError);
      expect(err.code).toBe("DISPATCHER_SHUTDOWN");
    });

    it("DispatchTimeoutError extends DispatcherError", () => {
      const err = new DispatchTimeoutError(3000, "NONCE_SPIKE");
      expect(err).toBeInstanceOf(DispatcherError);
      expect(err.code).toBe("DISPATCH_TIMEOUT");
      expect(err.timeoutMs).toBe(3000);
      expect(err.message).toMatch(/3000ms/);
    });

    it("all error subclasses have name equal to constructor name", () => {
      expect(new DashboardDeliveryError("T").name).toBe("DashboardDeliveryError");
      expect(new AlertValidationError("f", null).name).toBe("AlertValidationError");
      expect(new DispatcherShutdownError().name).toBe("DispatcherShutdownError");
      expect(new DispatchTimeoutError(100, "T").name).toBe("DispatchTimeoutError");
    });
  });

  // -------------------------------------------------------------------------
  // Telemetry counters
  // -------------------------------------------------------------------------

  describe("telemetry counters", () => {
    it("increments deliveredCount on each successful dispatch", async () => {
      const client = buildMockClient();
      const dispatcher = new AnomalyAlertDispatcher({ client });

      await dispatcher.dispatch(makeAlert());
      await dispatcher.dispatch(makeAlert());
      await dispatcher.dispatch(makeAlert());

      expect(dispatcher.deliveredCount).toBe(3);
      expect(dispatcher.failedCount).toBe(0);
    });

    it("increments failedCount and not deliveredCount on delivery failure", async () => {
      const client = buildMockClient(() => Promise.resolve(false));
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: true });

      await dispatcher.dispatch(makeAlert());
      await dispatcher.dispatch(makeAlert());

      expect(dispatcher.deliveredCount).toBe(0);
      expect(dispatcher.failedCount).toBe(2);
    });

    it("increments failedCount when client throws (non-blocking)", async () => {
      const client = buildMockClient((_alert) =>
        Promise.reject(new Error("socket hang up"))
      );
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: true });

      await dispatcher.dispatch(makeAlert());

      expect(dispatcher.failedCount).toBe(1);
      expect(dispatcher.deliveredCount).toBe(0);
    });

    it("reflects mixed success and failure across batch", async () => {
      let call = 0;
      const client = buildMockClient(async (_alert) => {
        call++;
        return call !== 2; // second call fails
      });
      const dispatcher = new AnomalyAlertDispatcher({ client, nonBlocking: true });

      await dispatcher.dispatchBatch([
        makeAlert({ type: "A" }),
        makeAlert({ type: "B" }),
        makeAlert({ type: "C" }),
      ]);

      expect(dispatcher.deliveredCount).toBe(2);
      expect(dispatcher.failedCount).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Observational-only invariant
  // -------------------------------------------------------------------------

  describe("observational-only invariant", () => {
    it("never calls any on-chain methods — only sendAlert on client", async () => {
      const client = buildMockClient();
      // Attach spies on all methods to confirm only sendAlert is called
      const methodNames = Object.getOwnPropertyNames(
        DashboardClient.prototype
      ).filter((m) => m !== "constructor");

      const dispatcher = new AnomalyAlertDispatcher({ client });
      await dispatcher.dispatch(makeAlert({ severity: "CRITICAL" }));

      for (const method of methodNames) {
        if (method !== "sendAlert") {
          // @ts-expect-error — dynamic method access
          expect(client[method]).toBeUndefined();
        }
      }
      expect(client.sendAlert).toHaveBeenCalledTimes(1);
    });
  });
});
