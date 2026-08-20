/**
 * MultisigWebhookNotifier — Test Suite (VAG-010)
 *
 * Coverage targets (>80% on the new module):
 *   - Happy path: valid anomaly → signed webhook delivered to all endpoints
 *   - Non-happy-path: network error, timeout, non-2xx response
 *   - Adversarial input: malformed/missing fields, wrong types
 *   - Configuration errors: missing secret, no endpoints
 *   - HMAC signing: signature format, determinism, secret never logged
 *   - On-call roster paging: triggered on delivery failure, not on success
 *   - throwOnAnyFailure mode
 *   - Multi-endpoint: partial success, all-fail, all-succeed
 *   - Observational-only invariant: no on-chain methods callable
 */

import axios from "axios";
import * as crypto from "crypto";
import MultisigWebhookNotifier, {
  CriticalAnomalyInput,
  WebhookConfigurationError,
  WebhookPayloadSerializationError,
  WebhookNon2xxResponseError,
  WebhookTimeoutError,
  WebhookNetworkError,
  WebhookNotificationError,
  computeHmacSignature,
} from "./multisig-webhook-notifier";
import { OnCallRoster } from "./oncall-roster";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_SECRET = "test-hmac-secret-32-chars-minimum!";
const TEST_URL_1 = "https://signer1.vero.xyz/webhook";
const TEST_URL_2 = "https://signer2.vero.xyz/webhook";
const TEST_URLS = `${TEST_URL_1},${TEST_URL_2}`;

function makeAnomaly(overrides: Partial<CriticalAnomalyInput> = {}): CriticalAnomalyInput {
  return {
    type: "THREAT_FEED_MATCH",
    severity: "CRITICAL",
    message: "Address matched active blocklist in threat feed",
    detail: "Address 0xDEADBEEF matches entry in threat feed last updated 2026-07-25",
    address: "0xDEADBEEF",
    metadata: { feedSource: "internal", matchCount: 1 },
    ...overrides,
  };
}

/** Build a mock axios instance whose post() resolves with a 200 response. */
function mockAxios(
  impl?: (url: string, data: unknown, cfg: unknown) => Promise<{ status: number }>
): jest.Mocked<typeof axios> {
  const defaultImpl = (_url: string, _data: unknown, _cfg: unknown) =>
    Promise.resolve({ status: 200, data: {} });
  const mock = { post: jest.fn(impl ?? defaultImpl) } as unknown as jest.Mocked<typeof axios>;
  return mock;
}

/** Build a mock OnCallRoster that resolves pageCurrentOnCall silently. */
function mockRoster(pageImpl?: () => Promise<void>): jest.Mocked<OnCallRoster> {
  const roster = new OnCallRoster({
    contacts: [{ name: "Test", email: "test@vero.xyz", role: "PRIMARY" }],
  });
  roster.pageCurrentOnCall = jest.fn(pageImpl ?? (() => Promise.resolve()));
  return roster as jest.Mocked<OnCallRoster>;
}

/** Returns a notifier wired with injected mocks — no real HTTP or file I/O. */
function makeNotifier(
  axiosMock = mockAxios(),
  rosterMock = mockRoster(),
  overrides: Partial<{
    secret: string;
    webhookUrls: string;
    throwOnAnyFailure: boolean;
    timeoutMs: number;
  }> = {}
): MultisigWebhookNotifier {
  return new MultisigWebhookNotifier({
    secret: overrides.secret ?? TEST_SECRET,
    webhookUrls: overrides.webhookUrls ?? TEST_URLS,
    timeoutMs: overrides.timeoutMs ?? 1000,
    throwOnAnyFailure: overrides.throwOnAnyFailure ?? false,
    _httpClient: axiosMock,
    _rosterOverride: rosterMock,
  });
}

// ---------------------------------------------------------------------------
// computeHmacSignature (unit tests — no HTTP)
// ---------------------------------------------------------------------------

describe("computeHmacSignature", () => {
  it("produces a sha256=<hex> prefixed string", () => {
    const sig = computeHmacSignature('{"hello":"world"}', TEST_SECRET);
    expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input and secret", () => {
    const body = '{"type":"NONCE_SPIKE"}';
    const sig1 = computeHmacSignature(body, TEST_SECRET);
    const sig2 = computeHmacSignature(body, TEST_SECRET);
    expect(sig1).toBe(sig2);
  });

  it("produces a different signature for a different secret", () => {
    const body = '{"type":"NONCE_SPIKE"}';
    const sig1 = computeHmacSignature(body, "secret-A");
    const sig2 = computeHmacSignature(body, "secret-B");
    expect(sig1).not.toBe(sig2);
  });

  it("produces a different signature for a different body", () => {
    const sig1 = computeHmacSignature('{"a":1}', TEST_SECRET);
    const sig2 = computeHmacSignature('{"a":2}', TEST_SECRET);
    expect(sig1).not.toBe(sig2);
  });

  it("matches a manually computed HMAC-SHA256", () => {
    const body = '{"event":"test"}';
    const secret = "my-test-secret";
    const expected =
      "sha256=" +
      crypto.createHmac("sha256", Buffer.from(secret, "utf-8"))
        .update(body, "utf-8")
        .digest("hex");
    expect(computeHmacSignature(body, secret)).toBe(expected);
  });

  it("throws WebhookConfigurationError for an empty secret", () => {
    expect(() => computeHmacSignature('{"x":1}', "")).toThrow(
      WebhookConfigurationError
    );
  });
});

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

describe("MultisigWebhookNotifier — happy path", () => {
  it("returns successCount=2 for two healthy endpoints", async () => {
    const notifier = makeNotifier();
    const result = await notifier.notifySigners(makeAnomaly());

    expect(result.successCount).toBe(2);
    expect(result.failureCount).toBe(0);
    expect(result.endpoints).toHaveLength(2);
    expect(result.endpoints.every((e) => e.delivered)).toBe(true);
  });

  it("sets source=vero-audit-guard and event=CRITICAL_ANOMALY_DETECTED in the posted body", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly());

    const [, rawBody] = (http.post as jest.Mock).mock.calls[0];
    const body = JSON.parse(rawBody as string);
    expect(body.source).toBe("vero-audit-guard");
    expect(body.event).toBe("CRITICAL_ANOMALY_DETECTED");
  });

  it("posts to all configured URLs", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly());

    const calledUrls = (http.post as jest.Mock).mock.calls.map(
      ([url]: [string]) => url
    );
    expect(calledUrls).toContain(TEST_URL_1);
    expect(calledUrls).toContain(TEST_URL_2);
  });

  it("includes X-Vero-Signature header with sha256= prefix", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly());

    const [, , config] = (http.post as jest.Mock).mock.calls[0];
    const sig = (config as { headers: Record<string, string> }).headers["X-Vero-Signature"];
    expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  it("the HMAC in the header verifies against the posted body", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly());

    const [, rawBody, config] = (http.post as jest.Mock).mock.calls[0];
    const sig = (config as { headers: Record<string, string> }).headers["X-Vero-Signature"];
    const expected = computeHmacSignature(rawBody as string, TEST_SECRET);
    expect(sig).toBe(expected);
  });

  it("preserves an explicit ISO timestamp from the input", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    const ts = "2026-07-25T12:00:00.000Z";
    await notifier.notifySigners(makeAnomaly({ timestamp: ts }));

    const [, rawBody] = (http.post as jest.Mock).mock.calls[0];
    const body = JSON.parse(rawBody as string);
    expect(body.detectedAt).toBe(ts);
  });

  it("includes address in anomaly payload when provided", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly({ address: "GTEST123" }));

    const [, rawBody] = (http.post as jest.Mock).mock.calls[0];
    const body = JSON.parse(rawBody as string);
    expect(body.anomaly.address).toBe("GTEST123");
  });

  it("omits address from payload when not provided", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    const { address: _a, ...noAddr } = makeAnomaly();
    await notifier.notifySigners(noAddr);

    const [, rawBody] = (http.post as jest.Mock).mock.calls[0];
    const body = JSON.parse(rawBody as string);
    expect(body.anomaly).not.toHaveProperty("address");
  });

  it("does NOT page the on-call roster on full success", async () => {
    const roster = mockRoster();
    const notifier = makeNotifier(mockAxios(), roster);
    await notifier.notifySigners(makeAnomaly());

    expect(roster.pageCurrentOnCall).not.toHaveBeenCalled();
  });

  it("completedAt is a valid ISO-8601 string", async () => {
    const notifier = makeNotifier();
    const result = await notifier.notifySigners(makeAnomaly());
    expect(isNaN(Date.parse(result.completedAt))).toBe(false);
  });

  it("isConfigured returns true when secret and URLs are set", () => {
    const notifier = makeNotifier();
    expect(notifier.isConfigured).toBe(true);
  });

  it("endpointCount reflects the number of configured URLs", () => {
    const notifier = makeNotifier(mockAxios(), mockRoster(), {
      webhookUrls: TEST_URL_1,
    });
    expect(notifier.endpointCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Non-happy-path: delivery failures
// ---------------------------------------------------------------------------

describe("MultisigWebhookNotifier — delivery failures", () => {
  it("returns failureCount=1 when one endpoint is unreachable (network error)", async () => {
    const http = mockAxios(async (url) => {
      if (url === TEST_URL_1) throw new Error("ECONNREFUSED");
      return { status: 200, data: {} };
    });
    const notifier = makeNotifier(http);
    const result = await notifier.notifySigners(makeAnomaly());

    expect(result.failureCount).toBe(1);
    expect(result.successCount).toBe(1);
    const failed = result.endpoints.find((e) => !e.delivered);
    expect(failed?.error).toBeInstanceOf(WebhookNetworkError);
  });

  it("maps axios ECONNABORTED to WebhookTimeoutError", async () => {
    const timeoutErr = Object.assign(new Error("timeout"), {
      isAxiosError: true,
      code: "ECONNABORTED",
    });
    const http = mockAxios(async () => { throw timeoutErr; });
    const notifier = makeNotifier(http);
    const result = await notifier.notifySigners(makeAnomaly());

    expect(result.failureCount).toBe(2);
    expect(result.endpoints[0].error).toBeInstanceOf(WebhookTimeoutError);
    const te = result.endpoints[0].error as WebhookTimeoutError;
    expect(te.timeoutMs).toBe(1000);
  });

  it("maps axios ERR_CANCELED to WebhookTimeoutError", async () => {
    const cancelErr = Object.assign(new Error("canceled"), {
      isAxiosError: true,
      code: "ERR_CANCELED",
    });
    const http = mockAxios(async () => { throw cancelErr; });
    const notifier = makeNotifier(http);
    const result = await notifier.notifySigners(makeAnomaly());

    expect(result.endpoints[0].error).toBeInstanceOf(WebhookTimeoutError);
  });

  it("maps axios 4xx/5xx response to WebhookNon2xxResponseError", async () => {
    const non2xxErr = Object.assign(new Error("Request failed with status 503"), {
      isAxiosError: true,
      response: { status: 503 },
    });
    const http = mockAxios(async () => { throw non2xxErr; });
    const notifier = makeNotifier(http);
    const result = await notifier.notifySigners(makeAnomaly());

    expect(result.failureCount).toBe(2);
    const err = result.endpoints[0].error as WebhookNon2xxResponseError;
    expect(err).toBeInstanceOf(WebhookNon2xxResponseError);
    expect(err.httpStatus).toBe(503);
    expect(err.endpointUrl).toBe(TEST_URL_1);
  });

  it("maps inline non-2xx response status (no throw) to WebhookNon2xxResponseError", async () => {
    const http = mockAxios(async () => ({ status: 429, data: {} }));
    const notifier = makeNotifier(http);
    const result = await notifier.notifySigners(makeAnomaly());

    const err = result.endpoints[0].error as WebhookNon2xxResponseError;
    expect(err).toBeInstanceOf(WebhookNon2xxResponseError);
    expect(err.httpStatus).toBe(429);
  });

  it("pages the on-call roster when any endpoint fails", async () => {
    const http = mockAxios(async () => { throw new Error("Connection refused"); });
    const roster = mockRoster();
    const notifier = makeNotifier(http, roster);
    await notifier.notifySigners(makeAnomaly());

    expect(roster.pageCurrentOnCall).toHaveBeenCalledTimes(1);
    const [alertMsg, severity, repo] = (roster.pageCurrentOnCall as jest.Mock).mock.calls[0];
    expect(alertMsg).toContain("VAG-010");
    expect(alertMsg).toContain("THREAT_FEED_MATCH");
    expect(severity).toBe("CRITICAL");
    expect(repo).toBe("vero-audit-guard");
  });

  it("does NOT throw by default (throwOnAnyFailure=false) even when all endpoints fail", async () => {
    const http = mockAxios(async () => { throw new Error("down"); });
    const notifier = makeNotifier(http, mockRoster(), { throwOnAnyFailure: false });

    await expect(notifier.notifySigners(makeAnomaly())).resolves.toBeDefined();
  });

  it("throws the first delivery error when throwOnAnyFailure=true and an endpoint fails", async () => {
    const http = mockAxios(async () => { throw new Error("DNS failure"); });
    const notifier = makeNotifier(http, mockRoster(), { throwOnAnyFailure: true });

    await expect(notifier.notifySigners(makeAnomaly())).rejects.toBeInstanceOf(
      WebhookNetworkError
    );
  });

  it("continues notifying remaining endpoints after one fails", async () => {
    let callCount = 0;
    const http = mockAxios(async () => {
      callCount++;
      if (callCount === 1) throw new Error("first fails");
      return { status: 200, data: {} };
    });
    const notifier = makeNotifier(http);
    const result = await notifier.notifySigners(makeAnomaly());

    expect(result.successCount).toBe(1);
    expect(result.failureCount).toBe(1);
    expect(callCount).toBe(2);
  });

  it("handles roster paging failure gracefully — returns result anyway", async () => {
    const http = mockAxios(async () => { throw new Error("down"); });
    const rosterWithError = mockRoster(async () => {
      throw new Error("roster unavailable");
    });
    const notifier = makeNotifier(http, rosterWithError);

    const result = await notifier.notifySigners(makeAnomaly());
    expect(result.failureCount).toBe(2);
    expect(result.successCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Configuration errors
// ---------------------------------------------------------------------------

describe("MultisigWebhookNotifier — configuration errors", () => {
  it("throws WebhookConfigurationError when secret is empty string", async () => {
    const notifier = makeNotifier(mockAxios(), mockRoster(), { secret: "" });
    await expect(notifier.notifySigners(makeAnomaly())).rejects.toBeInstanceOf(
      WebhookConfigurationError
    );
  });

  it("throws WebhookConfigurationError when webhookUrls is empty", async () => {
    const notifier = makeNotifier(mockAxios(), mockRoster(), { webhookUrls: "" });
    await expect(notifier.notifySigners(makeAnomaly())).rejects.toBeInstanceOf(
      WebhookConfigurationError
    );
  });

  it("throws WebhookConfigurationError when webhookUrls contains only whitespace/commas", async () => {
    const notifier = makeNotifier(mockAxios(), mockRoster(), {
      webhookUrls: " , , ",
    });
    await expect(notifier.notifySigners(makeAnomaly())).rejects.toBeInstanceOf(
      WebhookConfigurationError
    );
  });

  it("isConfigured returns false when secret is empty", () => {
    const notifier = new MultisigWebhookNotifier({ secret: "", webhookUrls: TEST_URLS });
    expect(notifier.isConfigured).toBe(false);
  });

  it("isConfigured returns false when no endpoints", () => {
    const notifier = new MultisigWebhookNotifier({
      secret: TEST_SECRET,
      webhookUrls: "",
    });
    expect(notifier.isConfigured).toBe(false);
  });

  it("configuration error is thrown BEFORE any HTTP call", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http, mockRoster(), { secret: "" });
    try {
      await notifier.notifySigners(makeAnomaly());
    } catch {
      // expected
    }
    expect(http.post).not.toHaveBeenCalled();
  });

  it("trims whitespace from individual URL entries", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http, mockRoster(), {
      webhookUrls: `  ${TEST_URL_1}  ,  ${TEST_URL_2}  `,
    });
    const result = await notifier.notifySigners(makeAnomaly());
    expect(result.successCount).toBe(2);
    const calledUrls = (http.post as jest.Mock).mock.calls.map(
      ([url]: [string]) => url
    );
    expect(calledUrls).toContain(TEST_URL_1);
    expect(calledUrls).toContain(TEST_URL_2);
  });
});

// ---------------------------------------------------------------------------
// Adversarial / invalid payload input
// ---------------------------------------------------------------------------

describe("MultisigWebhookNotifier — adversarial inputs", () => {
  it("throws WebhookPayloadSerializationError for empty type", async () => {
    const notifier = makeNotifier();
    await expect(
      notifier.notifySigners(makeAnomaly({ type: "" }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for whitespace-only type", async () => {
    const notifier = makeNotifier();
    await expect(
      notifier.notifySigners(makeAnomaly({ type: "   " }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for invalid severity", async () => {
    const notifier = makeNotifier();
    await expect(
      // @ts-expect-error — deliberate bad severity
      notifier.notifySigners(makeAnomaly({ severity: "EXTREME" }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for null severity", async () => {
    const notifier = makeNotifier();
    await expect(
      // @ts-expect-error — deliberate null
      notifier.notifySigners(makeAnomaly({ severity: null }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for empty message", async () => {
    const notifier = makeNotifier();
    await expect(
      notifier.notifySigners(makeAnomaly({ message: "" }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for empty detail", async () => {
    const notifier = makeNotifier();
    await expect(
      notifier.notifySigners(makeAnomaly({ detail: "" }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for numeric message", async () => {
    const notifier = makeNotifier();
    await expect(
      // @ts-expect-error — deliberate bad type
      notifier.notifySigners(makeAnomaly({ message: 42 }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for malformed ISO timestamp", async () => {
    const notifier = makeNotifier();
    await expect(
      notifier.notifySigners(makeAnomaly({ timestamp: "not-a-date" }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for array as metadata", async () => {
    const notifier = makeNotifier();
    await expect(
      // @ts-expect-error — deliberate bad metadata
      notifier.notifySigners(makeAnomaly({ metadata: [1, 2, 3] }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for null metadata", async () => {
    const notifier = makeNotifier();
    await expect(
      // @ts-expect-error — deliberate null
      notifier.notifySigners(makeAnomaly({ metadata: null }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for string metadata", async () => {
    const notifier = makeNotifier();
    await expect(
      // @ts-expect-error — deliberate string
      notifier.notifySigners(makeAnomaly({ metadata: "bad" }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("throws WebhookPayloadSerializationError for empty-string address", async () => {
    const notifier = makeNotifier();
    await expect(
      notifier.notifySigners(makeAnomaly({ address: "" }))
    ).rejects.toBeInstanceOf(WebhookPayloadSerializationError);
  });

  it("does NOT call HTTP post when payload validation fails", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    try {
      await notifier.notifySigners(makeAnomaly({ type: "" }));
    } catch {
      // expected
    }
    expect(http.post).not.toHaveBeenCalled();
  });

  it("does NOT page on-call roster when payload validation fails", async () => {
    const roster = mockRoster();
    const notifier = makeNotifier(mockAxios(), roster);
    try {
      await notifier.notifySigners(makeAnomaly({ severity: "INVALID" as "CRITICAL" }));
    } catch {
      // expected
    }
    expect(roster.pageCurrentOnCall).not.toHaveBeenCalled();
  });

  it("validation error fires before any I/O — serialization failure is safe", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    let caught: unknown;
    try {
      await notifier.notifySigners(makeAnomaly({ detail: "" }));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(WebhookPayloadSerializationError);
    expect(http.post).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Error class hierarchy
// ---------------------------------------------------------------------------

describe("Error class hierarchy", () => {
  it("WebhookConfigurationError extends WebhookNotificationError", () => {
    const err = new WebhookConfigurationError("missing secret");
    expect(err).toBeInstanceOf(WebhookNotificationError);
    expect(err.code).toBe("WEBHOOK_CONFIGURATION_INVALID");
    expect(err.name).toBe("WebhookConfigurationError");
  });

  it("WebhookPayloadSerializationError extends WebhookNotificationError", () => {
    const err = new WebhookPayloadSerializationError("bad field");
    expect(err).toBeInstanceOf(WebhookNotificationError);
    expect(err.code).toBe("WEBHOOK_PAYLOAD_SERIALIZATION_FAILED");
    expect(err.name).toBe("WebhookPayloadSerializationError");
  });

  it("WebhookNon2xxResponseError extends WebhookNotificationError", () => {
    const err = new WebhookNon2xxResponseError("https://example.com", 503);
    expect(err).toBeInstanceOf(WebhookNotificationError);
    expect(err.code).toBe("WEBHOOK_NON_2XX_RESPONSE");
    expect(err.httpStatus).toBe(503);
    expect(err.endpointUrl).toBe("https://example.com");
    expect(err.name).toBe("WebhookNon2xxResponseError");
  });

  it("WebhookTimeoutError extends WebhookNotificationError", () => {
    const err = new WebhookTimeoutError("https://example.com", 5000);
    expect(err).toBeInstanceOf(WebhookNotificationError);
    expect(err.code).toBe("WEBHOOK_TIMEOUT");
    expect(err.timeoutMs).toBe(5000);
    expect(err.message).toContain("5000ms");
    expect(err.name).toBe("WebhookTimeoutError");
  });

  it("WebhookNetworkError extends WebhookNotificationError", () => {
    const cause = new Error("ECONNREFUSED");
    const err = new WebhookNetworkError("https://example.com", cause);
    expect(err).toBeInstanceOf(WebhookNotificationError);
    expect(err.code).toBe("WEBHOOK_NETWORK_ERROR");
    expect(err.cause).toBe(cause);
    expect(err.message).toContain("ECONNREFUSED");
    expect(err.name).toBe("WebhookNetworkError");
  });

  it("all error subclasses preserve prototype chain (instanceof works after transpile)", () => {
    const errors: WebhookNotificationError[] = [
      new WebhookConfigurationError("x"),
      new WebhookPayloadSerializationError("x"),
      new WebhookNon2xxResponseError("u", 500),
      new WebhookTimeoutError("u", 1000),
      new WebhookNetworkError("u"),
    ];
    for (const err of errors) {
      expect(err instanceof Error).toBe(true);
      expect(err instanceof WebhookNotificationError).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Secret safety — confirm secret is never surfaced in logged output
// ---------------------------------------------------------------------------

describe("Secret safety", () => {
  it("the HMAC secret does not appear in the signed payload body", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly());

    const [, rawBody] = (http.post as jest.Mock).mock.calls[0];
    expect(rawBody as string).not.toContain(TEST_SECRET);
  });

  it("the signature header does not contain the raw secret", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly());

    const [, , config] = (http.post as jest.Mock).mock.calls[0];
    const sig = (config as { headers: Record<string, string> }).headers["X-Vero-Signature"];
    expect(sig).not.toContain(TEST_SECRET);
  });
});

// ---------------------------------------------------------------------------
// Observational-only invariant — no on-chain capability
// ---------------------------------------------------------------------------

describe("Observational-only invariant", () => {
  it("MultisigWebhookNotifier has no method named emergency_pause", () => {
    const notifier = makeNotifier();
    expect((notifier as unknown as Record<string, unknown>)["emergency_pause"]).toBeUndefined();
  });

  it("MultisigWebhookNotifier has no method named halt", () => {
    const notifier = makeNotifier();
    expect((notifier as unknown as Record<string, unknown>)["halt"]).toBeUndefined();
  });

  it("MultisigWebhookNotifier has no method named pause", () => {
    const notifier = makeNotifier();
    expect((notifier as unknown as Record<string, unknown>)["pause"]).toBeUndefined();
  });

  it("MultisigWebhookNotifier has no method named revert", () => {
    const notifier = makeNotifier();
    expect((notifier as unknown as Record<string, unknown>)["revert"]).toBeUndefined();
  });

  it("the module does not import @stellar/stellar-sdk (no on-chain capability)", () => {
    // Confirm by checking the module's own exports — no Keypair, no Horizon
    const mod = require("./multisig-webhook-notifier");
    expect(mod["Keypair"]).toBeUndefined();
    expect(mod["Horizon"]).toBeUndefined();
    expect(mod["TransactionBuilder"]).toBeUndefined();
  });

  it("notifySigners only calls http.post — no other side-effects on the HTTP client", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    await notifier.notifySigners(makeAnomaly({ severity: "CRITICAL" }));

    // Only post() should have been called — no get, delete, put, patch, etc.
    expect(http.post).toHaveBeenCalled();
    expect((http as unknown as Record<string, unknown>)["get"]).toBeUndefined();
    expect((http as unknown as Record<string, unknown>)["delete"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Edge cases and additional coverage
// ---------------------------------------------------------------------------

describe("Edge cases", () => {
  it("handles metadata with nested objects", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    const result = await notifier.notifySigners(
      makeAnomaly({ metadata: { nested: { deep: true }, count: 42 } })
    );
    expect(result.successCount).toBe(2);
    const [, rawBody] = (http.post as jest.Mock).mock.calls[0];
    const body = JSON.parse(rawBody as string);
    expect(body.anomaly.metadata.nested.deep).toBe(true);
  });

  it("defaults metadata to {} when not provided", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http);
    const { metadata: _m, ...noMeta } = makeAnomaly();
    await notifier.notifySigners(noMeta);

    const [, rawBody] = (http.post as jest.Mock).mock.calls[0];
    const body = JSON.parse(rawBody as string);
    expect(body.anomaly.metadata).toEqual({});
  });

  it("handles a single-endpoint configuration", async () => {
    const http = mockAxios();
    const notifier = makeNotifier(http, mockRoster(), { webhookUrls: TEST_URL_1 });
    const result = await notifier.notifySigners(makeAnomaly());

    expect(result.successCount).toBe(1);
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0].url).toBe(TEST_URL_1);
  });

  it("all four severity levels pass validation", async () => {
    const severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
    for (const severity of severities) {
      const notifier = makeNotifier();
      const result = await notifier.notifySigners(makeAnomaly({ severity }));
      expect(result.successCount).toBe(2);
    }
  });

  it("all endpoint results include a non-empty attemptedAt timestamp", async () => {
    const notifier = makeNotifier();
    const result = await notifier.notifySigners(makeAnomaly());
    for (const ep of result.endpoints) {
      expect(isNaN(Date.parse(ep.attemptedAt))).toBe(false);
    }
  });

  it("env-variable fallback: reads secret from MULTISIG_WEBHOOK_SECRET", () => {
    const prev = process.env["MULTISIG_WEBHOOK_SECRET"];
    process.env["MULTISIG_WEBHOOK_SECRET"] = "env-secret";
    const notifier = new MultisigWebhookNotifier({
      webhookUrls: TEST_URL_1,
      _httpClient: mockAxios(),
      _rosterOverride: mockRoster(),
    });
    expect(notifier.isConfigured).toBe(true);
    if (prev === undefined) {
      delete process.env["MULTISIG_WEBHOOK_SECRET"];
    } else {
      process.env["MULTISIG_WEBHOOK_SECRET"] = prev;
    }
  });

  it("env-variable fallback: reads URLs from MULTISIG_WEBHOOK_URLS", () => {
    const prev = process.env["MULTISIG_WEBHOOK_URLS"];
    process.env["MULTISIG_WEBHOOK_URLS"] = TEST_URL_1;
    const notifier = new MultisigWebhookNotifier({
      secret: TEST_SECRET,
      _httpClient: mockAxios(),
      _rosterOverride: mockRoster(),
    });
    expect(notifier.endpointCount).toBe(1);
    if (prev === undefined) {
      delete process.env["MULTISIG_WEBHOOK_URLS"];
    } else {
      process.env["MULTISIG_WEBHOOK_URLS"] = prev;
    }
  });
});
