jest.mock("./oncall-roster", () => ({
  OnCallRoster: jest.fn(),
}));

import { OnCallRoster } from "./oncall-roster";
import {
  escalateIncident,
  resetRoster,
  triggerCircuitBreaker,
  type IncidentReport,
} from "./irps";

const MockOnCallRoster = OnCallRoster as jest.MockedClass<typeof OnCallRoster>;

describe("incident response protocol utilities", () => {
  let pageCurrentOnCall: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    pageCurrentOnCall = jest.fn().mockResolvedValue(undefined);
    MockOnCallRoster.mockImplementation(() => ({
      pageCurrentOnCall,
    }) as unknown as OnCallRoster);
    resetRoster();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("pages the on-call roster with the incident details", async () => {
    const incident: IncidentReport = {
      severity: "HIGH",
      title: "Suspicious transaction",
      description: "A policy violation was detected",
      repository: "Vero-protocol/vero-audit-guard",
      findings: [{ rule: "RBAC", detail: "Unexpected signer" }],
    };

    await escalateIncident(incident);

    expect(MockOnCallRoster).toHaveBeenCalledTimes(1);
    expect(pageCurrentOnCall).toHaveBeenCalledWith(
      "[HIGH] Suspicious transaction — A policy violation was detected",
      "HIGH",
      "Vero-protocol/vero-audit-guard"
    );
  });

  it("uses the default critical circuit-breaker reason and repository", async () => {
    const promise = triggerCircuitBreaker();
    await jest.runAllTimersAsync();
    await promise;

    expect(pageCurrentOnCall).toHaveBeenCalledWith(
      "CRITICAL finding — manual intervention required",
      "CRITICAL",
      "vero-audit-guard"
    );
  });

  it("uses a supplied circuit-breaker reason", async () => {
    const promise = triggerCircuitBreaker("Manual pause requested");
    await jest.runAllTimersAsync();
    await promise;

    expect(pageCurrentOnCall).toHaveBeenCalledWith(
      "Manual pause requested",
      "CRITICAL",
      "vero-audit-guard"
    );
  });

  it("reuses the roster until reset", async () => {
    await escalateIncident({
      severity: "LOW",
      title: "First alert",
      description: "First description",
      repository: "repo-a",
    });
    await escalateIncident({
      severity: "MEDIUM",
      title: "Second alert",
      description: "Second description",
      repository: "repo-b",
    });

    expect(MockOnCallRoster).toHaveBeenCalledTimes(1);
    expect(pageCurrentOnCall).toHaveBeenCalledTimes(2);

    resetRoster();
    await escalateIncident({
      severity: "CRITICAL",
      title: "Third alert",
      description: "Third description",
      repository: "repo-c",
    });

    expect(MockOnCallRoster).toHaveBeenCalledTimes(2);
  });
});
