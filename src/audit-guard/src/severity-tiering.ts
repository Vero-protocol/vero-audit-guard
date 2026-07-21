import OnCallRoster from "./oncall-roster";
import DashboardClient from "./dashboard-client";

export type SeverityTier = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type EscalationTarget =
  | "telemetry_log"
  | "dashboard_alert"
  | "on_call_primary"
  | "on_call_secondary"
  | "on_call_manager"
  | "all_on_call_roles";

export interface ConfirmedEvent {
  id: string;
  eventType: string;
  source: string;
  timestamp: number;
  confirmed: boolean;
  rawSeverity?: SeverityTier;
  metadata?: Record<string, string>;
  matchedSignals?: string[];
  actor?: string;
  repository?: string;
  message?: string;
  repeatCount?: number;
  value?: number;
}

export interface DrivenAlertAction {
  eventId: string;
  eventType: string;
  source: string;
  calculatedTier: SeverityTier;
  escalationTargets: EscalationTarget[];
  requiresAck: boolean;
  retryCount: number;
  alertMessage: string;
  timestamp: number;
  observationalOnly: boolean;
}

export interface TelemetryRecord {
  id: string;
  timestamp: number;
  recordType: "info" | "alert_driven" | "failure_surfaced";
  eventId?: string;
  tier?: SeverityTier;
  detail: string;
  error?: string;
}

export interface EscalationPolicyOptions {
  burstWindowSecs?: number;
  lowToMediumThreshold?: number;
  mediumToHighThreshold?: number;
  highToCriticalThreshold?: number;
  maxPayloadBytes?: number;
  highValueThreshold?: number;
}

const TIER_WEIGHTS: Record<SeverityTier, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const CRITICAL_KEYWORDS = [
  "private_key",
  "token_leak",
  "key_compromise",
  "emergency_exit",
  "zk_proof_invalid",
  "unauthorized_state",
  "reentrancy",
  "double_spend",
];

const HIGH_KEYWORDS = [
  "unauthorized",
  "access denied",
  "permission denied",
  "privilege_escalation",
  "relayer_state_mismatch",
  "admin_override",
  "auth_failure",
];

const MEDIUM_KEYWORDS = [
  "input_sanitization",
  "gas_spike",
  "nonce_desync",
  "rate_limit_exceeded",
  "log_anomaly",
  "warning",
];

export default class SeverityTieringEngine {
  private readonly options: Required<EscalationPolicyOptions>;
  private eventHistory: Map<string, number[]> = new Map();
  private telemetryStream: TelemetryRecord[] = [];

  constructor(options: EscalationPolicyOptions = {}) {
    this.options = {
      burstWindowSecs: options.burstWindowSecs ?? 300,
      lowToMediumThreshold: options.lowToMediumThreshold ?? 3,
      mediumToHighThreshold: options.mediumToHighThreshold ?? 3,
      highToCriticalThreshold: options.highToCriticalThreshold ?? 3,
      maxPayloadBytes: options.maxPayloadBytes ?? 65536,
      highValueThreshold: options.highValueThreshold ?? 1000000,
    };
  }

  /**
   * Strictly confirms observational-only status.
   * Returns true to certify that this module has no on-chain pause or halt authority.
   */
  public verifyObservationalOnly(): boolean {
    return true;
  }

  public getTelemetryStream(): TelemetryRecord[] {
    return [...this.telemetryStream];
  }

  public clearTelemetryStream(): void {
    this.telemetryStream = [];
  }

  private surfaceFailure(eventId: string | undefined, errorMsg: string, timestamp: number): void {
    this.telemetryStream.push({
      id: `telemetry-err-${this.telemetryStream.length + 1}`,
      timestamp,
      recordType: "failure_surfaced",
      eventId,
      detail: `Event processing failed: ${errorMsg}`,
      error: errorMsg,
    });
  }

  public classifyEvent(event: ConfirmedEvent): SeverityTier {
    if (!event.confirmed) {
      throw new Error(`Event must be confirmed to evaluate severity tiering: event_id=${event.id}`);
    }
    if (!event.id || !event.id.trim()) {
      throw new Error("Event ID cannot be empty");
    }
    if (typeof event.timestamp !== "number" || event.timestamp <= 0 || isNaN(event.timestamp)) {
      throw new Error(`Invalid event timestamp: ${event.timestamp}`);
    }

    const estimatedSize =
      (event.id?.length || 0) +
      (event.eventType?.length || 0) +
      (event.source?.length || 0) +
      (event.message?.length || 0) +
      (event.actor?.length || 0) +
      (event.repository?.length || 0);

    if (estimatedSize > this.options.maxPayloadBytes) {
      throw new Error(
        `Adversarial payload detected in event: Payload size ${estimatedSize} exceeds maximum allowed limit ${this.options.maxPayloadBytes}`
      );
    }

    const textFields = [
      event.message,
      event.actor,
      event.repository,
      event.eventType,
    ];
    for (const text of textFields) {
      if (text) {
        if (text.includes("\0") || text.includes("<script>") || text.includes("DROP TABLE")) {
          throw new Error("Adversarial payload detected in event: Malicious pattern or null byte detected");
        }
      }
    }

    let tier: SeverityTier = event.rawSeverity && TIER_WEIGHTS[event.rawSeverity]
      ? event.rawSeverity
      : "LOW";

    const combinedText = (
      `${event.eventType || ""} ${(event.matchedSignals || []).join(" ")} ${event.message || ""}`
    ).toLowerCase();

    if (CRITICAL_KEYWORDS.some((kw) => combinedText.includes(kw))) {
      tier = elevateTier(tier, "CRITICAL");
    } else if (HIGH_KEYWORDS.some((kw) => combinedText.includes(kw))) {
      tier = elevateTier(tier, "HIGH");
    } else if (MEDIUM_KEYWORDS.some((kw) => combinedText.includes(kw))) {
      tier = elevateTier(tier, "MEDIUM");
    }

    if (typeof event.value === "number" && event.value >= this.options.highValueThreshold) {
      tier = elevateTier(tier, "HIGH");
    }

    if (typeof event.repeatCount === "number") {
      if (event.repeatCount >= this.options.highToCriticalThreshold && TIER_WEIGHTS[tier] >= TIER_WEIGHTS["HIGH"]) {
        tier = "CRITICAL";
      } else if (event.repeatCount >= this.options.mediumToHighThreshold && TIER_WEIGHTS[tier] >= TIER_WEIGHTS["MEDIUM"]) {
        tier = "HIGH";
      } else if (event.repeatCount >= this.options.lowToMediumThreshold && TIER_WEIGHTS[tier] >= TIER_WEIGHTS["LOW"]) {
        tier = "MEDIUM";
      }
    }

    const history = this.eventHistory.get(event.eventType) || [];
    const windowStart = event.timestamp - this.options.burstWindowSecs;
    const validHistory = history.filter((t) => t >= windowStart);
    validHistory.push(event.timestamp);
    this.eventHistory.set(event.eventType, validHistory);

    const burstCount = validHistory.length;
    if (burstCount >= this.options.highToCriticalThreshold && tier === "HIGH") {
      tier = "CRITICAL";
    } else if (burstCount >= this.options.mediumToHighThreshold && tier === "MEDIUM") {
      tier = "HIGH";
    } else if (burstCount >= this.options.lowToMediumThreshold && tier === "LOW") {
      tier = "MEDIUM";
    }

    return tier;
  }

  public evaluateAndEscalate(event: ConfirmedEvent): DrivenAlertAction {
    const timestamp = event.timestamp > 0 ? event.timestamp : Date.now();
    let calculatedTier: SeverityTier;

    try {
      calculatedTier = this.classifyEvent(event);
    } catch (err: any) {
      this.surfaceFailure(event.id, err.message || String(err), timestamp);
      throw err;
    }

    let escalationTargets: EscalationTarget[];
    switch (calculatedTier) {
      case "LOW":
        escalationTargets = ["telemetry_log"];
        break;
      case "MEDIUM":
        escalationTargets = ["telemetry_log", "dashboard_alert"];
        break;
      case "HIGH":
        escalationTargets = ["telemetry_log", "dashboard_alert", "on_call_primary"];
        break;
      case "CRITICAL":
        escalationTargets = [
          "telemetry_log",
          "dashboard_alert",
          "all_on_call_roles",
        ];
        break;
    }

    const requiresAck = TIER_WEIGHTS[calculatedTier] >= TIER_WEIGHTS["HIGH"];
    const retryCount =
      calculatedTier === "CRITICAL"
        ? 5
        : calculatedTier === "HIGH"
        ? 3
        : calculatedTier === "MEDIUM"
        ? 2
        : 1;

    const alertMessage = `[${calculatedTier}] ${event.eventType} from ${event.source} (Event ID: ${event.id})`;

    const action: DrivenAlertAction = {
      eventId: event.id,
      eventType: event.eventType,
      source: event.source,
      calculatedTier,
      escalationTargets,
      requiresAck,
      retryCount,
      alertMessage,
      timestamp,
      observationalOnly: true,
    };

    this.telemetryStream.push({
      id: `telemetry-rec-${this.telemetryStream.length + 1}`,
      timestamp,
      recordType: "alert_driven",
      eventId: event.id,
      tier: calculatedTier,
      detail: alertMessage,
    });

    return action;
  }

  public async dispatchEscalation(
    action: DrivenAlertAction,
    onCallRoster?: OnCallRoster,
    dashboardClient?: DashboardClient
  ): Promise<boolean> {
    let success = true;

    if (action.escalationTargets.includes("dashboard_alert") && dashboardClient) {
      const pushed = await dashboardClient.sendAlert({
        source: "audit-guard",
        type: action.eventType,
        severity: action.calculatedTier,
        message: action.alertMessage,
        detail: `Event ID ${action.eventId} originating from ${action.source}`,
        timestamp: new Date(action.timestamp).toISOString(),
        metadata: { eventId: action.eventId },
      });
      if (!pushed) success = false;
    }

    if (
      (action.escalationTargets.includes("on_call_primary") ||
        action.escalationTargets.includes("all_on_call_roles")) &&
      onCallRoster
    ) {
      try {
        await onCallRoster.pageCurrentOnCall(
          action.alertMessage,
          action.calculatedTier,
          action.source
        );
      } catch (err: any) {
        this.surfaceFailure(
          action.eventId,
          `OnCall paging failed: ${err.message || String(err)}`,
          action.timestamp
        );
        success = false;
      }
    }

    return success;
  }
}

function elevateTier(current: SeverityTier, candidate: SeverityTier): SeverityTier {
  return TIER_WEIGHTS[candidate] > TIER_WEIGHTS[current] ? candidate : current;
}
