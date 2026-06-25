import * as fs from "fs";

export type EventSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface EventLogScannerOptions {
  source?: string;
  scannedAt?: string;
  sensitiveKeywords?: string[];
  sensitiveEventTypes?: string[];
}

export interface EventLogEntry {
  id: string;
  line: number;
  timestamp: string;
  eventType: string;
  source: string;
  severity: EventSeverity;
  sensitive: boolean;
  matchedSignals: string[];
  raw: unknown;
  actor?: string;
  repository?: string;
  message?: string;
}

export interface EventLogIndex {
  byType: Record<string, EventLogEntry[]>;
  byActor: Record<string, EventLogEntry[]>;
  byRepository: Record<string, EventLogEntry[]>;
}

export interface EventLogScanResult {
  source: string;
  scannedAt: string;
  totalEvents: number;
  sensitiveCount: number;
  events: EventLogEntry[];
  sensitiveEvents: EventLogEntry[];
  index: EventLogIndex;
}

const DEFAULT_SENSITIVE_KEYWORDS = Object.freeze([
  "unauthorized",
  "auth_failure",
  "auth failed",
  "access denied",
  "permission denied",
  "privilege",
  "admin",
  "secret",
  "token",
  "password",
  "private_key",
  "credential",
  "suspicious",
]);

const DEFAULT_SENSITIVE_EVENT_TYPES = Object.freeze([
  "unauthorized_access",
  "auth_failure",
  "privilege_escalation",
  "permission_change",
  "admin_override",
  "secret_access",
  "token_leak",
]);

const SEVERITIES: EventSeverity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export default class EventLogScanner {
  private readonly sensitiveKeywords: string[];
  private readonly sensitiveEventTypes: string[];

  constructor(options: EventLogScannerOptions = {}) {
    this.sensitiveKeywords = normalizeSignals(
      options.sensitiveKeywords || DEFAULT_SENSITIVE_KEYWORDS
    );
    this.sensitiveEventTypes = normalizeSignals(
      options.sensitiveEventTypes || DEFAULT_SENSITIVE_EVENT_TYPES
    );
  }

  scanFile(
    filePath: string,
    options: EventLogScannerOptions = {}
  ): EventLogScanResult {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Event log file does not exist: ${filePath}`);
    }
    const content = fs.readFileSync(filePath, "utf8");
    return this.scanText(content, {
      ...options,
      source: options.source || filePath,
    });
  }

  scanText(
    logText: string,
    options: EventLogScannerOptions = {}
  ): EventLogScanResult {
    if (typeof logText !== "string") {
      throw new Error("Event log input must be a string");
    }

    const events = logText
      .split(/\r?\n/)
      .map((line, index) => ({ line, lineNumber: index + 1 }))
      .filter(({ line }) => line.trim().length > 0)
      .map(({ line, lineNumber }) =>
        this.normalizeEvent(parseLogLine(line), lineNumber, options)
      );

    const index = buildIndex(events);
    const sensitiveEvents = events.filter((event) => event.sensitive);

    return {
      source: options.source || "event-log",
      scannedAt: options.scannedAt || new Date().toISOString(),
      totalEvents: events.length,
      sensitiveCount: sensitiveEvents.length,
      events,
      sensitiveEvents,
      index,
    };
  }

  generateReport(result: EventLogScanResult): string {
    const lines = [
      "# Event Log Scan",
      "",
      `Source: ${result.source}`,
      `Scanned at: ${result.scannedAt}`,
      `Total events: ${result.totalEvents}`,
      `Sensitive events: ${result.sensitiveCount}`,
      "",
      "## Sensitive Events",
      "",
    ];

    if (result.sensitiveEvents.length === 0) {
      lines.push("No sensitive events detected.", "");
      return lines.join("\n");
    }

    for (const event of result.sensitiveEvents) {
      lines.push(
        `- [${event.severity}] ${event.eventType} at line ${event.line}`,
        `  - Source: ${event.source}`,
        `  - Signals: ${event.matchedSignals.join(", ")}`
      );
      if (event.repository) lines.push(`  - Repository: ${event.repository}`);
      if (event.actor) lines.push(`  - Actor: ${event.actor}`);
      if (event.message) lines.push(`  - Message: ${event.message}`);
    }

    lines.push("");
    return lines.join("\n");
  }

  private normalizeEvent(
    raw: unknown,
    lineNumber: number,
    options: EventLogScannerOptions
  ): EventLogEntry {
    const eventType =
      readString(raw, ["eventType", "event_type", "event", "type", "action", "alert"]) ||
      "unknown";
    const timestamp =
      readString(raw, ["timestamp", "time", "created_at", "createdAt"]) ||
      "unknown";
    const source =
      readString(raw, ["source", "service"]) ||
      options.source ||
      "event-log";
    const actor =
      readString(raw, ["actor", "user", "username", "login"]) ||
      readNestedString(raw, ["sender", "login"]);
    const repository =
      readString(raw, ["repository", "repo"]) ||
      readNestedString(raw, ["repository", "full_name"]);
    const message =
      readString(raw, ["message", "msg", "detail", "description"]) ||
      (typeof raw === "string" ? raw : undefined);
    const rawSeverity = readString(raw, ["severity", "level"]);
    const matchedSignals = this.findMatchedSignals(eventType, raw);
    const severity = normalizeSeverity(rawSeverity) || inferSeverity(matchedSignals);
    const sensitive =
      matchedSignals.length > 0 || severity === "HIGH" || severity === "CRITICAL";

    return {
      id: readString(raw, ["id", "event_id", "request_id"]) || makeId(lineNumber, eventType),
      line: lineNumber,
      timestamp,
      eventType,
      source,
      severity,
      sensitive,
      matchedSignals,
      raw,
      actor,
      repository,
      message,
    };
  }

  private findMatchedSignals(eventType: string, raw: unknown): string[] {
    const haystack = `${eventType} ${safeStringify(raw)}`.toLowerCase();
    const matches = new Set<string>();

    for (const eventSignal of this.sensitiveEventTypes) {
      if (eventType.toLowerCase().includes(eventSignal)) {
        matches.add(eventSignal);
      }
    }

    for (const keyword of this.sensitiveKeywords) {
      if (haystack.includes(keyword)) {
        matches.add(keyword);
      }
    }

    return Array.from(matches).sort();
  }
}

export function generateEventLogReport(result: EventLogScanResult): string {
  return new EventLogScanner().generateReport(result);
}

function parseLogLine(line: string): unknown {
  const trimmed = line.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    const kv = parseKeyValueLine(trimmed);
    return kv || trimmed;
  }
}

function parseKeyValueLine(line: string): Record<string, string> | null {
  const pairs = Array.from(line.matchAll(/([A-Za-z0-9_.-]+)=("[^"]*"|'[^']*'|\S+)/g));
  if (pairs.length === 0) return null;

  const parsed: Record<string, string> = {};
  for (const pair of pairs) {
    const key = pair[1];
    const value = pair[2].replace(/^["']|["']$/g, "");
    parsed[key] = value;
  }
  return parsed;
}

function buildIndex(events: EventLogEntry[]): EventLogIndex {
  const index: EventLogIndex = {
    byType: {},
    byActor: {},
    byRepository: {},
  };

  for (const event of events) {
    addToIndex(index.byType, event.eventType, event);
    if (event.actor) addToIndex(index.byActor, event.actor, event);
    if (event.repository) addToIndex(index.byRepository, event.repository, event);
  }

  return index;
}

function addToIndex(
  target: Record<string, EventLogEntry[]>,
  key: string,
  event: EventLogEntry
): void {
  if (!target[key]) target[key] = [];
  target[key].push(event);
}

function normalizeSignals(signals: readonly string[]): string[] {
  return signals.map((signal) => signal.toLowerCase().trim()).filter(Boolean);
}

function readString(raw: unknown, keys: string[]): string | undefined {
  if (!isRecord(raw)) return undefined;
  for (const key of keys) {
    const value = raw[key];
    if (typeof value === "string" && value.trim()) return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
  }
  return undefined;
}

function readNestedString(raw: unknown, path: string[]): string | undefined {
  let current: unknown = raw;
  for (const segment of path) {
    if (!isRecord(current)) return undefined;
    current = current[segment];
  }
  return typeof current === "string" && current.trim() ? current : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeSeverity(value: string | undefined): EventSeverity | undefined {
  if (!value) return undefined;
  const upper = value.toUpperCase();
  return SEVERITIES.includes(upper as EventSeverity)
    ? (upper as EventSeverity)
    : undefined;
}

function inferSeverity(signals: string[]): EventSeverity {
  if (signals.some((signal) => signal.includes("private_key") || signal.includes("token_leak"))) {
    return "CRITICAL";
  }
  if (
    signals.some((signal) =>
      ["unauthorized", "access denied", "permission denied", "privilege", "admin", "secret", "token"].some(
        (criticalSignal) => signal.includes(criticalSignal)
      )
    )
  ) {
    return "HIGH";
  }
  return signals.length > 0 ? "MEDIUM" : "LOW";
}

function safeStringify(raw: unknown): string {
  if (typeof raw === "string") return raw;
  try {
    return JSON.stringify(raw);
  } catch {
    return String(raw);
  }
}

function makeId(lineNumber: number, eventType: string): string {
  const slug = eventType.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return `line-${lineNumber}-${slug || "event"}`;
}
