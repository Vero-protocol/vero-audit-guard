import { WEBHOOK_URL, WEBHOOK_TOKEN } from "./config";
import fetch from "node-fetch";

export interface AlertPayload {
  repository: string;
  alert: string;
  timestamp: string;
}

export async function sendAlert(payload: AlertPayload): Promise<void> {
  if (!WEBHOOK_URL) return; // No webhook configured
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (WEBHOOK_TOKEN) headers["Authorization"] = `Bearer ${WEBHOOK_TOKEN}`;
  try {
    await fetch(WEBHOOK_URL, { method: "POST", headers, body: JSON.stringify(payload) });
  } catch (e) {
    console.error("Failed to deliver audit‑guard webhook:", e);
  }
}
