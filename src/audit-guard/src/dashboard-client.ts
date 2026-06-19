import axios from "axios";

export interface DashboardAlert {
  source: "audit-guard" | "anomaly-detector" | "scanner-engine";
  type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  detail: string;
  timestamp: string;
  metadata: Record<string, any>;
}

export class DashboardClient {
  private url: string;
  private token: string;

  constructor(url: string, token: string) {
    this.url = url;
    this.token = token;
  }

  /**
   * Sends an alert to the Guardian Dashboard
   */
  async sendAlert(alert: DashboardAlert): Promise<boolean> {
    if (!this.url) {
      return false;
    }

    try {
      await axios.post(this.url, alert, {
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
        },
        timeout: 5000,
      });
      console.log(`[DashboardClient] Alert successfully pushed to dashboard: ${alert.type}`);
      return true;
    } catch (error: any) {
      console.error(
        `[DashboardClient] Failed to push alert to dashboard: ${error.message}`
      );
      if (error.response) {
        console.error(
          `[DashboardClient] Response status: ${error.response.status}`
        );
      }
      return false;
    }
  }
}

export default DashboardClient;
