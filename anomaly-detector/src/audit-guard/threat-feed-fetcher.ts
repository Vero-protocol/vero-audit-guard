import axios from "axios";

export class ThreatFeedFetcher {
  private threatAddresses: Set<string> = new Set<string>();
  private lastUpdated: Date | null = null;
  private mockThreats: Set<string> | null = null;

  /**
   * Fetches threat data from the configured URLs, parses them, and updates the in-memory cache.
   * If fetching fails, it keeps the last successfully cached data.
   */
  public async updateFeed(): Promise<void> {
    const urls = this.getFeedUrls();
    if (urls.length === 0) {
      console.warn("[threat-feed-fetcher] No threat feed URLs configured. Set THREAT_FEED_URLS or THREAT_FEED_URL.");
      return;
    }

    const newThreats = new Set<string>();
    let successfulFetches = 0;

    for (const url of urls) {
      try {
        console.log(`[threat-feed-fetcher] Fetching threat feed from: ${url}`);
        const response = await axios.get(url, { timeout: 4000 });
        const parsed = this.parseFeedData(response.data);
        
        parsed.forEach((addr) => newThreats.add(addr));
        successfulFetches++;
      } catch (err) {
        console.error(`[threat-feed-fetcher] Failed to fetch threat feed from ${url}:`, (err as Error).message);
      }
    }

    if (successfulFetches > 0) {
      this.threatAddresses = newThreats;
      this.lastUpdated = new Date();
      console.log(`[threat-feed-fetcher] Feed updated. Loaded ${this.threatAddresses.size} unique threat indicator(s).`);
    } else {
      console.warn("[threat-feed-fetcher] All threat feed fetches failed. Retaining previously cached threat data.");
    }
  }

  /**
   * Check if a given address is present in the threat feed.
   */
  public isThreat(address: string): boolean {
    if (this.mockThreats !== null) {
      return this.mockThreats.has(address);
    }
    return this.threatAddresses.has(address);
  }

  /**
   * Get the last successful update timestamp.
   */
  public getLastUpdated(): Date | null {
    return this.lastUpdated;
  }

  /**
   * Returns a copy of the current threat addresses.
   */
  public getThreatAddresses(): Set<string> {
    return new Set<string>(this.threatAddresses);
  }

  /**
   * Configure mock threat addresses for unit and integration testing.
   */
  public setMockThreats(addresses: string[]): void {
    this.mockThreats = new Set<string>(addresses);
  }

  /**
   * Reset mock configuration.
   */
  public clearMockThreats(): void {
    this.mockThreats = null;
  }

  /**
   * Clear the in-memory threat cache.
   */
  public clearCache(): void {
    this.threatAddresses.clear();
    this.lastUpdated = null;
  }

  private getFeedUrls(): string[] {
    const rawUrls = process.env.THREAT_FEED_URLS ?? process.env.THREAT_FEED_URL ?? "";
    return rawUrls
      .split(",")
      .map((url) => url.trim())
      .filter(Boolean);
  }

  private parseFeedData(data: unknown): Set<string> {
    const addresses = new Set<string>();
    const stellarAddressRegex = /^G[A-Z2-7]{55}$/;

    if (!data) return addresses;

    // Helper to recursively find stellar addresses in nested JSON
    const extractFromJson = (obj: any) => {
      if (typeof obj === "string") {
        if (stellarAddressRegex.test(obj)) {
          addresses.add(obj);
        }
      } else if (Array.isArray(obj)) {
        for (const item of obj) {
          extractFromJson(item);
        }
      } else if (typeof obj === "object" && obj !== null) {
        for (const key of Object.keys(obj)) {
          extractFromJson(obj[key]);
        }
      }
    };

    if (typeof data === "object") {
      extractFromJson(data);
    } else if (typeof data === "string") {
      try {
        const parsedJson = JSON.parse(data);
        extractFromJson(parsedJson);
      } catch {
        const tokens = data.split(/[\s,;\n\r]+/);
        for (const token of tokens) {
          const trimmed = token.trim();
          if (stellarAddressRegex.test(trimmed)) {
            addresses.add(trimmed);
          }
        }
      }
    }

    return addresses;
  }
}
