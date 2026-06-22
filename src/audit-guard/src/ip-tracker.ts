export class IPTracker {
  private requests: Map<string, number[]>;
  private maxReqPerMin: number;
  private banList: Set<string>;

  constructor(maxReqPerMin: number = 100) {
    this.requests = new Map();
    this.banList = new Set();
    this.maxReqPerMin = maxReqPerMin;
  }

  /**
   * Records a request from an IP. Returns true if allowed, false if banned.
   */
  public recordRequest(ip: string): boolean {
    if (this.banList.has(ip)) {
      return false;
    }

    const now = Date.now();
    const oneMinAgo = now - 60 * 1000;

    let timestamps = this.requests.get(ip) || [];
    // Filter out requests older than 1 minute
    timestamps = timestamps.filter((time) => time > oneMinAgo);
    timestamps.push(now);

    this.requests.set(ip, timestamps);

    if (timestamps.length > this.maxReqPerMin) {
      this.banList.add(ip);
      return false;
    }

    return true;
  }

  public isBanned(ip: string): boolean {
    return this.banList.has(ip);
  }

  public getRequestCount(ip: string): number {
    const now = Date.now();
    const oneMinAgo = now - 60 * 1000;
    const timestamps = this.requests.get(ip) || [];
    return timestamps.filter((time) => time > oneMinAgo).length;
  }

  public unban(ip: string): void {
    this.banList.delete(ip);
    this.requests.delete(ip);
  }
}
