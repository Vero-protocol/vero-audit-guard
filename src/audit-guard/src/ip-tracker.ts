export class IPTracker {
  private requests: Map<string, number[]>;
  private maxReqPerMin: number;
  private banList: Map<string, number>;
  private maxTrackedIps: number;
  private banTtl: number;

  constructor(maxReqPerMin: number = 100, maxTrackedIps: number = 100000, banTtl: number = 3600000) {
    this.requests = new Map();
    this.banList = new Map();
    this.maxReqPerMin = maxReqPerMin;
    this.maxTrackedIps = maxTrackedIps;
    this.banTtl = banTtl;
  }

  private sweep(now: number) {
    const oneMinAgo = now - 60 * 1000;
    
    for (const [ip, timestamps] of this.requests) {
      if (timestamps.length === 0 || timestamps[timestamps.length - 1] <= oneMinAgo) {
        this.requests.delete(ip);
      } else {
        break;
      }
    }

    for (const [ip, expiry] of this.banList) {
      if (now > expiry) {
        this.banList.delete(ip);
      } else {
        break;
      }
    }
  }

  private enforceCaps() {
    while (this.requests.size > this.maxTrackedIps) {
      const oldest = this.requests.keys().next().value;
      if (oldest !== undefined) this.requests.delete(oldest);
      else break;
    }
    
    while (this.banList.size > this.maxTrackedIps) {
      const oldest = this.banList.keys().next().value;
      if (oldest !== undefined) this.banList.delete(oldest);
      else break;
    }
  }

  /**
   * Records a request from an IP. Returns true if allowed, false if banned.
   */
  public recordRequest(ip: string): boolean {
    const now = Date.now();
    this.sweep(now);

    if (this.banList.has(ip)) {
      if (now > this.banList.get(ip)!) {
        this.banList.delete(ip);
      } else {
        return false;
      }
    }

    const oneMinAgo = now - 60 * 1000;
    let timestamps = this.requests.get(ip) || [];
    timestamps = timestamps.filter((time) => time > oneMinAgo);
    timestamps.push(now);

    this.requests.delete(ip);
    this.requests.set(ip, timestamps);

    this.enforceCaps();

    if (timestamps.length > this.maxReqPerMin) {
      this.banList.delete(ip);
      this.banList.set(ip, now + this.banTtl);
      this.enforceCaps();
      return false;
    }

    return true;
  }

  public isBanned(ip: string): boolean {
    const now = Date.now();
    this.sweep(now);
    if (this.banList.has(ip)) {
      if (now > this.banList.get(ip)!) {
        this.banList.delete(ip);
        return false;
      }
      return true;
    }
    return false;
  }

  public getRequestCount(ip: string): number {
    const now = Date.now();
    this.sweep(now);
    const oneMinAgo = now - 60 * 1000;
    const timestamps = this.requests.get(ip) || [];
    
    if (timestamps.length > 0) {
      this.requests.delete(ip);
      this.requests.set(ip, timestamps);
    }
    return timestamps.filter((time) => time > oneMinAgo).length;
  }

  public unban(ip: string): void {
    this.banList.delete(ip);
    this.requests.delete(ip);
  }
}
