export interface PolicyLimits {
  maxSpendPerCallUsd: number;
  maxHourlySpendUsd: number;
  maxCallsPerHour: number;
  allowedDomains: string[];
}

export interface SpendEvaluationRequest {
  targetUrl: string;
  costUsd: number;
  toolName: string;
}

export interface SpendEvaluationResult {
  allowed: boolean;
  reason?: string;
  remainingHourlyBudgetUsd: number;
  callsInCurrentWindow: number;
}

interface HistoricalCall {
  timestamp: number;
  costUsd: number;
}

export class AgentSpendGuard {
  private policy: PolicyLimits;
  private callHistory: HistoricalCall[] = [];

  constructor(policy: PolicyLimits) {
    this.policy = policy;
  }

  private purgeStaleHistory(now: number): void {
    const oneHourAgo = now - 60 * 60 * 1000;
    this.callHistory = this.callHistory.filter((call) => call.timestamp > oneHourAgo);
  }

  public evaluate(request: SpendEvaluationRequest): SpendEvaluationResult {
    const now = Date.now();
    this.purgeStaleHistory(now);

    // 1. Domain Enforcement
    try {
      const url = new URL(request.targetUrl);
      const isDomainAllowed = this.policy.allowedDomains.some((domain) => {
        return url.hostname === domain || url.hostname.endsWith(`.${domain}`);
      });

      if (!isDomainAllowed) {
        return {
          allowed: false,
          reason: `Domain '${url.hostname}' is not permitted by policy.`,
          remainingHourlyBudgetUsd: this.getRemainingBudget(),
          callsInCurrentWindow: this.callHistory.length,
        };
      }
    } catch {
      return {
        allowed: false,
        reason: `Target URL '${request.targetUrl}' is invalid.`,
        remainingHourlyBudgetUsd: this.getRemainingBudget(),
        callsInCurrentWindow: this.callHistory.length,
      };
    }

    // 2. Single-Call Limit
    if (request.costUsd > this.policy.maxSpendPerCallUsd) {
      return {
        allowed: false,
        reason: `Cost of $${request.costUsd.toFixed(4)} exceeds single-call limit of $${this.policy.maxSpendPerCallUsd.toFixed(4)}.`,
        remainingHourlyBudgetUsd: this.getRemainingBudget(),
        callsInCurrentWindow: this.callHistory.length,
      };
    }

    // 3. Hourly Rate Limit
    if (this.callHistory.length >= this.policy.maxCallsPerHour) {
      return {
        allowed: false,
        reason: `Rate limit reached: Maximum ${this.policy.maxCallsPerHour} calls per hour exceeded.`,
        remainingHourlyBudgetUsd: this.getRemainingBudget(),
        callsInCurrentWindow: this.callHistory.length,
      };
    }

    // 4. Cumulative Hourly Spend
    const currentHourlySpend = this.callHistory.reduce((acc, call) => acc + call.costUsd, 0);
    if (currentHourlySpend + request.costUsd > this.policy.maxHourlySpendUsd) {
      return {
        allowed: false,
        reason: `Hourly spend limit of $${this.policy.maxHourlySpendUsd.toFixed(4)} exceeded. Requested: $${request.costUsd.toFixed(4)}, Available: $${(this.policy.maxHourlySpendUsd - currentHourlySpend).toFixed(4)}.`,
        remainingHourlyBudgetUsd: Math.max(0, this.policy.maxHourlySpendUsd - currentHourlySpend),
        callsInCurrentWindow: this.callHistory.length,
      };
    }

    // Record verified transaction
    this.callHistory.push({
      timestamp: now,
      costUsd: request.costUsd,
    });

    const updatedHourlySpend = currentHourlySpend + request.costUsd;

    return {
      allowed: true,
      remainingHourlyBudgetUsd: Math.max(0, this.policy.maxHourlySpendUsd - updatedHourlySpend),
      callsInCurrentWindow: this.callHistory.length,
    };
  }

  public getRemainingBudget(): number {
    this.purgeStaleHistory(Date.now());
    const spent = this.callHistory.reduce((acc, call) => acc + call.costUsd, 0);
    return Math.max(0, this.policy.maxHourlySpendUsd - spent);
  }
}
