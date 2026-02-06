/**
 * Governance Analytics
 *
 * All analytics consume ONLY normalized GovernanceState.
 * Computes metrics for governance observability dashboard.
 */

import type {
  GovernanceState,
  GovernanceEvent,
  BlockingReason,
  CleanupCost,
  ExecutionMode,
  ReversibilityClass,
} from "./types";

// ---- Time Windows ----

export type TimeWindow = "1h" | "24h" | "7d" | "30d" | "all";

function getWindowStart(window: TimeWindow): Date {
  const now = new Date();
  switch (window) {
    case "1h":
      return new Date(now.getTime() - 60 * 60 * 1000);
    case "24h":
      return new Date(now.getTime() - 24 * 60 * 60 * 1000);
    case "7d":
      return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    case "30d":
      return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    case "all":
      return new Date(0);
  }
}

function filterByWindow<T extends { timestamp: Date }>(
  items: T[],
  window: TimeWindow
): T[] {
  const start = getWindowStart(window);
  return items.filter((item) => item.timestamp >= start);
}

// ---- Block Rate ----

export interface BlockRateMetrics {
  window: TimeWindow;
  total_decisions: number;
  blocked_count: number;
  allowed_count: number;
  block_rate: number; // 0-1
  block_rate_percent: number; // 0-100
}

export function computeBlockRate(
  states: GovernanceState[],
  window: TimeWindow = "24h"
): BlockRateMetrics {
  // Filter by window using _normalization.normalized_at
  const start = getWindowStart(window);
  const filtered = states.filter(
    (s) => s._normalization.normalized_at >= start
  );

  const total = filtered.length;
  const blocked = filtered.filter((s) => s.blocked).length;
  const allowed = total - blocked;

  const blockRate = total > 0 ? blocked / total : 0;

  return {
    window,
    total_decisions: total,
    blocked_count: blocked,
    allowed_count: allowed,
    block_rate: blockRate,
    block_rate_percent: blockRate * 100,
  };
}

// ---- Top Blocking Reasons ----

export interface BlockingReasonCount {
  reason: BlockingReason;
  count: number;
  percentage: number;
}

export interface TopBlockingReasons {
  window: TimeWindow;
  total_blocked: number;
  reasons: BlockingReasonCount[];
}

export function computeTopBlockingReasons(
  states: GovernanceState[],
  window: TimeWindow = "7d"
): TopBlockingReasons {
  const start = getWindowStart(window);
  const blocked = states.filter(
    (s) => s.blocked && s._normalization.normalized_at >= start
  );

  const counts = new Map<BlockingReason, number>();
  for (const state of blocked) {
    const reason = state.blocking_reason || "UNKNOWN";
    counts.set(reason, (counts.get(reason) || 0) + 1);
  }

  const total = blocked.length;
  const reasons: BlockingReasonCount[] = Array.from(counts.entries())
    .map(([reason, count]) => ({
      reason,
      count,
      percentage: total > 0 ? (count / total) * 100 : 0,
    }))
    .sort((a, b) => b.count - a.count);

  return {
    window,
    total_blocked: total,
    reasons,
  };
}

// ---- Cleanup Cost Distribution ----

export interface CleanupCostCount {
  cost: CleanupCost;
  count: number;
  percentage: number;
}

export interface CleanupCostDistribution {
  window: TimeWindow;
  total: number;
  distribution: CleanupCostCount[];
}

export function computeCleanupCostDistribution(
  states: GovernanceState[],
  window: TimeWindow = "7d"
): CleanupCostDistribution {
  const start = getWindowStart(window);
  const filtered = states.filter(
    (s) => s._normalization.normalized_at >= start
  );

  const counts = new Map<CleanupCost, number>();
  for (const state of filtered) {
    const cost = state.cleanup_cost;
    counts.set(cost, (counts.get(cost) || 0) + 1);
  }

  const total = filtered.length;
  const distribution: CleanupCostCount[] = (
    ["LOW", "MEDIUM", "HIGH", "UNKNOWN"] as CleanupCost[]
  )
    .map((cost) => ({
      cost,
      count: counts.get(cost) || 0,
      percentage: total > 0 ? ((counts.get(cost) || 0) / total) * 100 : 0,
    }))
    .filter((d) => d.count > 0);

  return {
    window,
    total,
    distribution,
  };
}

// ---- Mode Violations ----

export interface ModeViolation {
  proposal_id: string;
  requested_mode: ExecutionMode;
  enforced_mode: ExecutionMode;
  timestamp: Date;
}

export interface ModeViolationMetrics {
  window: TimeWindow;
  total_requests: number;
  violations: ModeViolation[];
  violation_count: number;
  violation_rate: number;
}

export function computeModeViolations(
  states: GovernanceState[],
  window: TimeWindow = "7d"
): ModeViolationMetrics {
  const start = getWindowStart(window);
  const filtered = states.filter(
    (s) => s._normalization.normalized_at >= start
  );

  // Look for mode_contract.blocked events
  const violations: ModeViolation[] = [];
  for (const state of filtered) {
    const modeEvents = state.events.filter(
      (e) => e.type === "mode_contract.blocked"
    );
    for (const event of modeEvents) {
      violations.push({
        proposal_id: state.proposal_id,
        requested_mode: event.execution_mode || "unknown",
        enforced_mode: "commit", // Mode contract enforces commit-only
        timestamp: event.timestamp,
      });
    }
  }

  return {
    window,
    total_requests: filtered.length,
    violations,
    violation_count: violations.length,
    violation_rate:
      filtered.length > 0 ? violations.length / filtered.length : 0,
  };
}

// ---- Irreversible Actions ----

export interface IrreversibleActionMetrics {
  window: TimeWindow;
  total_decisions: number;
  irreversible_allowed: number;
  irreversible_blocked: number;
  irreversible_allowed_rate: number;
}

export function computeIrreversibleActions(
  states: GovernanceState[],
  window: TimeWindow = "7d"
): IrreversibleActionMetrics {
  const start = getWindowStart(window);
  const filtered = states.filter(
    (s) => s._normalization.normalized_at >= start
  );

  const irreversible = filtered.filter(
    (s) => s.reversibility_class === "IRREVERSIBLE"
  );
  const allowed = irreversible.filter((s) => !s.blocked).length;
  const blocked = irreversible.filter((s) => s.blocked).length;

  return {
    window,
    total_decisions: filtered.length,
    irreversible_allowed: allowed,
    irreversible_blocked: blocked,
    irreversible_allowed_rate:
      filtered.length > 0 ? allowed / filtered.length : 0,
  };
}

// ---- Budget Usage ----

export interface BudgetUsageMetrics {
  window: TimeWindow;
  average_step_usage: number;
  average_tool_call_usage: number;
  budget_exceeded_count: number;
  budget_exceeded_rate: number;
}

export function computeBudgetUsage(
  states: GovernanceState[],
  window: TimeWindow = "24h"
): BudgetUsageMetrics {
  const start = getWindowStart(window);
  const filtered = states.filter(
    (s) => s._normalization.normalized_at >= start
  );

  let totalStepUsage = 0;
  let totalToolUsage = 0;
  let exceededCount = 0;

  for (const state of filtered) {
    const budget = state.budget_state;
    if (budget.max_steps > 0) {
      totalStepUsage += budget.steps_used / budget.max_steps;
    }
    if (budget.max_tool_calls > 0) {
      totalToolUsage += budget.tool_calls_used / budget.max_tool_calls;
    }
    if (
      state.blocking_reason === "STEP_BUDGET" ||
      state.blocking_reason === "TOOL_BUDGET" ||
      state.blocking_reason === "RUNTIME_BUDGET"
    ) {
      exceededCount++;
    }
  }

  const count = filtered.length || 1;

  return {
    window,
    average_step_usage: (totalStepUsage / count) * 100,
    average_tool_call_usage: (totalToolUsage / count) * 100,
    budget_exceeded_count: exceededCount,
    budget_exceeded_rate: exceededCount / count,
  };
}

// ---- Composite Dashboard Metrics ----

export interface GovernanceDashboardMetrics {
  timestamp: Date;
  block_rate_24h: BlockRateMetrics;
  block_rate_7d: BlockRateMetrics;
  top_blocking_reasons: TopBlockingReasons;
  cleanup_cost_distribution: CleanupCostDistribution;
  mode_violations: ModeViolationMetrics;
  irreversible_actions: IrreversibleActionMetrics;
  budget_usage: BudgetUsageMetrics;
}

export function computeDashboardMetrics(
  states: GovernanceState[]
): GovernanceDashboardMetrics {
  return {
    timestamp: new Date(),
    block_rate_24h: computeBlockRate(states, "24h"),
    block_rate_7d: computeBlockRate(states, "7d"),
    top_blocking_reasons: computeTopBlockingReasons(states, "7d"),
    cleanup_cost_distribution: computeCleanupCostDistribution(states, "7d"),
    mode_violations: computeModeViolations(states, "7d"),
    irreversible_actions: computeIrreversibleActions(states, "7d"),
    budget_usage: computeBudgetUsage(states, "24h"),
  };
}

// ---- Time Series ----

export interface TimeSeriesPoint {
  timestamp: Date;
  value: number;
}

export interface BlockRateTimeSeries {
  window: TimeWindow;
  interval: "1h" | "1d";
  points: TimeSeriesPoint[];
}

export function computeBlockRateTimeSeries(
  states: GovernanceState[],
  window: TimeWindow = "7d",
  interval: "1h" | "1d" = "1d"
): BlockRateTimeSeries {
  const start = getWindowStart(window);
  const intervalMs = interval === "1h" ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;

  const filtered = states.filter(
    (s) => s._normalization.normalized_at >= start
  );

  // Group by interval
  const buckets = new Map<number, { blocked: number; total: number }>();

  for (const state of filtered) {
    const ts = state._normalization.normalized_at.getTime();
    const bucketKey = Math.floor(ts / intervalMs) * intervalMs;

    const bucket = buckets.get(bucketKey) || { blocked: 0, total: 0 };
    bucket.total++;
    if (state.blocked) bucket.blocked++;
    buckets.set(bucketKey, bucket);
  }

  // Convert to time series
  const points: TimeSeriesPoint[] = Array.from(buckets.entries())
    .map(([ts, data]) => ({
      timestamp: new Date(ts),
      value: data.total > 0 ? (data.blocked / data.total) * 100 : 0,
    }))
    .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  return {
    window,
    interval,
    points,
  };
}
