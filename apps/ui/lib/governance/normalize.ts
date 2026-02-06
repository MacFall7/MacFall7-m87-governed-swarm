/**
 * Governance Normalization
 *
 * Enforces fail-closed reconciliation at the ingestion boundary.
 * ALL governance data MUST pass through normalizeIncomingGovernance().
 */

import type {
  GovernanceState,
  GovernanceEvent,
  GovernanceEventType,
  BudgetState,
  GateState,
  GateDecision,
  ReversibilityClass,
  CleanupCost,
  ExecutionMode,
  BlockingReason,
  NormalizationMetadata,
  RawGovernanceResponse,
  RawGovernanceEvent,
  RawBudgetState,
  RawGateState,
} from "./types";

// ---- Enum Normalization (fail-closed) ----

const VALID_REVERSIBILITY_CLASSES = new Set<ReversibilityClass>([
  "REVERSIBLE",
  "PARTIALLY_REVERSIBLE",
  "IRREVERSIBLE",
]);

const VALID_CLEANUP_COSTS = new Set<CleanupCost>(["LOW", "MEDIUM", "HIGH"]);

const VALID_EXECUTION_MODES = new Set<ExecutionMode>([
  "commit",
  "draft",
  "preview",
]);

const VALID_GATE_DECISIONS = new Set<GateDecision>([
  "allowed",
  "blocked",
  "escalated",
]);

const VALID_BLOCKING_REASONS = new Set<BlockingReason>([
  "MODE_CONTRACT",
  "REVERSIBILITY",
  "RETRY_BUDGET",
  "STEP_BUDGET",
  "TOOL_BUDGET",
  "RUNTIME_BUDGET",
  "HUMAN_APPROVAL_REQUIRED",
]);

const VALID_EVENT_TYPES = new Set<GovernanceEventType>([
  "reversibility_gate.allowed",
  "reversibility_gate.blocked",
  "mode_contract.allowed",
  "mode_contract.blocked",
  "budget.exceeded",
  "proposal.allowed",
  "proposal.denied",
  "proposal.needs_approval",
  "proposal.approved",
  "job.created",
  "job.completed",
  "job.failed",
]);

function normalizeReversibilityClass(
  raw: unknown,
  unknownFields: string[]
): ReversibilityClass {
  if (typeof raw === "string") {
    const upper = raw.toUpperCase() as ReversibilityClass;
    if (VALID_REVERSIBILITY_CLASSES.has(upper)) {
      return upper;
    }
    unknownFields.push(`reversibility_class:${raw}`);
  }
  return "UNKNOWN";
}

function normalizeCleanupCost(
  raw: unknown,
  unknownFields: string[]
): CleanupCost {
  if (typeof raw === "string") {
    const upper = raw.toUpperCase() as CleanupCost;
    if (VALID_CLEANUP_COSTS.has(upper)) {
      return upper;
    }
    unknownFields.push(`cleanup_cost:${raw}`);
  }
  return "UNKNOWN";
}

function normalizeExecutionMode(
  raw: unknown,
  unknownFields: string[]
): ExecutionMode {
  if (typeof raw === "string") {
    const lower = raw.toLowerCase() as ExecutionMode;
    if (VALID_EXECUTION_MODES.has(lower)) {
      return lower;
    }
    unknownFields.push(`execution_mode:${raw}`);
  }
  return "unknown";
}

function normalizeGateDecision(
  raw: unknown,
  unknownFields: string[],
  fieldName: string
): GateDecision {
  if (typeof raw === "string") {
    const lower = raw.toLowerCase() as GateDecision;
    if (VALID_GATE_DECISIONS.has(lower)) {
      return lower;
    }
    unknownFields.push(`${fieldName}:${raw}`);
  }
  return "unknown";
}

function normalizeBlockingReason(
  raw: unknown,
  unknownFields: string[]
): BlockingReason | undefined {
  if (!raw) return undefined;
  if (typeof raw === "string") {
    const upper = raw.toUpperCase() as BlockingReason;
    if (VALID_BLOCKING_REASONS.has(upper)) {
      return upper;
    }
    unknownFields.push(`blocking_reason:${raw}`);
    return "UNKNOWN";
  }
  return undefined;
}

function normalizeEventType(
  raw: unknown,
  unknownFields: string[]
): GovernanceEventType {
  if (typeof raw === "string") {
    if (VALID_EVENT_TYPES.has(raw as GovernanceEventType)) {
      return raw as GovernanceEventType;
    }
    unknownFields.push(`event_type:${raw}`);
  }
  return "unknown.event";
}

// ---- Timestamp Normalization ----

function normalizeTimestamp(raw: unknown): Date {
  if (raw instanceof Date) {
    return raw;
  }
  if (typeof raw === "string") {
    const parsed = new Date(raw);
    if (!isNaN(parsed.getTime())) {
      return parsed;
    }
  }
  if (typeof raw === "number") {
    return new Date(raw);
  }
  return new Date();
}

// ---- Event Normalization ----

function normalizeEvent(
  raw: RawGovernanceEvent,
  unknownFields: string[]
): GovernanceEvent {
  return {
    type: normalizeEventType(raw.type, unknownFields),
    timestamp: normalizeTimestamp(raw.timestamp),
    timestamp_raw: typeof raw.timestamp === "string" ? raw.timestamp : undefined,
    proposal_id: raw.proposal_id,
    job_id: raw.job_id,
    agent: raw.agent,
    principal_id: raw.principal_id,
    reversibility_class: raw.reversibility_class
      ? normalizeReversibilityClass(raw.reversibility_class, unknownFields)
      : undefined,
    cleanup_cost: raw.cleanup_cost
      ? normalizeCleanupCost(raw.cleanup_cost, unknownFields)
      : undefined,
    execution_mode: raw.execution_mode
      ? normalizeExecutionMode(raw.execution_mode, unknownFields)
      : undefined,
    blocking_reason: normalizeBlockingReason(raw.blocking_reason, unknownFields),
    budget_multiplier: raw.budget_multiplier,
    retry_limit: raw.retry_limit,
    payload: raw.payload,
  };
}

// ---- Budget Normalization ----

function normalizeBudgetState(raw: RawBudgetState | undefined): BudgetState {
  const maxSteps = raw?.max_steps ?? 0;
  const stepsUsed = raw?.steps_used ?? 0;

  // Fix math bug: percentage_used must be (steps_used / max_steps) * 100
  // max_steps === 0 is handled specially (forces blocked)
  const percentageUsed =
    maxSteps > 0 ? (stepsUsed / maxSteps) * 100 : 100;

  return {
    max_steps: maxSteps,
    steps_used: stepsUsed,
    percentage_used: percentageUsed,
    max_tool_calls: raw?.max_tool_calls ?? 0,
    tool_calls_used: raw?.tool_calls_used ?? 0,
    max_runtime_seconds: raw?.max_runtime_seconds ?? 0,
    runtime_used_seconds: raw?.runtime_used_seconds ?? 0,
    retries_remaining: raw?.retries_remaining ?? null,
    budget_multiplier: raw?.budget_multiplier ?? 1.0,
  };
}

// ---- Gate State Normalization ----

function normalizeGateState(
  raw: RawGateState | undefined,
  unknownFields: string[]
): GateState {
  const reversibility = normalizeGateDecision(
    raw?.reversibility,
    unknownFields,
    "gate.reversibility"
  );
  const modeContract = normalizeGateDecision(
    raw?.mode_contract,
    unknownFields,
    "gate.mode_contract"
  );
  const humanApproval = normalizeGateDecision(
    raw?.human_approval,
    unknownFields,
    "gate.human_approval"
  );
  const overall = normalizeGateDecision(
    raw?.overall,
    unknownFields,
    "gate.overall"
  );

  return {
    reversibility,
    mode_contract: modeContract,
    human_approval: humanApproval,
    overall,
  };
}

// ---- Blocking Signal Detection (fail-closed) ----

interface BlockingSignals {
  blocked: boolean;
  reason?: BlockingReason;
  failClosedTriggered: boolean;
}

function detectBlockingSignals(
  raw: RawGovernanceResponse,
  budgetState: BudgetState,
  gateState: GateState
): BlockingSignals {
  const signals: string[] = [];
  let reason: BlockingReason | undefined;

  // Check if budget_state was actually provided in raw data
  // If not, budget-related checks should not trigger (read-only actions don't have budgets)
  const hasBudgetState = raw.budget_state !== undefined;

  // Signal 1: Explicit blocking_reason
  if (raw.blocking_reason) {
    signals.push("blocking_reason_present");
    reason = raw.blocking_reason.toUpperCase() as BlockingReason;
  }

  // Signal 2: Gate decision resolves to blocked
  if (gateState.overall === "blocked") {
    signals.push("gate.overall=blocked");
    if (!reason) {
      if (gateState.reversibility === "blocked") {
        reason = "REVERSIBILITY";
      } else if (gateState.mode_contract === "blocked") {
        reason = "MODE_CONTRACT";
      } else if (gateState.human_approval === "blocked") {
        reason = "HUMAN_APPROVAL_REQUIRED";
      }
    }
  }

  // Signal 3: Retries exhausted (only if budget_state was provided)
  if (
    hasBudgetState &&
    budgetState.retries_remaining !== null &&
    budgetState.retries_remaining <= 0
  ) {
    signals.push("retries_remaining<=0");
    if (!reason) reason = "RETRY_BUDGET";
  }

  // Signal 4: max_steps === 0 (only if budget_state was explicitly provided with max_steps=0)
  // This distinguishes "explicitly set to 0" from "field missing entirely"
  if (hasBudgetState && raw.budget_state?.max_steps === 0) {
    signals.push("max_steps=0");
    if (!reason) reason = "STEP_BUDGET";
  }

  // Signal 5: steps_used >= max_steps (when max_steps > 0)
  if (
    hasBudgetState &&
    budgetState.max_steps > 0 &&
    budgetState.steps_used >= budgetState.max_steps
  ) {
    signals.push("steps_used>=max_steps");
    if (!reason) reason = "STEP_BUDGET";
  }

  // Signal 6: tool_calls exhausted (only if budget_state was provided)
  if (
    hasBudgetState &&
    budgetState.max_tool_calls > 0 &&
    budgetState.tool_calls_used >= budgetState.max_tool_calls
  ) {
    signals.push("tool_calls_exhausted");
    if (!reason) reason = "TOOL_BUDGET";
  }

  // Signal 7: Explicit blocked=true
  if (raw.blocked === true) {
    signals.push("explicit_blocked=true");
  }

  const blocked = signals.length > 0;
  const failClosedTriggered = blocked && raw.blocked !== true;

  return { blocked, reason, failClosedTriggered };
}

// ---- Main Normalization Function ----

/**
 * Normalize a raw governance response into canonical GovernanceState.
 *
 * This is the ONLY entry point for governance data.
 * Enforces fail-closed reconciliation.
 */
export function normalizeGovernanceState(
  raw: RawGovernanceResponse,
  source: NormalizationMetadata["source"] = "raw"
): GovernanceState {
  const unknownFields: string[] = [];
  const rawValues: Record<string, unknown> = {};

  // Normalize nested structures
  const budgetState = normalizeBudgetState(raw.budget_state);
  const gateState = normalizeGateState(raw.gate_state, unknownFields);
  const events = (raw.events || []).map((e) => normalizeEvent(e, unknownFields));

  // Detect blocking signals (fail-closed)
  const blockingSignals = detectBlockingSignals(raw, budgetState, gateState);

  // Record raw values for unknown fields
  if (raw.reversibility_class && !VALID_REVERSIBILITY_CLASSES.has(raw.reversibility_class.toUpperCase() as ReversibilityClass)) {
    rawValues.reversibility_class = raw.reversibility_class;
  }
  if (raw.cleanup_cost && !VALID_CLEANUP_COSTS.has(raw.cleanup_cost.toUpperCase() as CleanupCost)) {
    rawValues.cleanup_cost = raw.cleanup_cost;
  }

  const state: GovernanceState = {
    proposal_id: raw.proposal_id || "unknown",
    job_id: raw.job_id,
    agent: raw.agent || "unknown",
    principal_id: raw.principal_id || "unknown",

    blocked: blockingSignals.blocked,
    blocking_reason: blockingSignals.reason,
    gate_state: gateState,
    budget_state: budgetState,

    reversibility_class: normalizeReversibilityClass(
      raw.reversibility_class,
      unknownFields
    ),
    cleanup_cost: normalizeCleanupCost(raw.cleanup_cost, unknownFields),
    execution_mode: normalizeExecutionMode(raw.execution_mode, unknownFields),
    human_approved: raw.human_approved ?? false,

    events,

    _normalization: {
      normalized_at: new Date(),
      source,
      unknown_fields: unknownFields,
      raw_values: rawValues,
      reconciliation_applied: blockingSignals.failClosedTriggered,
      fail_closed_triggered: blockingSignals.failClosedTriggered,
    },
  };

  return state;
}

// ---- Ingestion Adapter (single entry point) ----

/**
 * The ONLY entry point for governance data.
 *
 * Behavior:
 * - If raw is falsy → return undefined
 * - If raw resembles GovernanceState → reconcile and enforce fail-closed
 * - If raw resembles RawGovernanceResponse → normalize
 * - Always enforce blocking signals
 */
export function normalizeIncomingGovernance(
  raw: unknown
): GovernanceState | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }

  const obj = raw as Record<string, unknown>;

  // Check if already normalized (has _normalization metadata)
  if (obj._normalization && typeof obj._normalization === "object") {
    // Already normalized - reconcile
    return reconcileGovernanceState(obj as unknown as GovernanceState);
  }

  // Treat as raw response
  return normalizeGovernanceState(obj as RawGovernanceResponse, "raw");
}

/**
 * Reconcile an existing GovernanceState.
 *
 * Re-applies fail-closed logic and ensures timestamps are Date objects.
 */
function reconcileGovernanceState(state: GovernanceState): GovernanceState {
  const unknownFields = [...(state._normalization?.unknown_fields || [])];

  // Ensure event timestamps are Date objects
  const events = state.events.map((e) => ({
    ...e,
    timestamp: normalizeTimestamp(e.timestamp),
  }));

  // Re-check blocking signals
  // For reconciliation, we must include budget_state to ensure budget checks run
  const rawForBlocking: RawGovernanceResponse = {
    blocked: state.blocked,
    blocking_reason: state.blocking_reason,
    budget_state: {
      max_steps: state.budget_state.max_steps,
      steps_used: state.budget_state.steps_used,
      max_tool_calls: state.budget_state.max_tool_calls,
      tool_calls_used: state.budget_state.tool_calls_used,
      retries_remaining: state.budget_state.retries_remaining,
    },
  };
  const blockingSignals = detectBlockingSignals(
    rawForBlocking,
    state.budget_state,
    state.gate_state
  );

  return {
    ...state,
    blocked: blockingSignals.blocked,
    blocking_reason: blockingSignals.reason || state.blocking_reason,
    events,
    _normalization: {
      ...state._normalization,
      normalized_at: new Date(),
      source: "reconciled",
      unknown_fields: unknownFields,
      reconciliation_applied: true,
      fail_closed_triggered:
        state._normalization?.fail_closed_triggered ||
        blockingSignals.failClosedTriggered,
    },
  };
}

// ---- Exports ----

export {
  normalizeReversibilityClass,
  normalizeCleanupCost,
  normalizeExecutionMode,
  normalizeGateDecision,
  normalizeBlockingReason,
  normalizeEventType,
  normalizeTimestamp,
  normalizeBudgetState,
  normalizeGateState,
  detectBlockingSignals,
  reconcileGovernanceState,
};
