/**
 * Governance State Types
 *
 * Canonical types for governance observability.
 * All governance data MUST be normalized to these types before display or analytics.
 */

// ---- Enums (fail-closed defaults) ----

export type ReversibilityClass = "REVERSIBLE" | "PARTIALLY_REVERSIBLE" | "IRREVERSIBLE" | "UNKNOWN";
export type CleanupCost = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
export type ExecutionMode = "commit" | "draft" | "preview" | "unknown";
export type GateDecision = "allowed" | "blocked" | "escalated" | "unknown";

export type BlockingReason =
  | "MODE_CONTRACT"
  | "REVERSIBILITY"
  | "RETRY_BUDGET"
  | "STEP_BUDGET"
  | "TOOL_BUDGET"
  | "RUNTIME_BUDGET"
  | "HUMAN_APPROVAL_REQUIRED"
  | "UNKNOWN";

export type GovernanceEventType =
  | "reversibility_gate.allowed"
  | "reversibility_gate.blocked"
  | "mode_contract.allowed"
  | "mode_contract.blocked"
  | "budget.exceeded"
  | "proposal.allowed"
  | "proposal.denied"
  | "proposal.needs_approval"
  | "proposal.approved"
  | "job.created"
  | "job.completed"
  | "job.failed"
  | "unknown.event";

// ---- Core Types ----

export interface GovernanceEvent {
  type: GovernanceEventType;
  timestamp: Date;
  timestamp_raw?: string;
  proposal_id?: string;
  job_id?: string;
  agent?: string;
  principal_id?: string;
  reversibility_class?: ReversibilityClass;
  cleanup_cost?: CleanupCost;
  execution_mode?: ExecutionMode;
  blocking_reason?: BlockingReason;
  budget_multiplier?: number;
  retry_limit?: number;
  payload?: Record<string, unknown>;
}

export interface BudgetState {
  max_steps: number;
  steps_used: number;
  percentage_used: number;
  max_tool_calls: number;
  tool_calls_used: number;
  max_runtime_seconds: number;
  runtime_used_seconds: number;
  retries_remaining: number | null;
  budget_multiplier: number;
}

export interface GateState {
  reversibility: GateDecision;
  mode_contract: GateDecision;
  human_approval: GateDecision;
  overall: GateDecision;
}

export interface NormalizationMetadata {
  normalized_at: Date;
  source: "raw" | "cached" | "mock" | "reconciled";
  unknown_fields: string[];
  raw_values: Record<string, unknown>;
  reconciliation_applied: boolean;
  fail_closed_triggered: boolean;
}

export interface GovernanceState {
  // Identity
  proposal_id: string;
  job_id?: string;
  agent: string;
  principal_id: string;

  // Core state
  blocked: boolean;
  blocking_reason?: BlockingReason;
  gate_state: GateState;
  budget_state: BudgetState;

  // Reversibility
  reversibility_class: ReversibilityClass;
  cleanup_cost: CleanupCost;
  execution_mode: ExecutionMode;
  human_approved: boolean;

  // Telemetry
  events: GovernanceEvent[];

  // Metadata
  _normalization: NormalizationMetadata;
}

// ---- Raw Response Types (from backend) ----

export interface RawGovernanceEvent {
  type?: string;
  timestamp?: string | number | Date;
  proposal_id?: string;
  job_id?: string;
  agent?: string;
  principal_id?: string;
  reversibility_class?: string;
  cleanup_cost?: string;
  execution_mode?: string;
  blocking_reason?: string;
  budget_multiplier?: number;
  retry_limit?: number;
  payload?: Record<string, unknown>;
}

export interface RawBudgetState {
  max_steps?: number;
  steps_used?: number;
  percentage_used?: number;
  max_tool_calls?: number;
  tool_calls_used?: number;
  max_runtime_seconds?: number;
  runtime_used_seconds?: number;
  retries_remaining?: number | null;
  budget_multiplier?: number;
}

export interface RawGateState {
  reversibility?: string;
  mode_contract?: string;
  human_approval?: string;
  overall?: string;
}

export interface RawGovernanceResponse {
  proposal_id?: string;
  job_id?: string;
  agent?: string;
  principal_id?: string;
  blocked?: boolean;
  blocking_reason?: string;
  gate_state?: RawGateState;
  budget_state?: RawBudgetState;
  reversibility_class?: string;
  cleanup_cost?: string;
  execution_mode?: string;
  human_approved?: boolean;
  events?: RawGovernanceEvent[];
}
