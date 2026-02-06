/**
 * Governance Mock Data
 *
 * All mock data MUST flow through normalizeIncomingGovernance().
 * No mock governance state may bypass normalization.
 */

import type {
  RawGovernanceResponse,
  RawGovernanceEvent,
  RawBudgetState,
  RawGateState,
  GovernanceState,
} from "./types";
import { normalizeIncomingGovernance } from "./normalize";

// ---- Mock Data Builders ----

interface MockEventOptions {
  type: string;
  timestamp?: Date;
  proposal_id?: string;
  agent?: string;
  reversibility_class?: string;
  cleanup_cost?: string;
  execution_mode?: string;
  blocking_reason?: string;
}

function createRawEvent(options: MockEventOptions): RawGovernanceEvent {
  return {
    type: options.type,
    timestamp: (options.timestamp || new Date()).toISOString(),
    proposal_id: options.proposal_id,
    agent: options.agent,
    reversibility_class: options.reversibility_class,
    cleanup_cost: options.cleanup_cost,
    execution_mode: options.execution_mode,
    blocking_reason: options.blocking_reason,
  };
}

interface MockBudgetOptions {
  max_steps?: number;
  steps_used?: number;
  max_tool_calls?: number;
  tool_calls_used?: number;
  max_runtime_seconds?: number;
  runtime_used_seconds?: number;
  retries_remaining?: number | null;
  budget_multiplier?: number;
}

function createRawBudget(options: MockBudgetOptions = {}): RawBudgetState {
  return {
    max_steps: options.max_steps ?? 100,
    steps_used: options.steps_used ?? 0,
    max_tool_calls: options.max_tool_calls ?? 50,
    tool_calls_used: options.tool_calls_used ?? 0,
    max_runtime_seconds: options.max_runtime_seconds ?? 300,
    runtime_used_seconds: options.runtime_used_seconds ?? 0,
    retries_remaining: options.retries_remaining ?? 5,
    budget_multiplier: options.budget_multiplier ?? 1.0,
  };
}

interface MockGateOptions {
  reversibility?: string;
  mode_contract?: string;
  human_approval?: string;
  overall?: string;
}

function createRawGate(options: MockGateOptions = {}): RawGateState {
  return {
    reversibility: options.reversibility ?? "allowed",
    mode_contract: options.mode_contract ?? "allowed",
    human_approval: options.human_approval ?? "allowed",
    overall: options.overall ?? "allowed",
  };
}

// ---- Mock Scenario Builders ----

interface MockGovernanceOptions {
  proposal_id?: string;
  job_id?: string;
  agent?: string;
  principal_id?: string;
  blocked?: boolean;
  blocking_reason?: string;
  reversibility_class?: string;
  cleanup_cost?: string;
  execution_mode?: string;
  human_approved?: boolean;
  budget?: MockBudgetOptions;
  gate?: MockGateOptions;
  events?: MockEventOptions[];
}

/**
 * Create a raw governance response for normalization.
 * This does NOT bypass normalization - use createMockGovernanceState() instead.
 */
export function createRawGovernanceResponse(
  options: MockGovernanceOptions = {}
): RawGovernanceResponse {
  const proposalId = options.proposal_id || `mock-${Date.now()}`;

  return {
    proposal_id: proposalId,
    job_id: options.job_id,
    agent: options.agent || "MockAgent",
    principal_id: options.principal_id || "mock-principal",
    blocked: options.blocked ?? false,
    blocking_reason: options.blocking_reason,
    reversibility_class: options.reversibility_class || "REVERSIBLE",
    cleanup_cost: options.cleanup_cost || "LOW",
    execution_mode: options.execution_mode || "commit",
    human_approved: options.human_approved ?? false,
    budget_state: createRawBudget(options.budget),
    gate_state: createRawGate(options.gate),
    events: options.events?.map(createRawEvent) || [],
  };
}

/**
 * Create a normalized mock governance state.
 * ALWAYS flows through normalizeIncomingGovernance().
 */
export function createMockGovernanceState(
  options: MockGovernanceOptions = {}
): GovernanceState {
  const raw = createRawGovernanceResponse(options);
  const normalized = normalizeIncomingGovernance(raw);

  if (!normalized) {
    throw new Error(
      "[mock] Failed to normalize mock governance state - this should never happen"
    );
  }

  // Mark as mock source
  normalized._normalization.source = "mock";

  return normalized;
}

// ---- Scenario Presets ----

/**
 * Create a mock "allowed" governance state.
 */
export function createAllowedState(
  overrides: Partial<MockGovernanceOptions> = {}
): GovernanceState {
  return createMockGovernanceState({
    blocked: false,
    reversibility_class: "REVERSIBLE",
    cleanup_cost: "LOW",
    gate: { overall: "allowed" },
    events: [
      {
        type: "reversibility_gate.allowed",
        proposal_id: overrides.proposal_id,
        agent: overrides.agent || "Casey",
      },
    ],
    ...overrides,
  });
}

/**
 * Create a mock "blocked by reversibility" state.
 */
export function createBlockedReversibilityState(
  overrides: Partial<MockGovernanceOptions> = {}
): GovernanceState {
  return createMockGovernanceState({
    blocked: true,
    blocking_reason: "REVERSIBILITY",
    reversibility_class: "IRREVERSIBLE",
    gate: {
      reversibility: "blocked",
      overall: "blocked",
    },
    events: [
      {
        type: "reversibility_gate.blocked",
        proposal_id: overrides.proposal_id,
        agent: overrides.agent || "Casey",
        blocking_reason: "REVERSIBILITY",
      },
    ],
    ...overrides,
  });
}

/**
 * Create a mock "blocked by mode contract" state.
 */
export function createBlockedModeState(
  overrides: Partial<MockGovernanceOptions> = {}
): GovernanceState {
  return createMockGovernanceState({
    blocked: true,
    blocking_reason: "MODE_CONTRACT",
    execution_mode: "draft",
    gate: {
      mode_contract: "blocked",
      overall: "blocked",
    },
    events: [
      {
        type: "mode_contract.blocked",
        proposal_id: overrides.proposal_id,
        agent: overrides.agent || "Casey",
        execution_mode: "draft",
        blocking_reason: "MODE_CONTRACT",
      },
    ],
    ...overrides,
  });
}

/**
 * Create a mock "blocked by step budget" state.
 */
export function createBlockedBudgetState(
  overrides: Partial<MockGovernanceOptions> = {}
): GovernanceState {
  return createMockGovernanceState({
    blocked: true,
    blocking_reason: "STEP_BUDGET",
    budget: {
      max_steps: 100,
      steps_used: 100, // Exhausted
    },
    events: [
      {
        type: "budget.exceeded",
        proposal_id: overrides.proposal_id,
        agent: overrides.agent || "Casey",
        blocking_reason: "STEP_BUDGET",
      },
    ],
    ...overrides,
  });
}

/**
 * Create a mock "blocked by retry budget" state.
 */
export function createBlockedRetryState(
  overrides: Partial<MockGovernanceOptions> = {}
): GovernanceState {
  return createMockGovernanceState({
    blocked: true,
    blocking_reason: "RETRY_BUDGET",
    cleanup_cost: "HIGH",
    budget: {
      retries_remaining: 0, // Exhausted
    },
    events: [
      {
        type: "budget.exceeded",
        proposal_id: overrides.proposal_id,
        agent: overrides.agent || "Casey",
        blocking_reason: "RETRY_BUDGET",
      },
    ],
    ...overrides,
  });
}

/**
 * Create a mock "requires human approval" state.
 */
export function createRequiresApprovalState(
  overrides: Partial<MockGovernanceOptions> = {}
): GovernanceState {
  return createMockGovernanceState({
    blocked: true,
    blocking_reason: "HUMAN_APPROVAL_REQUIRED",
    reversibility_class: "IRREVERSIBLE",
    human_approved: false,
    gate: {
      human_approval: "escalated",
      overall: "escalated",
    },
    events: [
      {
        type: "proposal.needs_approval",
        proposal_id: overrides.proposal_id,
        agent: overrides.agent || "Casey",
      },
    ],
    ...overrides,
  });
}

// ---- Batch Mock Generation ----

/**
 * Generate a batch of mock governance states for testing/demo.
 * All states flow through normalization.
 */
export function generateMockDataset(count: number = 100): GovernanceState[] {
  const states: GovernanceState[] = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const timestamp = new Date(now - i * 60 * 60 * 1000); // 1 hour apart
    const proposalId = `mock-proposal-${i}`;

    // Vary the scenarios
    const scenario = i % 10;
    let state: GovernanceState;

    switch (scenario) {
      case 0:
        state = createBlockedReversibilityState({ proposal_id: proposalId });
        break;
      case 1:
        state = createBlockedModeState({ proposal_id: proposalId });
        break;
      case 2:
        state = createBlockedBudgetState({ proposal_id: proposalId });
        break;
      case 3:
        state = createBlockedRetryState({ proposal_id: proposalId });
        break;
      case 4:
        state = createRequiresApprovalState({ proposal_id: proposalId });
        break;
      default:
        // 50% allowed
        state = createAllowedState({
          proposal_id: proposalId,
          cleanup_cost: i % 3 === 0 ? "HIGH" : i % 3 === 1 ? "MEDIUM" : "LOW",
        });
    }

    // Backdate the normalization timestamp
    state._normalization.normalized_at = timestamp;

    states.push(state);
  }

  return states;
}
