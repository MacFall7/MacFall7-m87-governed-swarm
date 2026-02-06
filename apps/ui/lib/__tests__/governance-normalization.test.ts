/**
 * Governance Normalization Regression Tests
 *
 * These tests prove the normalization boundary cannot regress.
 * If a governance panel ever shows "allowed" while blocked=true signals exist,
 * these tests must fail.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  normalizeIncomingGovernance,
  normalizeGovernanceState,
  serializeGovernanceState,
  deserializeGovernanceState,
  createMockGovernanceState,
  createAllowedState,
  createBlockedReversibilityState,
  generateMockDataset,
  clearInMemoryStore,
} from "../governance";
import type {
  RawGovernanceResponse,
  GovernanceState,
} from "../governance/types";

describe("Governance Normalization Boundary", () => {
  beforeEach(() => {
    clearInMemoryStore();
  });

  // ----------------------------------------------------------------
  // TEST 1: Round-trip preserves nested event timestamps as Date
  // ----------------------------------------------------------------
  describe("timestamp preservation", () => {
    it("round-trip preserves nested event timestamps as Date objects", () => {
      const original = createAllowedState({
        proposal_id: "test-timestamp",
        events: [
          {
            type: "reversibility_gate.allowed",
            timestamp: new Date("2026-02-06T12:00:00Z"),
          },
        ],
      });

      // Serialize
      const serialized = serializeGovernanceState(original);

      // Verify serialized timestamps are strings
      expect(typeof serialized._normalization).toBe("object");
      const normalization = serialized._normalization as Record<string, unknown>;
      expect(typeof normalization.normalized_at).toBe("string");

      const events = serialized.events as Array<Record<string, unknown>>;
      expect(typeof events[0].timestamp).toBe("string");

      // Deserialize
      const restored = deserializeGovernanceState(serialized);

      // Verify restored timestamps are Date objects
      expect(restored).toBeDefined();
      expect(restored!._normalization.normalized_at).toBeInstanceOf(Date);
      expect(restored!.events[0].timestamp).toBeInstanceOf(Date);

      // Verify timestamp values preserved
      expect(restored!.events[0].timestamp.toISOString()).toBe(
        "2026-02-06T12:00:00.000Z"
      );
    });

    it("handles missing timestamp gracefully", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-missing-ts",
        events: [
          {
            type: "proposal.allowed",
            // timestamp intentionally missing
          },
        ],
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.events[0].timestamp).toBeInstanceOf(Date);
      // Should default to current time (not throw)
      expect(normalized!.events[0].timestamp.getTime()).toBeLessThanOrEqual(
        Date.now()
      );
    });
  });

  // ----------------------------------------------------------------
  // TEST 2: fail-closed when ANY blocking signal exists
  // ----------------------------------------------------------------
  describe("fail-closed blocking signals", () => {
    it("blocks when blocking_reason is present", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-blocking-reason",
        blocked: false, // Raw says allowed...
        blocking_reason: "MODE_CONTRACT", // ...but blocking signal exists
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(true); // Fail-closed!
      expect(normalized!._normalization.fail_closed_triggered).toBe(true);
    });

    it("blocks when gate_decision is blocked", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-gate-blocked",
        blocked: false,
        gate_state: {
          overall: "blocked",
          reversibility: "blocked",
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(true);
      expect(normalized!.blocking_reason).toBe("REVERSIBILITY");
    });

    it("blocks when retries_remaining <= 0", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-retries-zero",
        blocked: false,
        budget_state: {
          retries_remaining: 0,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(true);
      expect(normalized!.blocking_reason).toBe("RETRY_BUDGET");
    });

    it("blocks when max_steps === 0", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-max-steps-zero",
        blocked: false,
        budget_state: {
          max_steps: 0,
          steps_used: 0,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(true);
      expect(normalized!.blocking_reason).toBe("STEP_BUDGET");
      expect(normalized!.budget_state.percentage_used).toBe(100); // 0/0 = 100%
    });

    it("blocks when steps_used >= max_steps", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-steps-exceeded",
        blocked: false,
        budget_state: {
          max_steps: 100,
          steps_used: 100,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(true);
      expect(normalized!.blocking_reason).toBe("STEP_BUDGET");
    });

    it("blocks when tool_calls exhausted", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-tools-exceeded",
        blocked: false,
        budget_state: {
          max_steps: 100, // Explicitly set to avoid STEP_BUDGET trigger
          steps_used: 0,
          max_tool_calls: 50,
          tool_calls_used: 50,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(true);
      expect(normalized!.blocking_reason).toBe("TOOL_BUDGET");
    });
  });

  // ----------------------------------------------------------------
  // TEST 3: Unknown enums are defaulted conservatively
  // ----------------------------------------------------------------
  describe("unknown enum handling", () => {
    it("unknown reversibility_class defaults to UNKNOWN and is recorded", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-unknown-rev",
        reversibility_class: "COMPLETELY_MADE_UP",
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.reversibility_class).toBe("UNKNOWN");
      expect(normalized!._normalization.unknown_fields).toContain(
        "reversibility_class:COMPLETELY_MADE_UP"
      );
    });

    it("unknown cleanup_cost defaults to UNKNOWN and is recorded", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-unknown-cost",
        cleanup_cost: "SUPER_CHEAP",
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.cleanup_cost).toBe("UNKNOWN");
      expect(normalized!._normalization.unknown_fields).toContain(
        "cleanup_cost:SUPER_CHEAP"
      );
    });

    it("unknown execution_mode defaults to unknown and is recorded", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-unknown-mode",
        execution_mode: "turbo",
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.execution_mode).toBe("unknown");
      expect(normalized!._normalization.unknown_fields).toContain(
        "execution_mode:turbo"
      );
    });

    it("unknown event type defaults to unknown.event and is recorded", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-unknown-event",
        events: [
          {
            type: "custom.weird.event",
            timestamp: new Date().toISOString(),
          },
        ],
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.events[0].type).toBe("unknown.event");
      expect(normalized!._normalization.unknown_fields).toContain(
        "event_type:custom.weird.event"
      );
    });

    it("unknown gate decision defaults to unknown and is recorded", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-unknown-gate",
        gate_state: {
          overall: "maybe",
          reversibility: "pending",
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.gate_state.overall).toBe("unknown");
      expect(normalized!.gate_state.reversibility).toBe("unknown");
      expect(normalized!._normalization.unknown_fields).toContain(
        "gate.overall:maybe"
      );
    });
  });

  // ----------------------------------------------------------------
  // TEST 4: max_steps=0 always results in blocked=true
  // ----------------------------------------------------------------
  describe("max_steps=0 invariant", () => {
    it("max_steps=0 always blocks regardless of other fields", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-zero-budget",
        blocked: false,
        gate_state: {
          overall: "allowed",
          reversibility: "allowed",
          mode_contract: "allowed",
          human_approval: "allowed",
        },
        reversibility_class: "REVERSIBLE",
        cleanup_cost: "LOW",
        budget_state: {
          max_steps: 0, // Zero budget
          steps_used: 0,
          retries_remaining: 5,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(true);
      expect(normalized!.blocking_reason).toBe("STEP_BUDGET");
      expect(normalized!._normalization.fail_closed_triggered).toBe(true);
    });

    it("max_steps=0 sets percentage_used to 100", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-zero-pct",
        budget_state: {
          max_steps: 0,
          steps_used: 0,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.budget_state.percentage_used).toBe(100);
    });

    it("missing budget_state does not trigger false positive blocks", () => {
      // Read-only actions may not have budget_state at all
      const raw: RawGovernanceResponse = {
        proposal_id: "test-no-budget",
        blocked: false,
        gate_state: {
          overall: "allowed",
        },
        // budget_state intentionally missing
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized).toBeDefined();
      expect(normalized!.blocked).toBe(false); // Should NOT trigger false positive
      expect(normalized!.blocking_reason).toBeUndefined();
    });
  });

  // ----------------------------------------------------------------
  // TEST 5: Mock data flows through normalization
  // ----------------------------------------------------------------
  describe("mock data normalization", () => {
    it("createMockGovernanceState flows through normalizeIncomingGovernance", () => {
      const mock = createMockGovernanceState({
        proposal_id: "test-mock",
      });

      expect(mock._normalization.source).toBe("mock");
      expect(mock._normalization.normalized_at).toBeInstanceOf(Date);
    });

    it("all mock scenario presets are properly normalized", () => {
      const allowed = createAllowedState();
      const blockedRev = createBlockedReversibilityState();

      expect(allowed.blocked).toBe(false);
      expect(allowed._normalization.source).toBe("mock");

      expect(blockedRev.blocked).toBe(true);
      expect(blockedRev.blocking_reason).toBe("REVERSIBILITY");
    });

    it("generateMockDataset produces all normalized states", () => {
      const dataset = generateMockDataset(20);

      expect(dataset.length).toBe(20);

      for (const state of dataset) {
        expect(state._normalization).toBeDefined();
        expect(state._normalization.normalized_at).toBeInstanceOf(Date);
        expect(state._normalization.source).toBe("mock");
      }
    });
  });

  // ----------------------------------------------------------------
  // TEST 6: Reconciliation re-applies fail-closed
  // ----------------------------------------------------------------
  describe("reconciliation", () => {
    it("reconciliation re-applies fail-closed when signals exist", () => {
      // Create a state that looks allowed but has blocking signals
      const tamperedState: GovernanceState = {
        proposal_id: "tampered",
        agent: "Attacker",
        principal_id: "attacker-1",
        blocked: false, // Tampered to show allowed
        gate_state: {
          reversibility: "allowed",
          mode_contract: "allowed",
          human_approval: "allowed",
          overall: "allowed",
        },
        budget_state: {
          max_steps: 0, // But budget says blocked!
          steps_used: 0,
          percentage_used: 0, // Wrong math
          max_tool_calls: 0,
          tool_calls_used: 0,
          max_runtime_seconds: 0,
          runtime_used_seconds: 0,
          retries_remaining: null,
          budget_multiplier: 1.0,
        },
        reversibility_class: "REVERSIBLE",
        cleanup_cost: "LOW",
        execution_mode: "commit",
        human_approved: false,
        events: [],
        _normalization: {
          normalized_at: new Date(),
          source: "raw",
          unknown_fields: [],
          raw_values: {},
          reconciliation_applied: false,
          fail_closed_triggered: false,
        },
      };

      // Re-normalize (reconcile)
      const reconciled = normalizeIncomingGovernance(tamperedState);

      expect(reconciled).toBeDefined();
      expect(reconciled!.blocked).toBe(true); // Fail-closed wins
      expect(reconciled!._normalization.reconciliation_applied).toBe(true);
    });
  });

  // ----------------------------------------------------------------
  // TEST 7: Falsy input returns undefined
  // ----------------------------------------------------------------
  describe("edge cases", () => {
    it("returns undefined for null input", () => {
      expect(normalizeIncomingGovernance(null)).toBeUndefined();
    });

    it("returns undefined for undefined input", () => {
      expect(normalizeIncomingGovernance(undefined)).toBeUndefined();
    });

    it("returns undefined for non-object input", () => {
      expect(normalizeIncomingGovernance("string")).toBeUndefined();
      expect(normalizeIncomingGovernance(123)).toBeUndefined();
    });

    it("handles empty object gracefully", () => {
      const normalized = normalizeIncomingGovernance({});

      expect(normalized).toBeDefined();
      expect(normalized!.proposal_id).toBe("unknown");
      expect(normalized!.agent).toBe("unknown");
    });
  });

  // ----------------------------------------------------------------
  // TEST 8: percentage_used math is correct
  // ----------------------------------------------------------------
  describe("budget math", () => {
    it("percentage_used = (steps_used / max_steps) * 100", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-math",
        budget_state: {
          max_steps: 100,
          steps_used: 25,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized!.budget_state.percentage_used).toBe(25);
    });

    it("percentage_used handles fractional values", () => {
      const raw: RawGovernanceResponse = {
        proposal_id: "test-math-frac",
        budget_state: {
          max_steps: 3,
          steps_used: 1,
        },
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized!.budget_state.percentage_used).toBeCloseTo(33.33, 1);
    });
  });
});

describe("Governance Style Compliance", () => {
  // ----------------------------------------------------------------
  // META-TEST: Ensure governance cannot lie in the UI
  // ----------------------------------------------------------------
  it("governance panel cannot show allowed while blocking signals exist", () => {
    // This is the ultimate invariant: if ANY blocking signal exists,
    // the normalized state MUST have blocked=true

    const scenarios = [
      { blocking_reason: "REVERSIBILITY" },
      { gate_state: { overall: "blocked" } },
      { budget_state: { retries_remaining: 0 } },
      { budget_state: { max_steps: 0 } },
      { budget_state: { max_steps: 100, steps_used: 100 } },
      { budget_state: { max_tool_calls: 50, tool_calls_used: 50 } },
    ];

    for (const scenario of scenarios) {
      const raw: RawGovernanceResponse = {
        proposal_id: "invariant-test",
        blocked: false, // Explicitly says allowed
        ...scenario,
      };

      const normalized = normalizeIncomingGovernance(raw);

      expect(normalized!.blocked).toBe(true);
    }
  });
});
