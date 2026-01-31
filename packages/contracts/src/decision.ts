import type { EffectTag } from "./effects";

export type Decision = "ALLOW" | "DENY" | "REQUIRE_HUMAN" | "NEED_MORE_EVIDENCE";

export interface GovernanceDecision {
  proposal_id: string;
  decision: Decision;
  reasons: string[];
  required_approvals?: string[]; // e.g. ["mac"]
  allowed_effects?: EffectTag[];
}
