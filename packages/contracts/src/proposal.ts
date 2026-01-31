import type { EffectTag } from "./effects";

export interface TruthAccount {
  observations: string[];
  claims: Array<{ text: string; confidence: number }>;
}

export interface Proposal {
  proposal_id: string;      // uuid
  intent_id: string;        // uuid
  agent: string;            // e.g. "Planner", "CodeSurgeon"
  summary: string;
  effects: EffectTag[];
  artifacts?: Array<{ type: string; ref: string }>;
  truth_account: TruthAccount;
  risk_score?: number;      // 0..1
}
