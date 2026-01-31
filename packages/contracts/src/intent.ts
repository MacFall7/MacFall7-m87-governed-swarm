export type IntentMode = "plan" | "build" | "fix" | "report" | "ship";

export interface Intent {
  intent_id: string;        // uuid
  from: "mac" | string;
  mode: IntentMode;
  goal: string;
  constraints?: {
    no_deploy?: boolean;
    scope_paths?: string[];
    max_risk?: number;      // 0..1
  };
}
