export type RunnerTool = "echo" | "pytest" | "git" | "build";

export interface JobSpec {
  job_id: string;
  proposal_id: string;
  tool: RunnerTool;
  inputs: Record<string, any>;
  sandbox: {
    network: "deny" | "allowlist";
    fs: "ro" | "rw";
  };
  timeout_seconds: number;
}
