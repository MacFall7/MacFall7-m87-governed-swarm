export type EffectTag =
  | "READ_REPO"
  | "WRITE_PATCH"
  | "RUN_TESTS"
  | "BUILD_ARTIFACT"
  | "NETWORK_CALL"
  | "SEND_NOTIFICATION"
  | "CREATE_PR"
  | "MERGE"
  | "DEPLOY"
  | "READ_SECRETS";
