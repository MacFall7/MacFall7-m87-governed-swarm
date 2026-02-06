/**
 * Governance Observability Module
 *
 * Single entry point for governance normalization, analytics, and persistence.
 * All governance data MUST flow through normalizeIncomingGovernance().
 */

// Types
export * from "./types";

// Normalization (the ONLY entry point for governance data)
export {
  normalizeIncomingGovernance,
  normalizeGovernanceState,
  reconcileGovernanceState,
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
} from "./normalize";

// Persistence
export {
  serializeGovernanceState,
  serializeToJson,
  deserializeGovernanceState,
  storeGovernanceState,
  loadGovernanceState,
  removeGovernanceState,
  storeGovernanceStates,
  loadGovernanceStatesByPrefix,
  clearInMemoryStore,
} from "./persistence";

// Analytics
export {
  computeBlockRate,
  computeTopBlockingReasons,
  computeCleanupCostDistribution,
  computeModeViolations,
  computeIrreversibleActions,
  computeBudgetUsage,
  computeDashboardMetrics,
  computeBlockRateTimeSeries,
} from "./analytics";
export type {
  TimeWindow,
  BlockRateMetrics,
  BlockingReasonCount,
  TopBlockingReasons,
  CleanupCostCount,
  CleanupCostDistribution,
  ModeViolation,
  ModeViolationMetrics,
  IrreversibleActionMetrics,
  BudgetUsageMetrics,
  GovernanceDashboardMetrics,
  TimeSeriesPoint,
  BlockRateTimeSeries,
} from "./analytics";

// Mock Data (all mocks flow through normalization)
export {
  createRawGovernanceResponse,
  createMockGovernanceState,
  createAllowedState,
  createBlockedReversibilityState,
  createBlockedModeState,
  createBlockedBudgetState,
  createBlockedRetryState,
  createRequiresApprovalState,
  generateMockDataset,
} from "./mock";

// Data Access Layer (mandatory normalization boundary)
export {
  configureGovernanceAPI,
  fetchGovernanceState,
  fetchGovernanceStateWithCache,
  fetchGovernanceStates,
  fetchRecentGovernanceDecisions,
  subscribeToGovernance,
  notifyGovernanceUpdate,
  loadCachedGovernanceStates,
  loadCachedGovernanceStatesByAgent,
  createGovernanceHookResult,
} from "./data";
export type {
  GovernanceAPIConfig,
  FetchResult,
  UseGovernanceResult,
  GovernanceUpdateCallback,
} from "./data";
