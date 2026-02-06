/**
 * Governance Data Access Layer
 *
 * The ONLY way to access governance data in the UI.
 * All data passes through normalizeIncomingGovernance() by construction.
 *
 * This layer makes normalization "inescapable" - no component can
 * accidentally bypass the reconciliation boundary.
 */

import type { GovernanceState, RawGovernanceResponse } from "./types";
import { normalizeIncomingGovernance } from "./normalize";
import {
  loadGovernanceState,
  storeGovernanceState,
  loadGovernanceStatesByPrefix,
} from "./persistence";

// ---- API Client Types ----

export interface GovernanceAPIConfig {
  baseUrl: string;
  apiKey?: string;
  headers?: Record<string, string>;
}

export interface FetchResult<T> {
  data: T | null;
  error: string | null;
  status: number;
}

// ---- Singleton Config ----

let _config: GovernanceAPIConfig = {
  baseUrl: "/api",
};

/**
 * Configure the governance data layer.
 * Call once at app initialization.
 */
export function configureGovernanceAPI(config: Partial<GovernanceAPIConfig>): void {
  _config = { ..._config, ...config };
}

// ---- Fetch Helpers ----

async function fetchJSON<T>(
  path: string,
  options?: RequestInit
): Promise<FetchResult<T>> {
  try {
    const url = `${_config.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ..._config.headers,
    };
    if (_config.apiKey) {
      headers["X-M87-Key"] = _config.apiKey;
    }

    const response = await fetch(url, {
      ...options,
      headers: { ...headers, ...options?.headers },
    });

    if (!response.ok) {
      return {
        data: null,
        error: `HTTP ${response.status}: ${response.statusText}`,
        status: response.status,
      };
    }

    const data = await response.json();
    return { data, error: null, status: response.status };
  } catch (err) {
    return {
      data: null,
      error: err instanceof Error ? err.message : "Unknown error",
      status: 0,
    };
  }
}

// ---- Governance Data Access ----

/**
 * Fetch governance state for a proposal.
 * ALWAYS returns normalized data or null.
 */
export async function fetchGovernanceState(
  proposalId: string
): Promise<GovernanceState | null> {
  const result = await fetchJSON<RawGovernanceResponse>(
    `/v1/governance/${proposalId}`
  );

  if (result.error || !result.data) {
    console.error(`[governance] Failed to fetch ${proposalId}:`, result.error);
    return null;
  }

  // MANDATORY: Normalize before returning
  const normalized = normalizeIncomingGovernance(result.data);
  if (!normalized) {
    console.error(`[governance] Failed to normalize ${proposalId}`);
    return null;
  }

  return normalized;
}

/**
 * Fetch governance state with caching.
 * Checks cache first, fetches if miss, stores result.
 */
export async function fetchGovernanceStateWithCache(
  proposalId: string,
  maxAgeMs: number = 30000
): Promise<GovernanceState | null> {
  // Check cache first
  const cached = loadGovernanceState(proposalId);
  if (cached) {
    const age = Date.now() - cached._normalization.normalized_at.getTime();
    if (age < maxAgeMs) {
      return cached; // Cache hit, still fresh
    }
  }

  // Cache miss or stale - fetch fresh
  const fresh = await fetchGovernanceState(proposalId);
  if (fresh) {
    storeGovernanceState(proposalId, fresh);
  }

  return fresh;
}

/**
 * Fetch multiple governance states.
 * All results are normalized.
 */
export async function fetchGovernanceStates(
  proposalIds: string[]
): Promise<Map<string, GovernanceState>> {
  const results = new Map<string, GovernanceState>();

  // Fetch in parallel
  const promises = proposalIds.map(async (id) => {
    const state = await fetchGovernanceState(id);
    if (state) {
      results.set(id, state);
    }
  });

  await Promise.all(promises);
  return results;
}

/**
 * Fetch recent governance decisions.
 * Returns normalized states sorted by time.
 */
export async function fetchRecentGovernanceDecisions(
  limit: number = 100
): Promise<GovernanceState[]> {
  const result = await fetchJSON<{ decisions: RawGovernanceResponse[] }>(
    `/v1/governance/recent?limit=${limit}`
  );

  if (result.error || !result.data?.decisions) {
    console.error("[governance] Failed to fetch recent decisions:", result.error);
    return [];
  }

  // MANDATORY: Normalize each decision
  const normalized: GovernanceState[] = [];
  for (const raw of result.data.decisions) {
    const state = normalizeIncomingGovernance(raw);
    if (state) {
      normalized.push(state);
    }
  }

  return normalized;
}

// ---- Subscription / Real-time ----

export type GovernanceUpdateCallback = (state: GovernanceState) => void;

const _subscribers = new Map<string, Set<GovernanceUpdateCallback>>();

/**
 * Subscribe to governance updates for a proposal.
 * Returns unsubscribe function.
 */
export function subscribeToGovernance(
  proposalId: string,
  callback: GovernanceUpdateCallback
): () => void {
  if (!_subscribers.has(proposalId)) {
    _subscribers.set(proposalId, new Set());
  }
  _subscribers.get(proposalId)!.add(callback);

  return () => {
    _subscribers.get(proposalId)?.delete(callback);
  };
}

/**
 * Notify subscribers of a governance update.
 * MUST pass through normalization before notifying.
 */
export function notifyGovernanceUpdate(
  proposalId: string,
  rawData: unknown
): void {
  const normalized = normalizeIncomingGovernance(rawData);
  if (!normalized) {
    console.error(`[governance] Failed to normalize update for ${proposalId}`);
    return;
  }

  const callbacks = _subscribers.get(proposalId);
  if (callbacks) {
    for (const cb of callbacks) {
      try {
        cb(normalized);
      } catch (err) {
        console.error(`[governance] Subscriber error for ${proposalId}:`, err);
      }
    }
  }
}

// ---- Batch Loading from Cache ----

/**
 * Load all cached governance states.
 * All results are re-normalized (reconciled) on load.
 */
export function loadCachedGovernanceStates(): Map<string, GovernanceState> {
  return loadGovernanceStatesByPrefix("");
}

/**
 * Load cached governance states by agent.
 */
export function loadCachedGovernanceStatesByAgent(
  agent: string
): GovernanceState[] {
  const all = loadCachedGovernanceStates();
  return Array.from(all.values()).filter((s) => s.agent === agent);
}

// ---- Data Hook Interface ----

/**
 * Interface for React/framework hooks.
 * Provides a consistent shape for governance data access.
 */
export interface UseGovernanceResult {
  state: GovernanceState | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

/**
 * Create a governance data hook result.
 * This is framework-agnostic - wrap with useState/useEffect in React.
 */
export function createGovernanceHookResult(
  proposalId: string
): {
  getInitialState: () => UseGovernanceResult;
  fetch: () => Promise<UseGovernanceResult>;
} {
  return {
    getInitialState: () => ({
      state: loadGovernanceState(proposalId) || null,
      loading: true,
      error: null,
      refetch: async () => {},
    }),
    fetch: async () => {
      const state = await fetchGovernanceState(proposalId);
      return {
        state,
        loading: false,
        error: state ? null : "Failed to fetch governance state",
        refetch: async () => {},
      };
    },
  };
}
