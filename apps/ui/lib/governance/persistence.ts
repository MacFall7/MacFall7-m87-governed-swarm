/**
 * Governance Persistence Helpers
 *
 * Ensures governance data is safely serialized/deserialized.
 * All reads MUST pass through normalizeIncomingGovernance().
 */

import type { GovernanceState, GovernanceEvent } from "./types";
import { normalizeIncomingGovernance } from "./normalize";

// ---- Serialization ----

/**
 * Deep-serialize a GovernanceEvent for storage/transport.
 * Converts Date objects to ISO strings.
 */
function serializeEvent(event: GovernanceEvent): Record<string, unknown> {
  return {
    ...event,
    timestamp: event.timestamp.toISOString(),
    timestamp_raw: event.timestamp_raw || event.timestamp.toISOString(),
  };
}

/**
 * Serialize a GovernanceState for storage/transport.
 *
 * - Converts event timestamps to ISO strings
 * - Converts _normalization.normalized_at to ISO string
 * - Preserves all other fields
 */
export function serializeGovernanceState(
  state: GovernanceState
): Record<string, unknown> {
  return {
    ...state,
    events: state.events.map(serializeEvent),
    _normalization: {
      ...state._normalization,
      normalized_at: state._normalization.normalized_at.toISOString(),
    },
  };
}

/**
 * Serialize to JSON string for storage.
 */
export function serializeToJson(state: GovernanceState): string {
  return JSON.stringify(serializeGovernanceState(state));
}

// ---- Deserialization ----

/**
 * Deserialize a GovernanceState from storage/transport.
 *
 * ALWAYS calls normalizeIncomingGovernance() to enforce fail-closed.
 * This prevents silent corruption from stale/malformed data.
 */
export function deserializeGovernanceState(
  data: unknown
): GovernanceState | undefined {
  // Parse if string
  let parsed = data;
  if (typeof data === "string") {
    try {
      parsed = JSON.parse(data);
    } catch {
      console.error("[governance] Failed to parse JSON:", data);
      return undefined;
    }
  }

  // ALWAYS normalize after deserialization
  return normalizeIncomingGovernance(parsed);
}

// ---- Storage Adapters ----

const STORAGE_KEY_PREFIX = "m87:governance:";

/**
 * Store governance state in localStorage (browser) or memory (Node).
 */
export function storeGovernanceState(
  key: string,
  state: GovernanceState
): void {
  const fullKey = STORAGE_KEY_PREFIX + key;
  const serialized = serializeToJson(state);

  if (typeof localStorage !== "undefined") {
    localStorage.setItem(fullKey, serialized);
  } else {
    // Node.js fallback - in-memory store
    inMemoryStore.set(fullKey, serialized);
  }
}

/**
 * Load governance state from storage.
 * ALWAYS returns normalized state or undefined.
 */
export function loadGovernanceState(key: string): GovernanceState | undefined {
  const fullKey = STORAGE_KEY_PREFIX + key;

  let raw: string | null = null;
  if (typeof localStorage !== "undefined") {
    raw = localStorage.getItem(fullKey);
  } else {
    raw = inMemoryStore.get(fullKey) || null;
  }

  if (!raw) return undefined;

  return deserializeGovernanceState(raw);
}

/**
 * Remove governance state from storage.
 */
export function removeGovernanceState(key: string): void {
  const fullKey = STORAGE_KEY_PREFIX + key;

  if (typeof localStorage !== "undefined") {
    localStorage.removeItem(fullKey);
  } else {
    inMemoryStore.delete(fullKey);
  }
}

// In-memory store for Node.js environments
const inMemoryStore = new Map<string, string>();

/**
 * Clear all governance state from in-memory store (for testing).
 */
export function clearInMemoryStore(): void {
  inMemoryStore.clear();
}

// ---- Batch Operations ----

/**
 * Store multiple governance states.
 */
export function storeGovernanceStates(
  states: Map<string, GovernanceState>
): void {
  for (const [key, state] of states) {
    storeGovernanceState(key, state);
  }
}

/**
 * Load all governance states matching a prefix.
 */
export function loadGovernanceStatesByPrefix(
  prefix: string
): Map<string, GovernanceState> {
  const result = new Map<string, GovernanceState>();
  const fullPrefix = STORAGE_KEY_PREFIX + prefix;

  if (typeof localStorage !== "undefined") {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(fullPrefix)) {
        const shortKey = key.slice(STORAGE_KEY_PREFIX.length);
        const state = loadGovernanceState(shortKey);
        if (state) {
          result.set(shortKey, state);
        }
      }
    }
  } else {
    for (const [key, value] of inMemoryStore) {
      if (key.startsWith(fullPrefix)) {
        const shortKey = key.slice(STORAGE_KEY_PREFIX.length);
        const state = deserializeGovernanceState(value);
        if (state) {
          result.set(shortKey, state);
        }
      }
    }
  }

  return result;
}
