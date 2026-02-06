/**
 * Governance Style Compliance Test
 *
 * Ensures governance UI components use semantic tokens, not hardcoded colors.
 * This is a fail-closed test: missing files are errors unless explicitly allowed.
 */

import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// Allow missing files during initial scaffolding
const ALLOW_MISSING = process.env.ALLOW_MISSING_GOV_FILES === "1";

// Get the directory where this test file lives
const TEST_DIR = path.dirname(new URL(import.meta.url).pathname);

// Files that must use semantic tokens (relative to test directory)
const GOVERNANCE_FILES = [
  "../governance/types.ts",
  "../governance/normalize.ts",
  "../governance/analytics.ts",
  "../governance/persistence.ts",
  "../governance/mock.ts",
  "../governance/index.ts",
];

// Forbidden patterns - hardcoded Tailwind color utilities
const FORBIDDEN_PATTERNS = [
  // Basic color utilities with any shade
  /\b(bg|text|border|ring|outline|shadow|divide|from|to|via)-(red|blue|green|yellow|purple|pink|indigo|gray|slate|zinc|neutral|stone|amber|lime|emerald|teal|cyan|sky|violet|fuchsia|rose)-\d{2,3}(\/\d{1,3})?\b/g,

  // Gradient utilities
  /\bfrom-(red|blue|green|yellow|purple|pink|indigo|gray)-\d{2,3}\b/g,
  /\bto-(red|blue|green|yellow|purple|pink|indigo|gray)-\d{2,3}\b/g,
  /\bvia-(red|blue|green|yellow|purple|pink|indigo|gray)-\d{2,3}\b/g,

  // Ring/outline with colors
  /\bring-(red|blue|green|yellow|purple|pink|indigo)-\d{2,3}\b/g,
  /\boutline-(red|blue|green|yellow|purple|pink|indigo)-\d{2,3}\b/g,
];

// Allowed semantic tokens for governance
const ALLOWED_TOKENS = [
  "risk-low",
  "risk-medium",
  "risk-high",
  "risk-critical",
  "risk-info",
  "risk-purple",
  "foreground",
  "background",
  "muted",
  "border",
  "primary",
  "secondary",
  "destructive",
  "accent",
];

describe("Governance Style Compliance", () => {
  GOVERNANCE_FILES.forEach((filePath) => {
    it(`${filePath} uses semantic tokens, not hardcoded colors`, () => {
      const fullPath = path.resolve(TEST_DIR, filePath);

      // Fail-closed: missing files are errors unless explicitly allowed
      if (!fs.existsSync(fullPath)) {
        if (ALLOW_MISSING) {
          console.warn(`[ALLOW_MISSING] Skipping ${filePath} - file not found`);
          return;
        }
        throw new Error(
          `Governance style compliance: missing file ${filePath}\n` +
            `  Either create the file or set ALLOW_MISSING_GOV_FILES=1 during scaffolding.`
        );
      }

      const content = fs.readFileSync(fullPath, "utf-8");
      const violations: string[] = [];

      FORBIDDEN_PATTERNS.forEach((pattern) => {
        // Reset regex lastIndex for global patterns
        pattern.lastIndex = 0;
        const matches = content.match(pattern);
        if (matches) {
          violations.push(...matches);
        }
      });

      if (violations.length > 0) {
        const uniqueViolations = [...new Set(violations)];
        throw new Error(
          `Found ${violations.length} hardcoded color utilities in ${filePath}:\n` +
            `  Violations: ${uniqueViolations.join(", ")}\n` +
            `  Use semantic tokens instead: ${ALLOWED_TOKENS.slice(0, 6).join(", ")}, etc.`
        );
      }

      expect(violations).toHaveLength(0);
    });
  });

  it("should have forbidden patterns defined and valid", () => {
    // Meta-test to ensure our patterns are valid regex
    expect(FORBIDDEN_PATTERNS.length).toBeGreaterThan(0);
    FORBIDDEN_PATTERNS.forEach((pattern) => {
      expect(pattern).toBeInstanceOf(RegExp);
      // Verify patterns are global for proper matching
      expect(pattern.flags).toContain("g");
    });
  });

  it("should catch common violation patterns", () => {
    // Sanity check: ensure patterns catch expected violations
    const testCases = [
      { input: "bg-blue-500", shouldMatch: true },
      { input: "text-purple-300/50", shouldMatch: true },
      { input: "border-red-600", shouldMatch: true },
      { input: "from-indigo-500", shouldMatch: true },
      { input: "ring-green-400", shouldMatch: true },
      { input: "bg-risk-critical", shouldMatch: false },
      { input: "text-foreground", shouldMatch: false },
      { input: "border-border", shouldMatch: false },
    ];

    testCases.forEach(({ input, shouldMatch }) => {
      const matches = FORBIDDEN_PATTERNS.some((pattern) => {
        pattern.lastIndex = 0;
        return pattern.test(input);
      });
      expect(matches).toBe(shouldMatch);
    });
  });
});

// ---- Optional Broader UI Compliance ----
// Enable with ENFORCE_UI_TOKEN_COMPLIANCE=1

const ENFORCE_BROAD_COMPLIANCE = process.env.ENFORCE_UI_TOKEN_COMPLIANCE === "1";

describe.skipIf(!ENFORCE_BROAD_COMPLIANCE)("Broad UI Style Compliance", () => {
  const UI_SRC_PATTERNS = [
    "../**/*.tsx",
    "../**/*.jsx",
    "../**/*.css",
  ];

  it("should enforce semantic tokens across all UI source files", () => {
    const glob = require("glob");

    UI_SRC_PATTERNS.forEach((pattern) => {
      const fullPattern = path.resolve(TEST_DIR, pattern);
      const files = glob.sync(fullPattern, { nodir: true });

      files.forEach((filePath: string) => {
        // Skip test files and node_modules
        if (filePath.includes("__tests__") || filePath.includes("node_modules")) {
          return;
        }

        const content = fs.readFileSync(filePath, "utf-8");
        const violations: string[] = [];

        FORBIDDEN_PATTERNS.forEach((p) => {
          p.lastIndex = 0;
          const matches = content.match(p);
          if (matches) {
            violations.push(...matches);
          }
        });

        if (violations.length > 0) {
          const uniqueViolations = [...new Set(violations)];
          throw new Error(
            `Found ${violations.length} hardcoded color utilities in ${filePath}:\n` +
              `  Violations: ${uniqueViolations.slice(0, 5).join(", ")}${uniqueViolations.length > 5 ? "..." : ""}\n` +
              `  Use semantic tokens instead.`
          );
        }
      });
    });

    expect(true).toBe(true); // If we get here, all files passed
  });
});
