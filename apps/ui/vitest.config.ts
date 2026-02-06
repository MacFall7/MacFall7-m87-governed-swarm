import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["lib/__tests__/**/*.test.ts"],
    coverage: {
      reporter: ["text", "json", "html"],
      include: ["lib/governance/**/*.ts"],
      exclude: ["lib/__tests__/**"],
    },
  },
});
