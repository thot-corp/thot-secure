import { defineConfig } from "vitest/config";

/**
 * Configuration Vitest du SDK Thot Secure.
 *
 * Les tests s'exécutent dans Node, **sans réseau** : `fetch` et la fabrique WebSocket sont
 * injectés (mocks) dans chaque test.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    reporters: ["default"],
    testTimeout: 10_000,
  },
});
