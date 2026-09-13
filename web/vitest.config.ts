import { fileURLToPath, URL } from 'node:url';

import { defineConfig } from 'vitest/config';

/**
 * Les tests couvrent le client HTTP et le client WebSocket en environnement
 * Node (aucun DOM requis) : `fetch` et `WebSocket` sont injectés/mockés.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    globals: false,
    restoreMocks: true,
    clearMocks: true,
    reporters: ['default'],
  },
});
