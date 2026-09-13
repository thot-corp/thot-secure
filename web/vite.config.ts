import { fileURLToPath, URL } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig, type ProxyOptions } from 'vite';

/**
 * Cible de l'API Thot Secure en développement.
 * Le serveur (`thotsecure serve`) écoute par défaut sur 127.0.0.1:8080 (cf. contrat §9).
 */
const DEV_API_TARGET = 'http://127.0.0.1:8080';

/**
 * `/api/v1/ws` est déclaré explicitement (en plus de `/api`) pour documenter
 * l'intention et garantir `ws: true` sur le préfixe WebSocket, quel que soit
 * l'ordre de résolution des règles de proxy.
 */
function apiProxy(): Record<string, ProxyOptions> {
  return {
    '/api': { target: DEV_API_TARGET, changeOrigin: true, ws: true },
    '/api/v1/ws': { target: DEV_API_TARGET, changeOrigin: true, ws: true },
    // Endpoints hors préfixe `/api/v1` (contrat §4.1 et §4.9) : pratiques en dev.
    '/healthz': { target: DEV_API_TARGET, changeOrigin: true },
    '/readyz': { target: DEV_API_TARGET, changeOrigin: true },
    '/version': { target: DEV_API_TARGET, changeOrigin: true },
    '/openapi.json': { target: DEV_API_TARGET, changeOrigin: true },
  };
}

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: apiProxy(),
  },
  preview: {
    port: 4173,
    strictPort: true,
    proxy: apiProxy(),
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    target: 'es2022',
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
          query: ['@tanstack/react-query'],
        },
      },
    },
  },
});
