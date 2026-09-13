/**
 * Point d'entrée du dashboard Thot Secure (React 18 + TypeScript + Vite).
 *
 * Ordre des fournisseurs — il est significatif :
 *   1. `QueryClientProvider` : `AuthProvider` purge le cache de TanStack Query
 *      au changement de clé API (aucune donnée d'un tenant ne doit survivre à
 *      une autre clé) et utilise donc `useQueryClient()`.
 *   2. `BrowserRouter` : les écrans décident de la navigation (redirection vers
 *      l'écran de connexion, deep-links `?focus=<finding_id>`).
 *   3. `AuthProvider` : interroge `GET /api/v1/auth/whoami`, seule source de
 *      vérité du rôle, des capacités, du mode d'autonomie et du périmètre
 *      `tenant_id` (fail-closed tant que la réponse n'est pas arrivée).
 *   4. `ErrorBoundary` : une erreur de rendu ne doit jamais blanchir la console
 *      ni masquer le bandeau `dry_run` / mode d'autonomie.
 *
 * Note : `index.css` importe les directives Tailwind et le thème « SOC ».
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import App from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import { shouldRetry } from './lib/api';
import { AuthProvider } from './lib/auth';
import './index.css';

/**
 * Cache partagé. Politique volontairement conservatrice :
 *  - `retry: shouldRetry` : jamais de réessai sur 4xx (401/403 inclus) ni sur
 *    annulation ; deux essais sur réseau/5xx.
 *  - `refetchOnWindowFocus: false` : un onglet d'astreinte ne doit pas relancer
 *    dix requêtes au retour de focus ; les pages exposent un bouton « Rafraîchir ».
 *  - `staleTime` court : les données SOC vieillissent vite, sans marteler l'API.
 */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: shouldRetry,
      retryDelay: (attempt) => Math.min(1_000 * 2 ** attempt, 8_000),
      refetchOnWindowFocus: false,
      staleTime: 15_000,
      gcTime: 5 * 60_000,
    },
    mutations: {
      retry: false,
    },
  },
});

const container = document.getElementById('root');

if (!container) {
  // Situation impossible avec `index.html` livré : on échoue bruyamment plutôt
  // que de laisser une page blanche silencieuse.
  throw new Error('Élément #root introuvable dans index.html.');
}

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ErrorBoundary>
            <App />
          </ErrorBoundary>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
