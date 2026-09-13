/// <reference types="vite/client" />

/**
 * Variables d'environnement du dashboard (build-time, préfixe `VITE_`).
 * Cf. `.env.example`.
 */
interface ImportMetaEnv {
  /** URL de base de l'API (défaut : `/api/v1`, via proxy). */
  readonly VITE_THOT_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
