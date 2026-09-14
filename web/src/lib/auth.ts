/**
 * Authentification et capacités côté client.
 *
 * Modèle :
 *  - la clé API (`ao_…`, contrat §4) est saisie par l'utilisateur et conservée
 *    dans `localStorage` (elle n'est jamais journalisée ni affichée en clair) ;
 *  - `GET /api/v1/auth/whoami` est la **seule** source de vérité pour le rôle,
 *    les capacités, le mode d'autonomie et le périmètre `tenant_id` ;
 *  - le client API est ensuite « épinglé » sur ce `tenant_id` : aucune requête
 *    ne peut viser un autre tenant, et aucune donnée d'un autre tenant ne peut
 *    être rendue (garde dans `lib/api.ts`).
 *
 * Fail-closed : tant que `whoami` n'a pas répondu, les capacités valent `[]`,
 * `dry_run` vaut `true` et le mode vaut `manual`.
 *
 * Note de forme : ce fichier est en `.ts` (et non `.tsx`) conformément à
 * l'arborescence demandée ; les deux composants qu'il expose sont donc
 * construits avec `createElement` plutôt qu'avec la syntaxe JSX.
 */
import {
  createContext,
  createElement,
  Fragment,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import type { ReactElement, ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { ThotSecureError, apiClient, errorMessage, isAbortError, isThotSecureError } from './api';
import type { ThotSecureClient } from './api';
import {
  capabilitiesForRole,
  hasAnyCapability,
  hasCapability,
  ROLE_LABELS,
} from './capabilities';
import type { AutonomyMode, Capability, Role, WhoAmI } from './types';

/** Clé de stockage local de la clé API. */
export const API_KEY_STORAGE_KEY = 'thotsecure.api_key';

export type AuthStatus = 'anonymous' | 'loading' | 'authenticated' | 'error';

export interface AuthContextValue {
  /** Client partagé, épinglé sur le périmètre de la clé. */
  client: ThotSecureClient;
  /** Base d'API résolue (utile pour le WebSocket). */
  apiBaseUrl: string;
  apiKey: string | null;
  /** Périmètre de données **imposé par la clé** (`whoami.tenant_id`). */
  tenantId: string | null;
  /**
   * Tenant « inspecté » dans l'interface. Réservé aux administrateurs et
   * **jamais** utilisé comme périmètre de données : sert uniquement à afficher
   * des métadonnées de tenant.
   */
  viewTenantId: string | null;
  setViewTenantId: (tenantId: string) => void;
  whoami: WhoAmI | null;
  status: AuthStatus;
  error: ThotSecureError | null;
  role: Role | null;
  roleLabel: string | null;
  capabilities: readonly Capability[];
  autonomy: AutonomyMode;
  /** `true` par défaut tant que `whoami` n'a pas confirmé le contraire. */
  dryRun: boolean;
  can: (capability: Capability) => boolean;
  canAny: (capabilities: readonly Capability[]) => boolean;
  /** Fragment d'identité à inclure dans les clés de cache TanStack Query. */
  queryScope: string;
  signIn: (apiKey: string) => void;
  signOut: () => void;
  refresh: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function readStoredApiKey(): string | null {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return null;
    const raw = window.localStorage.getItem(API_KEY_STORAGE_KEY);
    return raw && raw.trim() !== '' ? raw.trim() : null;
  } catch {
    return null;
  }
}

function writeStoredApiKey(apiKey: string | null): void {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return;
    if (apiKey === null) window.localStorage.removeItem(API_KEY_STORAGE_KEY);
    else window.localStorage.setItem(API_KEY_STORAGE_KEY, apiKey);
  } catch {
    /* stockage indisponible (mode privé, quota) : la session reste en mémoire */
  }
}

function toThotSecureError(cause: unknown): ThotSecureError {
  if (isThotSecureError(cause)) return cause;
  return new ThotSecureError({
    code: 'network_error',
    status: 0,
    message: errorMessage(cause),
    cause,
  });
}

export interface AuthProviderProps {
  children: ReactNode;
  /** Client injectable (tests) ; par défaut le singleton `apiClient`. */
  client?: ThotSecureClient;
}

/**
 * Fournit l'identité, les capacités et le périmètre tenant.
 * ⚠️ Doit être monté **sous** `QueryClientProvider` (le cache TanStack Query est
 * purgé à chaque changement de clé, pour qu'aucune donnée d'un tenant ne
 * survive à une autre clé).
 */
export function AuthProvider(props: AuthProviderProps): ReactElement {
  const client = props.client ?? apiClient;
  const queryClient = useQueryClient();

  const [apiKey, setApiKey] = useState<string | null>(() => readStoredApiKey());
  const [whoami, setWhoami] = useState<WhoAmI | null>(null);
  const [status, setStatus] = useState<AuthStatus>(() =>
    readStoredApiKey() ? 'loading' : 'anonymous',
  );
  const [error, setError] = useState<ThotSecureError | null>(null);
  const [viewTenantId, setViewTenantIdState] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  // Sans clé API, l'état d'authentification est **déduit**, pas synchronisé : la remise à
  // zéro se fait donc pendant le rendu (patron « ajuster un état quand une prop change »), et
  // seul l'appel au client — un système externe — reste dans l'effet.
  const [lastApiKey, setLastApiKey] = useState(apiKey);
  if (apiKey !== lastApiKey) {
    setLastApiKey(apiKey);
    if (!apiKey) {
      setWhoami(null);
      setError(null);
      setViewTenantIdState(null);
      setStatus('anonymous');
    }
  }

  useEffect(() => {
    if (!apiKey) {
      client.setCredentials(null, null);
      return;
    }

    const controller = new AbortController();
    let cancelled = false;
    setStatus('loading');
    setError(null);
    // Le périmètre reste inconnu jusqu'à la réponse de `whoami`.
    client.setCredentials(apiKey, null);

    client
      .whoami({ signal: controller.signal })
      .then((me) => {
        if (cancelled) return;
        client.setCredentials(apiKey, me.tenant_id);
        setWhoami(me);
        setViewTenantIdState((previous) =>
          previous && previous === me.tenant_id ? previous : me.tenant_id,
        );
        setStatus('authenticated');
      })
      .catch((cause: unknown) => {
        if (cancelled || isAbortError(cause)) return;
        client.setCredentials(apiKey, null);
        setWhoami(null);
        setError(toThotSecureError(cause));
        setStatus('error');
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [apiKey, client, reloadToken]);

  const signIn = useCallback(
    (nextApiKey: string) => {
      const trimmed = nextApiKey.trim();
      if (trimmed === '') return;
      writeStoredApiKey(trimmed);
      // Purge : aucune donnée d'une session précédente ne doit réapparaître.
      queryClient.clear();
      setWhoami(null);
      setViewTenantIdState(null);
      setApiKey(trimmed);
    },
    [queryClient],
  );

  const signOut = useCallback(() => {
    writeStoredApiKey(null);
    queryClient.clear();
    client.setCredentials(null, null);
    setWhoami(null);
    setViewTenantIdState(null);
    setError(null);
    setApiKey(null);
    setStatus('anonymous');
  }, [client, queryClient]);

  const refresh = useCallback(() => setReloadToken((token) => token + 1), []);

  const setViewTenantId = useCallback((tenantId: string) => setViewTenantIdState(tenantId), []);

  const capabilities = useMemo<readonly Capability[]>(
    () => whoami?.capabilities ?? [],
    [whoami],
  );

  const can = useCallback(
    (capability: Capability) => hasCapability(capabilities, capability),
    [capabilities],
  );

  const canAny = useCallback(
    (required: readonly Capability[]) => hasAnyCapability(capabilities, required),
    [capabilities],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      client,
      apiBaseUrl: client.baseUrl,
      apiKey,
      tenantId: whoami?.tenant_id ?? null,
      viewTenantId,
      setViewTenantId,
      whoami,
      status,
      error,
      role: whoami?.role ?? null,
      roleLabel: whoami ? ROLE_LABELS[whoami.role] : null,
      capabilities,
      autonomy: whoami?.autonomy ?? 'manual',
      dryRun: whoami ? whoami.dry_run !== false : true,
      can,
      canAny,
      queryScope: `${apiKey ?? 'anon'}:${whoami?.tenant_id ?? 'none'}`,
      signIn,
      signOut,
      refresh,
    }),
    [
      apiKey,
      can,
      canAny,
      capabilities,
      client,
      error,
      refresh,
      setViewTenantId,
      signIn,
      signOut,
      status,
      viewTenantId,
      whoami,
    ],
  );

  return createElement(AuthContext.Provider, { value }, props.children);
}

/** Accède au contexte d'authentification. Lève hors `AuthProvider`. */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth() doit être utilisé à l’intérieur de <AuthProvider>.');
  }
  return context;
}

/** `true` si la capacité est accordée par `whoami`. */
export function useCapability(capability: Capability): boolean {
  const { can } = useAuth();
  return can(capability);
}

export interface RequireCapabilityProps {
  capability: Capability;
  children: ReactNode;
  /** Contenu alternatif ; par défaut : rien du tout (masquage). */
  fallback?: ReactNode;
}

/**
 * Masque son contenu quand la capacité manque. Exigence produit : les boutons
 * d'action ne doivent pas être affichés à un rôle qui ne peut pas les exercer.
 */
export function RequireCapability(props: RequireCapabilityProps): ReactElement | null {
  const granted = useCapability(props.capability);
  if (!granted) return props.fallback ? createElement(Fragment, null, props.fallback) : null;
  return createElement(Fragment, null, props.children);
}

/** Capacités effectives d'un rôle — utile pour l'aide contextuelle. */
export function roleCapabilities(role: Role | null): Capability[] {
  return role ? capabilitiesForRole(role) : [];
}
