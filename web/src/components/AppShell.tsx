/**
 * Coque applicative : barre latérale de navigation, en-tête, sélecteur de
 * période, indicateur de connexion au flux temps réel.
 *
 * Deux invariants de sûreté sont portés par cette coque :
 *  1. `AutonomyBanner` (compact) est affiché **en permanence** dans l'en-tête :
 *     le mode d'autonomie et l'état `dry_run` ne sont jamais masqués, quelle que
 *     soit la page consultée (exigence produit, contrat §1).
 *  2. La navigation est **filtrée par capacité** (`capabilities.ts`) : un rôle
 *     qui ne peut pas lire le journal d'audit ne voit pas l'entrée de menu. Le
 *     serveur revérifie de toute façon chaque route (défense en profondeur).
 *
 * Le fournisseur de période expose une fenêtre temporelle unique (1 h → 30 j) à
 * toutes les pages, pour que compteurs, listes et exports restent cohérents.
 */
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import type { JSX } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';

import { AutonomyBanner } from './AutonomyBanner';
import { ErrorBoundary } from './ErrorBoundary';
import { LiveStreamProvider, StreamStatusIndicator } from './LiveStream';
import { Button, StatusPill } from './ui';
import { useAuth } from '@/lib/auth';
import { resolveRootBaseUrl } from '@/lib/api';
import { CAPABILITY_LABELS } from '@/lib/capabilities';
import { formatDateTime } from '@/lib/format';
import type { Capability } from '@/lib/types';

/* -------------------------------------------------------------------------- */
/* Période d'analyse partagée                                                  */
/* -------------------------------------------------------------------------- */

export const PERIOD_VALUES = ['1h', '24h', '7d', '30d'] as const;
export type PeriodValue = (typeof PERIOD_VALUES)[number];

const PERIOD_LABELS: Record<PeriodValue, string> = {
  '1h': '1 h',
  '24h': '24 h',
  '7d': '7 j',
  '30d': '30 j',
};

const PERIOD_SECONDS: Record<PeriodValue, number> = {
  '1h': 3_600,
  '24h': 86_400,
  '7d': 604_800,
  '30d': 2_592_000,
};

export interface PeriodContextValue {
  period: PeriodValue;
  /** Borne basse ISO 8601 (`since`) cohérente avec la période choisie. */
  since: string;
  /** Libellé lisible de la borne basse. */
  sinceLabel: string;
  setPeriod: (period: PeriodValue) => void;
  /** Réancre la fenêtre sur « maintenant » et invalide les requêtes en cache. */
  refresh: () => void;
}

const PeriodContext = createContext<PeriodContextValue | null>(null);

export function PeriodProvider(props: { children: ReactNode }): JSX.Element {
  const queryClient = useQueryClient();
  const [period, setPeriodValue] = useState<PeriodValue>('24h');
  const [anchorMs, setAnchorMs] = useState<number>(() => Date.now());

  // `since` est figé entre deux actions de l'opérateur : sinon la clé de requête
  // changerait à chaque rendu et relancerait les appels en boucle.
  const since = useMemo(
    () => new Date(anchorMs - PERIOD_SECONDS[period] * 1_000).toISOString(),
    [anchorMs, period],
  );

  const setPeriod = useCallback((next: PeriodValue) => {
    setPeriodValue(next);
    setAnchorMs(Date.now());
  }, []);

  const refresh = useCallback(() => {
    setAnchorMs(Date.now());
    void queryClient.invalidateQueries();
  }, [queryClient]);

  const value = useMemo<PeriodContextValue>(
    () => ({ period, since, sinceLabel: formatDateTime(since), setPeriod, refresh }),
    [period, refresh, setPeriod, since],
  );

  return <PeriodContext.Provider value={value}>{props.children}</PeriodContext.Provider>;
}

export function usePeriod(): PeriodContextValue {
  const context = useContext(PeriodContext);
  if (!context) throw new Error('usePeriod() doit être utilisé dans <PeriodProvider>.');
  return context;
}

export function PeriodSelector(): JSX.Element {
  const { period, setPeriod, refresh, sinceLabel } = usePeriod();

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-2xs uppercase tracking-wider text-slate-500">Période</span>
      <div
        role="group"
        aria-label="Période d'analyse"
        className="flex overflow-hidden rounded border border-slate-700"
      >
        {PERIOD_VALUES.map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={period === value}
            onClick={() => setPeriod(value)}
            className={clsx(
              'px-2 py-0.5 text-2xs font-medium transition-colors',
              period === value
                ? 'bg-cyan-900/60 text-cyan-100'
                : 'bg-slate-950 text-slate-400 hover:bg-slate-800/70 hover:text-slate-200',
            )}
          >
            {PERIOD_LABELS[value]}
          </button>
        ))}
      </div>
      <Button
        size="sm"
        variant="secondary"
        onClick={refresh}
        title={`Réancrer la fenêtre sur maintenant (depuis ${sinceLabel})`}
      >
        Rafraîchir
      </Button>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Navigation                                                                  */
/* -------------------------------------------------------------------------- */

interface NavItem {
  to: string;
  label: string;
  glyph: string;
  /** `null` : accessible sans capacité (page de soutien). */
  capability: Capability | null;
  description: string;
  /** `true` : correspondance exacte de la route (`/`). */
  end?: boolean;
}

export const NAV_ITEMS: readonly NavItem[] = [
  {
    to: '/',
    label: 'Tableau de bord',
    glyph: '◧',
    capability: 'read:stats',
    description: 'KPI, flux temps réel, répartition des sévérités',
    end: true,
  },
  {
    to: '/findings',
    label: 'Findings',
    glyph: '⚠',
    capability: 'read:findings',
    description: 'Détections agrégées, preuves, statut, rapports',
  },
  {
    to: '/actions',
    label: 'Actions',
    glyph: '⚙',
    capability: 'read:findings',
    description: 'Playbooks, approbation, exécution, rollback',
  },
  {
    to: '/audit',
    label: 'Audit',
    glyph: '⛓',
    capability: 'read:audit',
    description: 'Journal chaîné append-only, vérification d’intégrité',
  },
  {
    to: '/rules',
    label: 'Règles & politiques',
    glyph: '⚖',
    capability: 'read:rules',
    description: 'Détection YAML, policy-as-code, rechargement',
  },
  {
    to: '/collectors',
    label: 'Collecteurs',
    glyph: '⇄',
    capability: 'read:stats',
    description: 'État des collecteurs, exécution manuelle',
  },
  {
    to: '/support',
    label: 'Soutien',
    glyph: '♥',
    capability: null,
    description: 'Adresses de dons officielles et avertissement anti-arnaque',
  },
];

/* -------------------------------------------------------------------------- */
/* Coque                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * `GET /version` est public (contrat §4.1) : on s'en sert uniquement pour
 * afficher version et licence en pied de page, jamais pour autoriser quoi que ce
 * soit côté client.
 */
function useServerVersion(): { version: string | null; license: string | null } {
  const { client } = useAuth();
  const query = useQuery({
    queryKey: ['server-version'],
    queryFn: ({ signal }) => client.serverVersion({ signal }),
    staleTime: 5 * 60_000,
    retry: false,
  });

  return useMemo(
    () => ({ version: query.data?.version ?? null, license: query.data?.license ?? null }),
    [query.data],
  );
}

/**
 * URL de la console embarquée (contrat §4.9).
 *
 * - base d'API **absolue** (`http://hote:8080/api/v1`, ou
 *   `VITE_THOT_API_URL` en dev) : la console est à la racine de l'API (`GET /`) ;
 * - base relative (`/api/v1`, derrière le proxy nginx) : la racine appartient au
 *   SPA ; la console reste joignable sur son point d'entrée `/ui/login`, proxifié.
 */
function embeddedConsoleUrl(apiBaseUrl: string): string {
  const root = resolveRootBaseUrl(apiBaseUrl);
  return root === '' ? '/ui/login' : `${root}/`;
}

export function AppShell(): JSX.Element {
  const { tenantId, role, roleLabel, capabilities, autonomy, dryRun, signOut, can, apiBaseUrl } = useAuth();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { version, license } = useServerVersion();

  const visibleItems = useMemo(
    () => NAV_ITEMS.filter((item) => item.capability === null || can(item.capability)),
    [can],
  );

  const currentItem = useMemo(() => {
    const exact = visibleItems.find((item) => item.to === location.pathname);
    if (exact) return exact;
    return visibleItems.find((item) => item.to !== '/' && location.pathname.startsWith(item.to)) ?? null;
  }, [location.pathname, visibleItems]);

  const capabilityTitle = capabilities.map((capability) => CAPABILITY_LABELS[capability]).join(' · ');

  return (
    <LiveStreamProvider tenantId={tenantId}>
      <PeriodProvider>
        <div className="flex min-h-screen">
          {sidebarOpen ? (
            <div
              className="fixed inset-0 z-30 bg-slate-950/70 lg:hidden"
              role="presentation"
              onClick={() => setSidebarOpen(false)}
            />
          ) : null}

          <aside
            className={clsx(
              'fixed inset-y-0 left-0 z-40 flex w-60 shrink-0 flex-col overflow-y-auto border-r border-slate-800 bg-slate-950/95 px-2 py-3 transition-transform lg:static lg:translate-x-0',
              sidebarOpen ? 'translate-x-0' : '-translate-x-full',
            )}
          >
            <div className="px-1.5">
              <p className="text-sm font-semibold tracking-tight text-slate-50">Thot Secure</p>
              <p className="text-2xs text-slate-500">
                Console SOC — interface riche optionnelle
              </p>
            </div>

            <nav aria-label="Navigation principale" className="mt-3 space-y-0.5">
              {visibleItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end ?? false}
                  title={item.description}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-start gap-2 rounded px-2 py-1.5 text-xs transition-colors',
                      isActive
                        ? 'bg-cyan-950/60 font-medium text-cyan-100'
                        : 'text-slate-300 hover:bg-slate-800/60 hover:text-white',
                    )
                  }
                >
                  <span aria-hidden="true" className="mt-0.5 w-3 text-center text-2xs text-cyan-400">
                    {item.glyph}
                  </span>
                  <span className="min-w-0">{item.label}</span>
                </NavLink>
              ))}
            </nav>

            <div className="mt-4 space-y-2 px-1.5">
              <div>
                <p className="text-2xs uppercase tracking-wider text-slate-500">Rôle</p>
                <p className="text-xs text-slate-200" title={capabilityTitle}>
                  {roleLabel ?? '—'}
                  {role !== null ? (
                    <span className="ml-1 font-mono text-2xs text-slate-500">{role}</span>
                  ) : null}
                </p>
              </div>
              <div>
                <p className="text-2xs uppercase tracking-wider text-slate-500">Périmètre (clé API)</p>
                <p className="break-all font-mono text-2xs text-slate-300">{tenantId ?? '—'}</p>
              </div>
              <p className="text-2xs leading-relaxed text-slate-500">
                Les capacités proviennent de <code>GET /api/v1/auth/whoami</code>. Les contrôles non autorisés sont
                masqués ici et refusés par le serveur.
              </p>
            </div>

            <div className="mt-auto space-y-2 px-1.5 pt-4">
              <a
                href={embeddedConsoleUrl(apiBaseUrl)}
                target="_blank"
                rel="noopener noreferrer"
                className="block text-2xs text-cyan-300"
                title="Console embarquée servie par l’API (Jinja2 + JS, aucun build Node requis) : c’est la référence. En développement, l’API n’est pas proxifiée sur /ui : ouvrez directement http://127.0.0.1:8080/."
              >
                Console embarquée ↗
              </a>
              <Button size="sm" variant="secondary" className="w-full" onClick={signOut}>
                Se déconnecter
              </Button>
            </div>
          </aside>

          <div className="flex min-w-0 flex-1 flex-col">
            <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/85 backdrop-blur">
              <div className="flex flex-wrap items-center gap-2 px-3 py-2">
                <Button
                  size="sm"
                  variant="secondary"
                  className="lg:hidden"
                  aria-expanded={sidebarOpen}
                  onClick={() => setSidebarOpen((value) => !value)}
                >
                  Menu
                </Button>
                <h1 className="min-w-0 truncate">{currentItem?.label ?? 'Thot Secure'}</h1>
                <AutonomyBanner mode={autonomy} dryRun={dryRun} tenantId={tenantId} compact />
                <div className="ml-auto flex flex-wrap items-center gap-2">
                  <StatusPill
                    label={`${capabilities.length} capacité(s)`}
                    title={capabilityTitle !== '' ? capabilityTitle : 'Aucune capacité accordée'}
                    className="border-slate-700 bg-slate-800/70 text-slate-300"
                  />
                  {roleLabel !== null ? (
                    <StatusPill label={roleLabel} className="border-cyan-800 bg-cyan-950/50 text-cyan-200" />
                  ) : null}
                </div>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/70 px-3 py-1.5">
                <StreamStatusIndicator />
                <PeriodSelector />
              </div>
            </header>

            <main className="min-w-0 flex-1 space-y-3 px-3 py-3">
              {/*
                Filet local : une erreur de rendu d'une page ne doit pas masquer
                la coque — donc pas le bandeau `dry_run` / mode d'autonomie. La
                clé sur le chemin réarme le filet à chaque navigation.
              */}
              <ErrorBoundary key={location.pathname}>
                <Outlet />
              </ErrorBoundary>
            </main>

            <footer className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-slate-800 px-3 py-2 text-2xs text-slate-500">
              <span>
                Thot Secure{version !== null ? ` v${version}` : ''}
                {license !== null ? ` — ${license}` : ''} · SOAR/CSPM défensif.
              </span>
              <span>
                La console embarquée servie par l’API (<code className="soc-code-inline">GET /</code>) reste la
                référence sans build Node ; cette interface est la version riche optionnelle.
              </span>
            </footer>
          </div>
        </div>
      </PeriodProvider>
    </LiveStreamProvider>
  );
}
