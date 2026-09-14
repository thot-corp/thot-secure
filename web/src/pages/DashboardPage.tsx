/**
 * Tableau de bord : posture globale, flux temps réel, findings les plus risqués.
 *
 * Le bandeau d'autonomie est répété ici en version complète (l'en-tête de la
 * coque n'en affiche qu'une variante compacte) : sur l'écran d'astreinte, le mode
 * d'autonomie et l'état `dry_run` doivent être lisibles sans cliquer quoi que ce
 * soit.
 */
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { AutonomyBanner } from '@/components/AutonomyBanner';
import { KpiCards } from '@/components/KpiCards';
import { LiveStream } from '@/components/LiveStream';
import { SeverityBadge } from '@/components/SeverityBadge';
import { usePeriod } from '@/components/AppShell';
import {
  EmptyState,
  ErrorNotice,
  LockedNotice,
  LoadingBlock,
  PageHeader,
  Panel,
  StatusPill,
} from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { FINDING_STATUS_CLASSES, FINDING_STATUS_LABELS, formatNumber, formatRelative, formatScore } from '@/lib/format';
import type { JSX } from 'react';

export function DashboardPage(): JSX.Element {
  const { client, queryScope, can, tenantId, autonomy, dryRun } = useAuth();
  const { since, sinceLabel } = usePeriod();
  const canStats = can('read:stats');
  const canFindings = can('read:findings');

  const statsQuery = useQuery({
    queryKey: ['stats', queryScope],
    queryFn: ({ signal }) => client.statsOverview({ signal }),
    enabled: canStats,
  });

  const recentQuery = useQuery({
    queryKey: ['findings', 'recent', queryScope, since],
    queryFn: ({ signal }) =>
      client.listFindings({ status: 'open', since, sort: 'risk_score', limit: 8 }, { signal }),
    enabled: canFindings,
  });

  const recentFindings = recentQuery.data?.items ?? [];
  const pendingApprovals = statsQuery.data?.actions_pending_approval ?? 0;

  return (
    <div className="space-y-3">
      <PageHeader
        title="Tableau de bord"
        description={`Posture du tenant « ${tenantId ?? '—'} » · fenêtre depuis ${sinceLabel}. Les compteurs proviennent de GET /api/v1/stats/overview ; le flux de GET /api/v1/ws/stream.`}
        actions={
          <Link
            to="/findings"
            className="text-2xs text-cyan-300"
            title="Ouvrir la liste complète des findings"
          >
            Voir tous les findings →
          </Link>
        }
      />

      <AutonomyBanner mode={autonomy} dryRun={dryRun} tenantId={tenantId} />

      {canStats ? (
        <KpiCards
          stats={statsQuery.data ?? null}
          isLoading={statsQuery.isLoading}
          error={statsQuery.error}
          onRetry={() => void statsQuery.refetch()}
        />
      ) : (
        <LockedNotice capability="read:stats" />
      )}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
        <div className="space-y-3 xl:col-span-2">
          <LiveStream maxHeight={420} />
        </div>

        <div className="space-y-3">
          <Panel
            title="Findings ouverts les plus risqués"
            description={`Depuis ${sinceLabel} · tri serveur risk_score`}
            actions={
              <Link to="/findings" className="text-2xs text-cyan-300">
                Tout voir →
              </Link>
            }
          >
            {!canFindings ? (
              <LockedNotice capability="read:findings" />
            ) : recentQuery.error ? (
              <ErrorNotice
                error={recentQuery.error}
                title="Findings indisponibles"
                onRetry={() => void recentQuery.refetch()}
              />
            ) : recentQuery.isLoading ? (
              <LoadingBlock label="Chargement des findings…" rows={4} />
            ) : recentFindings.length === 0 ? (
              <EmptyState
                title="Aucun finding ouvert"
                description="Aucune détection ouverte sur la période : élargissez la fenêtre temporelle pour vérifier l’activité des règles."
              />
            ) : (
              <ul className="space-y-1.5">
                {recentFindings.map((finding) => (
                  <li key={finding.finding_id}>
                    <Link
                      to={`/findings?focus=${encodeURIComponent(finding.finding_id)}`}
                      className="block rounded border border-slate-800 bg-slate-950/50 px-2 py-1.5 hover:border-cyan-800 hover:no-underline"
                    >
                      <span className="flex items-center justify-between gap-2">
                        <SeverityBadge severity={finding.severity} />
                        <span className="font-mono text-2xs text-slate-300">
                          risque {formatScore(finding.risk_score)}
                        </span>
                      </span>
                      <span className="mt-0.5 block truncate text-xs text-slate-100" title={finding.title}>
                        {finding.title}
                      </span>
                      <span className="mt-0.5 block truncate font-mono text-2xs text-slate-500">
                        {finding.rule_id} · {formatNumber(finding.count)} occurrence(s) ·{' '}
                        {formatRelative(finding.last_seen)}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel
            title="Actions en attente d’approbation"
            description="Une action en attente n’est jamais exécutée automatiquement."
            actions={
              <Link to="/actions" className="text-2xs text-cyan-300">
                Ouvrir →
              </Link>
            }
          >
            {pendingApprovals > 0 ? (
              <p className="text-xs text-amber-200">
                <span className="font-mono text-lg font-semibold">{formatNumber(pendingApprovals)}</span> action(s)
                attendent une décision humaine. L’exécution est refusée tant que l’approbation n’a pas été donnée
                (contrat §4.6).
              </p>
            ) : (
              <p className="text-xs text-emerald-200">
                Aucune action en attente : rien n’est suspendu à une décision.
              </p>
            )}
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <StatusPill
                label={`Autonomie : ${autonomy}`}
                className="border-slate-700 bg-slate-800/70 text-slate-300"
              />
              <StatusPill
                label={dryRun ? 'dry_run actif' : 'exécution réelle armée'}
                className={
                  dryRun
                    ? 'border-amber-700 bg-amber-950/60 text-amber-200'
                    : 'border-rose-700 bg-rose-950/60 text-rose-200'
                }
              />
              <StatusPill
                label={FINDING_STATUS_LABELS.open}
                className={FINDING_STATUS_CLASSES.open}
                title="Statut des findings ciblés par le flux d’astreinte."
              />
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
