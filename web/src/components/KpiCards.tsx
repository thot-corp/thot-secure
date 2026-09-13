/**
 * Cartes KPI du tableau de bord.
 *
 * Source : `GET /api/v1/stats/overview` (contrat §4.8). Les compteurs affichés
 * sont ceux de la période sélectionnée dans la coque pour les valeurs 24 h / 7 j
 * du contrat ; `MTTA`/`MTTR` sont en secondes et rendus par `formatDuration`.
 *
 * Sûreté : la carte « Posture » reprend le mode d'autonomie et l'état `dry_run`
 * **renvoyés par le serveur** (`stats.autonomy`, `stats.dry_run`) — et non les
 * valeurs du client, qui sont elles-mêmes issues de `whoami`. Les deux doivent
 * concorder ; en cas d'écart, c'est la valeur serveur qui est affichée.
 */
import clsx from 'clsx';
import type { ReactNode } from 'react';

import { Button, DistributionBar, ErrorNotice, InlineNotice, LoadingBlock, Panel } from './ui';
import type { BarSegment } from './ui';
import { AUTONOMY_LABELS, SEVERITY_DOT_CLASSES, SEVERITY_LABELS, formatDuration, formatNumber } from '@/lib/format';
import { SEVERITIES } from '@/lib/types';
import type { Severity, SeverityCounts, StatsOverview } from '@/lib/types';

export type KpiTone = 'neutral' | 'ok' | 'warn' | 'danger';

const TILE_TONE_CLASS: Record<KpiTone, string> = {
  neutral: 'border-slate-800 bg-slate-950/50',
  ok: 'border-emerald-900 bg-emerald-950/20',
  warn: 'border-amber-800 bg-amber-950/20',
  danger: 'border-rose-800 bg-rose-950/25',
};

const TILE_VALUE_TONE_CLASS: Record<KpiTone, string> = {
  neutral: 'text-slate-100',
  ok: 'text-emerald-200',
  warn: 'text-amber-200',
  danger: 'text-rose-200',
};

interface KpiTileProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: KpiTone;
  title?: string;
}

function KpiTile(props: KpiTileProps): JSX.Element {
  const { label, value, hint, tone = 'neutral', title } = props;
  return (
    <div className={clsx('rounded-md border px-2.5 py-2', TILE_TONE_CLASS[tone])} title={title}>
      <p className="text-2xs uppercase tracking-wider text-slate-400">{label}</p>
      <p className={clsx('mt-0.5 font-mono text-lg font-semibold leading-tight', TILE_VALUE_TONE_CLASS[tone])}>
        {value}
      </p>
      {hint ? <p className="mt-0.5 text-2xs leading-snug text-slate-400">{hint}</p> : null}
    </div>
  );
}

/** Lecture défensive d'un compteur par sévérité (le serveur peut omettre une clé). */
function severityCount(counts: SeverityCounts | undefined, severity: Severity): number {
  const value = counts?.[severity];
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

export interface KpiCardsProps {
  stats: StatsOverview | null | undefined;
  isLoading?: boolean;
  error?: unknown;
  onRetry?: () => void;
}

export function KpiCards(props: KpiCardsProps): JSX.Element {
  const { stats, isLoading = false, error, onRetry } = props;

  if (error) {
    return (
      <Panel title="Indicateurs clés">
        <ErrorNotice error={error} title="Statistiques indisponibles" onRetry={onRetry} />
      </Panel>
    );
  }

  if (isLoading || !stats) {
    return (
      <Panel title="Indicateurs clés">
        <LoadingBlock label="Chargement des statistiques…" rows={4} />
      </Panel>
    );
  }

  const segments: BarSegment[] = SEVERITIES.map((severity) => ({
    label: SEVERITY_LABELS[severity],
    value: severityCount(stats.findings_by_severity, severity),
    className: SEVERITY_DOT_CLASSES[severity],
  }));

  const urgentFindings =
    severityCount(stats.findings_by_severity, 'critical') + severityCount(stats.findings_by_severity, 'high');
  const pendingApprovals = stats.actions_pending_approval;
  const topRules = Array.isArray(stats.top_rules) ? stats.top_rules : [];

  return (
    <Panel
      title="Indicateurs clés"
      description={
        stats.generated_at !== null
          ? `Instantané serveur généré le ${stats.generated_at}`
          : 'Compteurs 24 h / 7 j renvoyés par l’API'
      }
      actions={onRetry ? <Button size="sm" variant="secondary" onClick={onRetry}>Rafraîchir</Button> : undefined}
    >
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <KpiTile
          label="Événements 24 h"
          value={formatNumber(stats.events_24h)}
          hint={`${formatNumber(stats.events_7d)} sur 7 jours`}
        />
        <KpiTile
          label="Findings 24 h"
          value={formatNumber(stats.findings_24h)}
          hint={`${formatNumber(stats.findings_7d)} sur 7 jours`}
          tone={stats.findings_24h > 0 ? 'warn' : 'neutral'}
        />
        <KpiTile
          label="Findings ouverts"
          value={formatNumber(stats.open_findings)}
          hint={`dont ${formatNumber(urgentFindings)} en sévérité haute ou critique`}
          tone={urgentFindings > 0 ? 'danger' : 'ok'}
        />
        <KpiTile
          label="Approbations en attente"
          value={formatNumber(pendingApprovals)}
          hint="Actions en `pending_approval` — aucune exécution sans décision humaine"
          tone={pendingApprovals > 0 ? 'warn' : 'ok'}
        />
        <KpiTile label="MTTA" value={formatDuration(stats.mtta_seconds)} hint="Délai moyen de prise en compte" />
        <KpiTile label="MTTR" value={formatDuration(stats.mttr_seconds)} hint="Délai moyen de remédiation" />
        <KpiTile
          label="Actions réussies"
          value={formatNumber(stats.actions_succeeded)}
          hint={`${formatNumber(stats.actions_failed)} échec(s) · ${formatNumber(stats.actions_rolled_back)} annulée(s)`}
          tone={stats.actions_failed > 0 ? 'warn' : 'ok'}
        />
        <KpiTile
          label="Posture"
          value={AUTONOMY_LABELS[stats.autonomy]}
          hint={stats.dry_run ? 'dry_run actif : playbooks simulés' : 'exécution réelle armée'}
          tone={stats.dry_run ? 'warn' : 'danger'}
          title="Valeurs renvoyées par GET /api/v1/stats/overview (source serveur)."
        />
      </div>

      <div className="mt-3 space-y-2">
        <h3>Findings par sévérité</h3>
        <DistributionBar segments={segments} />
      </div>

      {!stats.dry_run ? (
        <InlineNotice tone="danger" className="mt-3" title="Exécution réelle armée (dry_run = false)">
          Les playbooks agissent réellement sur les cibles. Toute exécution exige une double confirmation explicite
          dans cette interface, et reste tracée dans le journal d’audit.
        </InlineNotice>
      ) : null}

      {topRules.length > 0 ? (
        <div className="mt-3">
          <h3>Règles les plus déclenchées</h3>
          <ul className="mt-1 space-y-0.5">
            {topRules.slice(0, 8).map((rule) => (
              <li key={rule.rule_id} className="flex items-center justify-between gap-3 text-2xs">
                <span className="min-w-0 truncate text-slate-300" title={rule.rule_name ?? rule.rule_id}>
                  <span className="font-mono text-slate-400">{rule.rule_id}</span>
                  {rule.rule_name ? ` — ${rule.rule_name}` : ''}
                </span>
                <span className="font-mono text-slate-200">{formatNumber(rule.count)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Panel>
  );
}
