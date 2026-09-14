/**
 * Table des findings : filtres (statut, sévérité, score minimal), tri, pagination
 * par curseur.
 *
 * Contrat de lecture (§4.4) :
 *  - filtres serveur : `status`, `severity`, `rule_id`, `since`, `until`,
 *    `min_risk`, `sort` (`risk_score` | `last_seen`), `limit`, `cursor` ;
 *  - le `tenant_id` n'est **jamais** un paramètre : le client est épinglé sur le
 *    périmètre de la clé (`lib/api.ts` refuse toute ligne d'un autre tenant).
 *
 * Le tri demandé par l'opérateur est appliqué à la page courante ; la clé de tri
 * est également transmise au serveur (`sort`) pour que la page reçue soit
 * pertinente. Les deux mécanismes sont affichés à l'écran pour éviter toute
 * ambiguïté sur ce qui est trié.
 */
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { useMemo, useState } from 'react';
import type { JSX } from 'react';

import { usePeriod } from './AppShell';
import { EmptyState } from './EmptyState';
import { SeverityBadge } from './SeverityBadge';
import { Button, Checkbox, ErrorNotice, Field, LoadingBlock, Panel, Select, TextInput } from './ui';
import { useAuth } from '@/lib/auth';
import {
  FINDING_STATUS_CLASSES,
  FINDING_STATUS_LABELS,
  SEVERITY_LABELS,
  SEVERITY_RANK,
  formatDateTime,
  formatNumber,
  formatScore,
} from '@/lib/format';
import type { Finding, FindingSort, FindingStatus, Severity, SortDirection } from '@/lib/types';
import { FINDING_STATUSES, SEVERITIES } from '@/lib/types';

/** Taille de page demandée au serveur (le contrat autorise davantage, sans intérêt ici). */
export const FINDINGS_PAGE_SIZE = 50;

type SortKey = 'risk_score' | 'last_seen' | 'severity' | 'status' | 'count' | 'title';

interface SortState {
  key: SortKey;
  direction: SortDirection;
}

const SORT_LABELS: Record<SortKey, string> = {
  risk_score: 'Score de risque',
  last_seen: 'Dernière observation',
  severity: 'Sévérité',
  status: 'Statut',
  count: 'Occurrences',
  title: 'Titre',
};

function compareFindings(left: Finding, right: Finding, key: SortKey): number {
  switch (key) {
    case 'risk_score':
      return left.risk_score - right.risk_score;
    case 'count':
      return left.count - right.count;
    case 'severity':
      return SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity];
    case 'status':
      return FINDING_STATUSES.indexOf(left.status) - FINDING_STATUSES.indexOf(right.status);
    case 'title':
      return left.title.localeCompare(right.title, 'fr');
    case 'last_seen':
    default:
      // Les horodatages du contrat sont ISO 8601 : l'ordre lexicographique suffit.
      return left.last_seen.localeCompare(right.last_seen);
  }
}

export interface FindingsTableProps {
  /** Finding actuellement ouvert dans le panneau de détail. */
  selectedId: string | null;
  onSelect: (findingId: string) => void;
  className?: string;
}

export function FindingsTable(props: FindingsTableProps): JSX.Element {
  const { selectedId, onSelect, className } = props;
  const { client, queryScope, can } = useAuth();
  const { since, sinceLabel } = usePeriod();
  const canRead = can('read:findings');

  const [status, setStatus] = useState<FindingStatus | ''>('open');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [minRisk, setMinRisk] = useState<number | null>(null);
  const [minRiskDraft, setMinRiskDraft] = useState<string>('');
  const [useWindow, setUseWindow] = useState(true);
  const [sort, setSort] = useState<SortState>({ key: 'risk_score', direction: 'desc' });
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);

  const cursor = cursorStack.length > 0 ? cursorStack[cursorStack.length - 1] ?? null : null;
  const serverSort: FindingSort = sort.key === 'last_seen' ? 'last_seen' : 'risk_score';

  const query = useQuery({
    queryKey: [
      'findings',
      queryScope,
      { status, severity, minRisk, serverSort, cursor, useWindow, since: useWindow ? since : null },
    ],
    queryFn: ({ signal }) =>
      client.listFindings(
        {
          status,
          severity,
          min_risk: minRisk ?? undefined,
          since: useWindow ? since : undefined,
          sort: serverSort,
          limit: FINDINGS_PAGE_SIZE,
          cursor: cursor ?? undefined,
        },
        { signal },
      ),
    enabled: canRead,
  });

  // Tableau stable entre deux rendus : sans ce `useMemo`, le repli `[]`
  // construirait un nouveau tableau à chaque rendu, et les `useMemo` qui en dépendent
  // se recalculeraient tous autant de fois.
  const items = useMemo(() => query.data?.items ?? [], [query.data]);
  const total = query.data?.total ?? null;
  const nextCursor = query.data?.next_cursor ?? null;
  const hasNext = typeof nextCursor === 'string' && nextCursor !== '';
  const hasPrevious = cursorStack.length > 1;

  const sortedItems = useMemo(() => {
    const copy = [...items];
    copy.sort((left, right) => compareFindings(left, right, sort.key));
    if (sort.direction === 'desc') copy.reverse();
    return copy;
  }, [items, sort.direction, sort.key]);

  const resetPagination = (): void => setCursorStack([null]);

  const applyMinRisk = (): void => {
    const trimmed = minRiskDraft.trim();
    if (trimmed === '') {
      setMinRisk(null);
    } else {
      const parsed = Number(trimmed);
      setMinRisk(Number.isFinite(parsed) ? Math.min(100, Math.max(0, parsed)) : null);
    }
    resetPagination();
  };

  const toggleSort = (key: SortKey): void => {
    setSort((previous) =>
      previous.key === key
        ? { key, direction: previous.direction === 'asc' ? 'desc' : 'asc' }
        : { key, direction: key === 'title' ? 'asc' : 'desc' },
    );
    // Le tri étant appliqué côté client à la page courante, on revient à la
    // première page pour éviter d'afficher « page 3 triée à l'envers ».
    resetPagination();
  };

  const sortIndicator = (key: SortKey): string =>
    sort.key === key ? (sort.direction === 'desc' ? '▾' : '▴') : '';

  if (!canRead) {
    return (
      <div className={className}>
        <EmptyState
          variant="locked"
          title="Findings masqués — capacité « read:findings » requise"
          description="Votre clé API ne permet pas de lire les findings. Le serveur applique ce contrôle indépendamment de cette interface."
        />
      </div>
    );
  }

  return (
    <Panel
      className={className}
      title="Findings"
      description={`Filtres serveur : statut, sévérité, score minimal${
        useWindow ? ` · fenêtre depuis ${sinceLabel}` : ' · toutes périodes'
      } · page de ${FINDINGS_PAGE_SIZE}`}
      actions={
        <Button size="sm" variant="secondary" busy={query.isFetching} onClick={() => void query.refetch()}>
          Rafraîchir
        </Button>
      }
    >
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Statut" className="w-40">
          <Select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value as FindingStatus | '');
              resetPagination();
            }}
          >
            <option value="">Tous</option>
            {FINDING_STATUSES.map((value) => (
              <option key={value} value={value}>
                {FINDING_STATUS_LABELS[value]}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Sévérité" className="w-36">
          <Select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value as Severity | '');
              resetPagination();
            }}
          >
            <option value="">Toutes</option>
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {SEVERITY_LABELS[value]}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Score minimal (0–100)" className="w-40">
          <div className="flex gap-1">
            <TextInput
              type="number"
              min={0}
              max={100}
              step={5}
              value={minRiskDraft}
              placeholder={minRisk === null ? 'aucun' : String(minRisk)}
              onChange={(event) => setMinRiskDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  applyMinRisk();
                }
              }}
            />
            <Button size="sm" variant="secondary" onClick={applyMinRisk}>
              OK
            </Button>
          </div>
        </Field>

        <Field label="Tri" className="w-44">
          <Select
            value={sort.key}
            onChange={(event) => toggleSort(event.target.value as SortKey)}
          >
            {(Object.keys(SORT_LABELS) as SortKey[]).map((key) => (
              <option key={key} value={key}>
                {SORT_LABELS[key]}
              </option>
            ))}
          </Select>
        </Field>

        {minRisk !== null ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setMinRisk(null);
              setMinRiskDraft('');
              resetPagination();
            }}
          >
            Score ≥ {minRisk} ✕
          </Button>
        ) : null}

        <div className="pb-1">
          <Checkbox
            checked={useWindow}
            onChange={(checked) => {
              setUseWindow(checked);
              resetPagination();
            }}
            label={`Limiter à la période sélectionnée (depuis ${sinceLabel})`}
          />
        </div>
      </div>

      {query.error ? (
        <ErrorNotice
          className="mt-2"
          error={query.error}
          title="Chargement des findings impossible"
          onRetry={() => void query.refetch()}
        />
      ) : null}

      <div className={clsx('mt-2', query.isFetching && 'opacity-60')}>
        {query.isLoading ? (
          <LoadingBlock label="Chargement des findings…" rows={5} />
        ) : sortedItems.length === 0 ? (
          <EmptyState
            title="Aucun finding pour ces critères"
            description="Élargissez la période, abaissez le score minimal ou changez de statut. Une liste vide n’est pas nécessairement un signe d’absence de menace."
          />
        ) : (
          <div className="soc-table-wrap">
            <table className="soc-table">
              <caption>
                Tri appliqué à la page courante : {SORT_LABELS[sort.key]} ({sort.direction === 'desc' ? 'décroissant' : 'croissant'}) —
                le serveur reçoit <code className="soc-code-inline">sort={serverSort}</code>.
              </caption>
              <thead>
                <tr>
                  <SortableHeader label="Sévérité" onClick={() => toggleSort('severity')} indicator={sortIndicator('severity')} />
                  <SortableHeader label="Risque" onClick={() => toggleSort('risk_score')} indicator={sortIndicator('risk_score')} align="right" />
                  <SortableHeader label="Titre / règle" onClick={() => toggleSort('title')} indicator={sortIndicator('title')} />
                  <SortableHeader label="Statut" onClick={() => toggleSort('status')} indicator={sortIndicator('status')} />
                  <SortableHeader label="Occ." onClick={() => toggleSort('count')} indicator={sortIndicator('count')} align="right" />
                  <SortableHeader label="Dernière observation" onClick={() => toggleSort('last_seen')} indicator={sortIndicator('last_seen')} />
                  <th scope="col">Tags</th>
                </tr>
              </thead>
              <tbody>
                {sortedItems.map((finding) => (
                  <tr
                    key={finding.finding_id}
                    data-selected={selectedId === finding.finding_id}
                    data-tone={finding.severity === 'critical' ? 'danger' : undefined}
                    className="cursor-pointer"
                    onClick={() => onSelect(finding.finding_id)}
                  >
                    <td>
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="soc-num">{formatScore(finding.risk_score)}</td>
                    <td className="max-w-[26rem]">
                      <p className="truncate font-medium text-slate-100" title={finding.title}>
                        {finding.title}
                      </p>
                      <p className="truncate font-mono text-2xs text-slate-500">
                        {finding.rule_id} · {finding.rule_name}
                      </p>
                    </td>
                    <td>
                      <span
                        className={clsx(
                          'rounded border px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide',
                          FINDING_STATUS_CLASSES[finding.status],
                        )}
                      >
                        {FINDING_STATUS_LABELS[finding.status]}
                      </span>
                    </td>
                    <td className="soc-num">{formatNumber(finding.count)}</td>
                    <td className="whitespace-nowrap text-2xs text-slate-400">{formatDateTime(finding.last_seen)}</td>
                    <td className="max-w-[14rem]">
                      <span className="flex flex-wrap gap-1">
                        {finding.tags.slice(0, 4).map((tag) => (
                          <span key={tag} className="soc-code-inline">
                            {tag}
                          </span>
                        ))}
                        {finding.tags.length > 4 ? (
                          <span className="text-2xs text-slate-500">+{finding.tags.length - 4}</span>
                        ) : null}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <nav className="mt-2 flex flex-wrap items-center justify-between gap-2" aria-label="Pagination des findings">
        <p className="text-2xs text-slate-400">
          Page {cursorStack.length}
          {total !== null ? ` · ${formatNumber(total)} finding(s) au total selon les filtres` : ''} · curseur{' '}
          <code className="soc-code-inline">{cursor === null ? 'initial' : cursor}</code>
        </p>
        <div className="flex gap-1.5">
          <Button
            size="sm"
            variant="secondary"
            disabled={!hasPrevious}
            onClick={() => setCursorStack((previous) => (previous.length > 1 ? previous.slice(0, -1) : previous))}
          >
            Précédent
          </Button>
          <Button
            size="sm"
            variant="secondary"
            disabled={!hasNext}
            onClick={() =>
              setCursorStack((previous) => [...previous, nextCursor])
            }
          >
            Suivant
          </Button>
        </div>
      </nav>
    </Panel>
  );
}

interface SortableHeaderProps {
  label: string;
  onClick: () => void;
  indicator: string;
  align?: 'left' | 'right';
}

function SortableHeader(props: SortableHeaderProps): JSX.Element {
  const { label, onClick, indicator, align = 'left' } = props;
  return (
    <th scope="col" className={align === 'right' ? 'text-right' : undefined}>
      <button type="button" onClick={onClick} className="inline-flex items-center gap-1 hover:text-slate-100">
        {label}
        <span aria-hidden="true" className="text-cyan-400">
          {indicator}
        </span>
      </button>
    </th>
  );
}
