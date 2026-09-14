/**
 * Journal d'audit (`GET /api/v1/audit`, `GET /api/v1/audit/verify`,
 * `GET /api/v1/audit/export`, contrat §4.7).
 *
 * Le journal est **append-only** et chaîné par hash (contrat §3.5) : chaque
 * enregistrement porte `prev_hash` et `hash`. Le bouton « Vérifier l'intégrité »
 * appelle `/audit/verify` et affiche le verdict — **en rouge lorsqu'il est
 * invalide**, avec le numéro de séquence de la première rupture (`broken_at`).
 * Un audit corrompu est un incident de sécurité : il ne doit jamais pouvoir
 * passer pour un simple avertissement discret.
 *
 * L'export (jsonl / cef) est téléchargé comme fichier : le contenu n'est jamais
 * rendu dans le document.
 */
import { useMutation, useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { useMemo, useState } from 'react';
import type { JSX } from 'react';

import { usePeriod } from './AppShell';
import { EmptyState } from './EmptyState';
import {
  Button,
  CodeBlock,
  ErrorNotice,
  Field,
  InlineNotice,
  LoadingBlock,
  Panel,
  StatusPill,
  TextInput,
} from './ui';
import { useAuth } from '@/lib/auth';
import { errorMessage } from '@/lib/api';
import { auditExportFileName, auditMimeType, downloadText } from '@/lib/download';
import { abbreviateHash, formatDateTime, formatNumber } from '@/lib/format';
import type { AuditExportFormat, AuditRecord, AuditVerifyResult } from '@/lib/types';
import { AUDIT_EXPORT_FORMATS } from '@/lib/types';

export const AUDIT_PAGE_SIZE = 100;

export interface AuditLogProps {
  className?: string;
}

export function AuditLog(props: AuditLogProps): JSX.Element {
  const { className } = props;
  const { client, queryScope, can } = useAuth();
  const { since, sinceLabel } = usePeriod();
  const canRead = can('read:audit');

  const [actionDraft, setActionDraft] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [actorDraft, setActorDraft] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);

  const cursor = cursorStack.length > 0 ? cursorStack[cursorStack.length - 1] ?? null : null;

  const query = useQuery({
    queryKey: ['audit', queryScope, { actionFilter, actorFilter, since, cursor }],
    queryFn: ({ signal }) =>
      client.listAudit(
        {
          since,
          action: actionFilter === '' ? undefined : actionFilter,
          actor: actorFilter === '' ? undefined : actorFilter,
          limit: AUDIT_PAGE_SIZE,
          cursor: cursor ?? undefined,
        },
        { signal },
      ),
    enabled: canRead,
  });

  const verifyMutation = useMutation<AuditVerifyResult, unknown, void>({
    mutationFn: () => client.verifyAudit(),
  });

  const exportMutation = useMutation<string, unknown, AuditExportFormat>({
    mutationFn: (format: AuditExportFormat) => client.auditExport(format),
    onSuccess: (content, format) => {
      downloadText(content, auditExportFileName(format), auditMimeType(format));
    },
  });

  // Tableau stable entre deux rendus : sans ce `useMemo`, le repli `[]`
  // construirait un nouveau tableau à chaque rendu, et les `useMemo` qui en dépendent
  // se recalculeraient tous autant de fois.
  const records = useMemo(() => query.data?.items ?? [], [query.data]);
  const nextCursor = query.data?.next_cursor ?? null;
  const hasNext = typeof nextCursor === 'string' && nextCursor !== '';
  const hasPrevious = cursorStack.length > 1;

  const verdict = verifyMutation.data ?? null;
  const exportError = exportMutation.error ? errorMessage(exportMutation.error) : null;

  /** Nombre de ruptures visibles dans la page courante (chaînage local). */
  const brokenLinks = useMemo(() => {
    const sorted = [...records].sort((left, right) => left.seq - right.seq);
    let count = 0;
    for (let index = 1; index < sorted.length; index += 1) {
      const current = sorted[index];
      const previous = sorted[index - 1];
      if (!current || !previous) continue;
      if (current.prev_hash !== previous.hash) count += 1;
    }
    return count;
  }, [records]);

  const resetPagination = (): void => setCursorStack([null]);

  if (!canRead) {
    return (
      <div className={className}>
        <EmptyState
          variant="locked"
          title="Journal d’audit masqué — capacité « read:audit » requise"
          description="Le journal chaîné contient les décisions et actions de tous les acteurs du tenant. Sa lecture est réservée aux clés disposant de read:audit."
        />
      </div>
    );
  }

  return (
    <Panel
      className={className}
      title="Journal d’audit (chaîné par hash)"
      description={`Depuis ${sinceLabel} · page de ${AUDIT_PAGE_SIZE} · un enregistrement n’est jamais modifié ni supprimé (append-only)`}
      actions={
        <>
          <Button size="sm" variant="secondary" busy={query.isFetching} onClick={() => void query.refetch()}>
            Rafraîchir
          </Button>
          <Button
            size="sm"
            variant="primary"
            busy={verifyMutation.isPending}
            onClick={() => verifyMutation.mutate(undefined)}
            title="Recalcule la chaîne de hash côté serveur et détecte toute falsification."
          >
            Vérifier l’intégrité
          </Button>
        </>
      }
    >
      {verifyMutation.error ? (
        <ErrorNotice
          className="mb-2"
          error={verifyMutation.error}
          title="Vérification impossible"
          onRetry={() => verifyMutation.mutate(undefined)}
        />
      ) : null}

      {verdict ? (
        verdict.valid ? (
          <InlineNotice tone="success" className="mb-2" title="Chaîne d’audit intègre">
            <p>
              {formatNumber(verdict.records)} enregistrement(s) vérifié(s) : chaque `hash` correspond au calcul
              sha256(seq|ts|tenant|acteur|rôle|action|target|before|after|prev_hash) et chaque `prev_hash` référence
              l’enregistrement précédent.
            </p>
          </InlineNotice>
        ) : (
          <InlineNotice tone="danger" className="mb-2" title="⚠ Intégrité de l’audit INVALIDE">
            <p className="font-semibold">
              La chaîne de hash est rompue
              {verdict.broken_at === null ? '' : ` à la séquence #${verdict.broken_at}`} — sur{' '}
              {formatNumber(verdict.records)} enregistrement(s) vérifié(s).
            </p>
            <p>
              Un journal d’audit dont l’intégrité est invalide signale une falsification, une restauration partielle
              ou une corruption de la base. Traitez-le comme un incident de sécurité : conservez une copie de la
              base, comparez avec l’export SIEM et n’exécutez pas d’action d’automatisation tant que la cause n’est
              pas établie.
            </p>
          </InlineNotice>
        )
      ) : null}

      {brokenLinks > 0 ? (
        <InlineNotice tone="danger" className="mb-2" title="Ruptures de chaînage détectées dans cette page">
          {formatNumber(brokenLinks)} lien(s) incohérent(s) entre enregistrements consécutifs de cette page. Cela
          peut aussi provenir d’un filtrage (les enregistrements intermédiaires ne sont pas affichés) : lancez «
          Vérifier l’intégrité » pour un verdict faisant autorité.
        </InlineNotice>
      ) : null}

      <div className="flex flex-wrap items-end gap-2">
        <Field label="Action" className="w-56">
          <div className="flex gap-1">
            <TextInput
              value={actionDraft}
              placeholder="ex. action.approve"
              onChange={(event) => setActionDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  setActionFilter(actionDraft.trim());
                  resetPagination();
                }
              }}
            />
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                setActionFilter(actionDraft.trim());
                resetPagination();
              }}
            >
              OK
            </Button>
          </div>
        </Field>

        <Field label="Acteur" className="w-56">
          <div className="flex gap-1">
            <TextInput
              value={actorDraft}
              placeholder="ex. api-key:ci"
              onChange={(event) => setActorDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  setActorFilter(actorDraft.trim());
                  resetPagination();
                }
              }}
            />
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                setActorFilter(actorDraft.trim());
                resetPagination();
              }}
            >
              OK
            </Button>
          </div>
        </Field>

        {actionFilter !== '' || actorFilter !== '' ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setActionFilter('');
              setActorFilter('');
              setActionDraft('');
              setActorDraft('');
              resetPagination();
            }}
          >
            Réinitialiser les filtres ✕
          </Button>
        ) : null}

        <div className="ml-auto flex flex-wrap items-end gap-1.5">
          {AUDIT_EXPORT_FORMATS.map((format) => (
            <Button
              key={format}
              size="sm"
              variant="secondary"
              busy={exportMutation.isPending && exportMutation.variables === format}
              onClick={() => exportMutation.mutate(format)}
              title={
                format === 'jsonl'
                  ? 'Export JSON Lines pour SIEM (un enregistrement par ligne)'
                  : 'Export CEF (ArcSight Common Event Format)'
              }
            >
              Exporter {format.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>

      {exportError ? <ErrorNotice className="mt-2" error={exportError} title="Export impossible" /> : null}

      {query.error ? (
        <ErrorNotice
          className="mt-2"
          error={query.error}
          title="Chargement du journal impossible"
          onRetry={() => void query.refetch()}
        />
      ) : null}

      <div className={clsx('mt-2', query.isFetching && 'opacity-60')}>
        {query.isLoading ? (
          <LoadingBlock label="Chargement du journal d’audit…" rows={6} />
        ) : records.length === 0 ? (
          <EmptyState
            title="Aucun enregistrement d’audit sur cette période"
            description="Élargissez la période dans la barre supérieure ou retirez les filtres action/acteur."
          />
        ) : (
          <div className="soc-table-wrap">
            <table className="soc-table">
              <caption>Un enregistrement d’audit est immuable : il décrit qui a fait quoi, avec l’état avant/après.</caption>
              <thead>
                <tr>
                  <th scope="col">Séq.</th>
                  <th scope="col">Horodatage</th>
                  <th scope="col">Acteur</th>
                  <th scope="col">Action</th>
                  <th scope="col">Cible</th>
                  <th scope="col">Transition</th>
                  <th scope="col">Hash</th>
                </tr>
              </thead>
              <tbody>
                {records.map((record) => (
                  <AuditRow
                    key={record.seq}
                    record={record}
                    expanded={expandedSeq === record.seq}
                    onToggle={() => setExpandedSeq((previous) => (previous === record.seq ? null : record.seq))}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <nav className="mt-2 flex flex-wrap items-center justify-between gap-2" aria-label="Pagination du journal d’audit">
        <p className="text-2xs text-slate-400">
          Page {cursorStack.length} · curseur <code className="soc-code-inline">{cursor === null ? 'initial' : cursor}</code>
          {query.data?.total !== null && query.data?.total !== undefined
            ? ` · ${formatNumber(query.data.total)} enregistrement(s)`
            : ''}
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
            onClick={() => setCursorStack((previous) => [...previous, nextCursor])}
          >
            Suivant
          </Button>
        </div>
      </nav>

      <p className="mt-2 text-2xs text-slate-500">
        En ligne de commande, la vérification équivaut à <code className="soc-code-inline">thotsecure audit verify</code>{' '}
        dont le code de sortie vaut 3 lorsque la vérification est négative (contrat §8).
      </p>
    </Panel>
  );
}

interface AuditRowProps {
  record: AuditRecord;
  expanded: boolean;
  onToggle: () => void;
}

function AuditRow(props: AuditRowProps): JSX.Element {
  const { record, expanded, onToggle } = props;

  const describe = (payload: Record<string, unknown> | null): string => {
    if (payload === null) return '—';
    const entries = Object.entries(payload);
    if (entries.length === 0) return '{}';
    return entries
      .slice(0, 3)
      .map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value) ?? ''}`)
      .join(' · ');
  };

  return (
    <>
      <tr className="cursor-pointer" onClick={onToggle} data-selected={expanded}>
        <td className="soc-num text-2xs text-slate-400">#{record.seq}</td>
        <td className="whitespace-nowrap text-2xs text-slate-400">{formatDateTime(record.ts)}</td>
        <td className="text-2xs">
          <span className="font-mono">{record.actor}</span>
          <p className="text-slate-500">{record.actor_role}</p>
        </td>
        <td className="font-mono text-2xs text-cyan-200">{record.action}</td>
        <td className="soc-mono">
          {record.target.type}
          <span className="ml-1 text-slate-500">{record.target.id}</span>
        </td>
        <td className="max-w-[22rem] text-2xs text-slate-400">
          <span className="block truncate" title={describe({ ...(record.before ?? {}) })}>
            avant : {describe({ ...(record.before ?? {}) })}
          </span>
          <span className="block truncate text-slate-300" title={describe({ ...(record.after ?? {}) })}>
            après : {describe({ ...(record.after ?? {}) })}
          </span>
        </td>
        <td className="font-mono text-2xs text-slate-400" title={`hash=${record.hash}\nprev_hash=${record.prev_hash}`}>
          {abbreviateHash(record.hash, 6)}
          <p className="text-slate-600">← {abbreviateHash(record.prev_hash, 4)}</p>
        </td>
      </tr>
      {expanded ? (
        <tr>
          <td colSpan={7} className="bg-slate-950/60">
            <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
              <div>
                <p className="text-2xs uppercase tracking-wider text-slate-500">État avant</p>
                <CodeBlock className="mt-1" value={record.before} maxHeight={160} />
              </div>
              <div>
                <p className="text-2xs uppercase tracking-wider text-slate-500">État après</p>
                <CodeBlock className="mt-1" value={record.after} maxHeight={160} />
              </div>
            </div>
            <div className="mt-2 space-y-0.5">
              <p className="break-all font-mono text-2xs text-slate-400">hash = {record.hash}</p>
              <p className="break-all font-mono text-2xs text-slate-400">prev_hash = {record.prev_hash}</p>
            </div>
            <StatusPill
              className="mt-2 border-slate-700 bg-slate-800/70 text-slate-300"
              label={`tenant ${record.tenant_id}`}
              title="Le périmètre de la clé API borne l’affichage : une ligne d’un autre tenant ferait échouer la requête (fail closed)."
            />
            <p className="mt-1 text-2xs text-slate-500" onClick={onToggle}>
              Cliquez sur la ligne pour replier.
            </p>
          </td>
        </tr>
      ) : null}
    </>
  );
}
