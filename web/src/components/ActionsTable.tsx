/**
 * Table des actions SOAR (`GET /api/v1/actions`, contrat §4.6).
 *
 * Fonctions : filtres (statut, playbook), pagination par curseur, approbation,
 * rejet, exécution et rollback — chaque mutation passant par
 * `ActionApprovalDialog` (double confirmation explicite).
 *
 * Sûreté :
 *  - **bandeau `dry_run` permanent** : dès qu'une action listée est en dry-run, ou
 *    que le garde-fou global (`whoami.dry_run`) est actif, un avertissement est
 *    affiché en tête de panneau. Un opérateur ne doit jamais confondre une
 *    simulation avec une contre-mesure réelle ;
 *  - l'exécution n'est proposée que sur une action `planned` ou `approved` : le
 *    serveur refuse `pending_approval` non approuvée (409) et l'interface ne doit
 *    pas inviter à un appel voué à l'échec ;
 *  - le rollback n'est proposé que si le serveur l'annonce disponible
 *    (`rollback.available`, contrat §3.4) ;
 *  - chaque bouton est masqué si la capacité requise manque
 *    (`approve:actions` / `execute:actions`).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Fragment, useEffect, useMemo, useState } from 'react';
import type { JSX } from 'react';

import { ActionApprovalDialog } from './ActionApprovalDialog';
import type { ActionOperation } from './ActionApprovalDialog';
import { EmptyState } from './EmptyState';
import {
  Button,
  CodeBlock,
  ErrorNotice,
  Field,
  InlineNotice,
  LoadingBlock,
  Panel,
  Select,
  StatusPill,
  TextInput,
} from './ui';
import { useAuth } from '@/lib/auth';
import { errorMessage } from '@/lib/api';
import {
  ACTION_STATUS_CLASSES,
  ACTION_STATUS_LABELS,
  AUTONOMY_LABELS,
  formatDateTime,
  formatNumber,
  formatRelative,
  isActionTerminal,
} from '@/lib/format';
import type { Action, ActionStatus } from '@/lib/types';
import { ACTION_STATUSES } from '@/lib/types';

export const ACTIONS_PAGE_SIZE = 50;

export interface ActionsTableProps {
  className?: string;
}

/**
 * Horloge de rendu, mise à jour par intervalle.
 *
 * `Date.now()` **pendant le rendu** est impur : le résultat change sans qu'aucune prop ni aucun
 * état n'ait bougé, donc React ne peut ni mémoïser ni comparer deux rendus de façon fiable —
 * c'est ce que la règle `react-hooks/purity` du compilateur React refuse, à juste titre.
 *
 * Conséquence secondaire agréable : la mention « expiré » se rafraîchit toute seule, au lieu de
 * rester figée jusqu'au prochain chargement de la liste.
 */
function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

export function ActionsTable(props: ActionsTableProps): JSX.Element {
  const { className } = props;
  const { client, queryScope, dryRun, can } = useAuth();
  const queryClient = useQueryClient();
  const canRead = can('read:findings');
  const canApprove = can('approve:actions');
  const canExecute = can('execute:actions');

  const [status, setStatus] = useState<ActionStatus | ''>('pending_approval');
  const [playbookDraft, setPlaybookDraft] = useState('');
  const [playbook, setPlaybook] = useState('');
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [pending, setPending] = useState<{ operation: ActionOperation; action: Action } | null>(null);

  const cursor = cursorStack.length > 0 ? cursorStack[cursorStack.length - 1] ?? null : null;

  const query = useQuery({
    queryKey: ['actions', queryScope, { status, playbook, cursor }],
    queryFn: ({ signal }) =>
      client.listActions(
        {
          status,
          playbook: playbook === '' ? undefined : playbook,
          limit: ACTIONS_PAGE_SIZE,
          cursor: cursor ?? undefined,
        },
        { signal },
      ),
    enabled: canRead,
  });

  // Tableau stable entre deux rendus : sans ce `useMemo`, le repli `[]`
  // construirait un nouveau tableau à chaque rendu, et les `useMemo` qui en dépendent
  // se recalculeraient tous autant de fois.
  const now = useNow();
  const items = useMemo(() => query.data?.items ?? [], [query.data]);
  const nextCursor = query.data?.next_cursor ?? null;
  const hasNext = typeof nextCursor === 'string' && nextCursor !== '';
  const hasPrevious = cursorStack.length > 1;

  const mutation = useMutation({
    mutationFn: (payload: { operation: ActionOperation; actionId: string; comment: string }): Promise<Action> => {
      switch (payload.operation) {
        case 'approve':
          return client.approveAction(payload.actionId, { comment: payload.comment });
        case 'reject':
          return client.rejectAction(payload.actionId, { reason: payload.comment });
        case 'execute':
          return client.executeAction(payload.actionId);
        case 'rollback':
          return client.rollbackAction(payload.actionId);
        default:
          throw new Error(`Opération d’action inconnue : ${String(payload.operation)}`);
      }
    },
    onSuccess: () => {
      setPending(null);
      void queryClient.invalidateQueries({ queryKey: ['actions'] });
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      void queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const dryRunActionCount = useMemo(() => items.filter((action) => action.dry_run).length, [items]);
  const showDryRunBanner = dryRun || dryRunActionCount > 0;

  const resetPagination = (): void => setCursorStack([null]);

  if (!canRead) {
    return (
      <div className={className}>
        <EmptyState
          variant="locked"
          title="Actions masquées — capacité « read:findings » requise"
          description="Le contrat §4.6 protège la lecture des actions par la capacité read:findings. Votre clé API ne la possède pas."
        />
      </div>
    );
  }

  return (
    <Panel
      className={className}
      title="Actions SOAR"
      description={`Statuts : ${ACTION_STATUSES.map((value) => ACTION_STATUS_LABELS[value]).join(' · ')}`}
      actions={
        <Button size="sm" variant="secondary" busy={query.isFetching} onClick={() => void query.refetch()}>
          Rafraîchir
        </Button>
      }
    >
      {showDryRunBanner ? (
        <InlineNotice tone="warn" className="mb-2" title="Mode dry-run actif — aucune contre-mesure réelle">
          <p>
            {dryRun
              ? 'THOT_DRY_RUN=true : le garde-fou global prime sur toute politique et sur toute demande d’exécution (contrat §6, garde-fou 4). '
              : ''}
            {dryRunActionCount > 0
              ? `${formatNumber(dryRunActionCount)} action(s) de cette page ont été planifiées avec dry_run = true : les connecteurs sont simulés et retournent un jeton de rollback sans effet.`
              : ''}
          </p>
          <p>
            Vérifiez le connecteur configuré (contrat §7) avant toute levée de garde-fou : la levée doit être tracée,
            revue et limitée à un tenant.
          </p>
        </InlineNotice>
      ) : (
        <InlineNotice tone="danger" className="mb-2" title="Exécution réelle armée (dry_run = false)">
          Les playbooks agissent réellement sur les cibles. Toute exécution exige ici une double confirmation
          explicite et reste journalisée dans l’audit chaîné.
        </InlineNotice>
      )}

      <div className="flex flex-wrap items-end gap-2">
        <Field label="Statut" className="w-48">
          <Select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value as ActionStatus | '');
              resetPagination();
            }}
          >
            <option value="">Tous</option>
            {ACTION_STATUSES.map((value) => (
              <option key={value} value={value}>
                {ACTION_STATUS_LABELS[value]}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Playbook" className="w-56">
          <div className="flex gap-1">
            <TextInput
              value={playbookDraft}
              placeholder="ex. block-source-ip"
              onChange={(event) => setPlaybookDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  setPlaybook(playbookDraft.trim());
                  resetPagination();
                }
              }}
            />
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                setPlaybook(playbookDraft.trim());
                resetPagination();
              }}
            >
              Filtrer
            </Button>
          </div>
        </Field>

        {playbook !== '' ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setPlaybook('');
              setPlaybookDraft('');
              resetPagination();
            }}
          >
            Playbook « {playbook} » ✕
          </Button>
        ) : null}
      </div>

      {query.error ? (
        <ErrorNotice
          className="mt-2"
          error={query.error}
          title="Chargement des actions impossible"
          onRetry={() => void query.refetch()}
        />
      ) : null}

      <div className={clsx('mt-2', query.isFetching && 'opacity-60')}>
        {query.isLoading ? (
          <LoadingBlock label="Chargement des actions…" rows={5} />
        ) : items.length === 0 ? (
          <EmptyState
            title="Aucune action pour ces critères"
            description="Les actions sont créées par le moteur de décision (politique matching) ou planifiées explicitement. Aucune action en attente n’est une bonne nouvelle."
          />
        ) : (
          <div className="soc-table-wrap">
            <table className="soc-table">
              <caption>
                Page de {ACTIONS_PAGE_SIZE} ·{' '}
                {canApprove || canExecute
                  ? 'les opérations disponibles dépendent du statut de l’action et de vos capacités.'
                  : 'aucune opération affichée : votre rôle ne dispose ni de approve:actions ni de execute:actions.'}
              </caption>
              <thead>
                <tr>
                  <th scope="col">Playbook</th>
                  <th scope="col">Cible</th>
                  <th scope="col">Statut</th>
                  <th scope="col">Mode</th>
                  <th scope="col">Policy</th>
                  <th scope="col">Demandée</th>
                  <th scope="col">Expiration</th>
                  <th scope="col">Audit</th>
                  <th scope="col">Opérations</th>
                </tr>
              </thead>
              <tbody>
                {items.map((action) => {
                  const expired =
                    action.expires_at !== null && new Date(action.expires_at).getTime() < now;
                  const terminal = isActionTerminal(action.status);
                  const showApprove = canApprove && action.status === 'pending_approval';
                  const showExecute = canExecute && (action.status === 'planned' || action.status === 'approved');
                  const showRollback =
                    canExecute && action.status === 'succeeded' && action.rollback.available;
                  const showReject = canApprove && action.status === 'pending_approval';

                  return (
                    <Fragment key={action.action_id}>
                      <tr
                        data-selected={expandedId === action.action_id}
                        data-tone={action.dry_run ? undefined : 'warn'}
                      >
                        <td>
                          <button
                            type="button"
                            className="text-left font-mono text-2xs text-cyan-200 hover:underline"
                            aria-expanded={expandedId === action.action_id}
                            onClick={() =>
                              setExpandedId((previous) =>
                                previous === action.action_id ? null : action.action_id,
                              )
                            }
                          >
                            {action.playbook}
                          </button>
                          <p className="font-mono text-2xs text-slate-500">{action.action_id}</p>
                        </td>
                        <td className="soc-mono">
                          {action.target.value}
                          <span className="ml-1 text-slate-500">({action.target.type})</span>
                        </td>
                        <td>
                          <StatusPill
                            label={ACTION_STATUS_LABELS[action.status]}
                            className={ACTION_STATUS_CLASSES[action.status]}
                          />
                          {terminal ? <p className="mt-0.5 text-2xs text-slate-500">terminal</p> : null}
                        </td>
                        <td className="text-2xs">
                          {AUTONOMY_LABELS[action.mode]}
                          <p className={clsx('text-2xs', action.dry_run ? 'text-amber-300' : 'text-rose-300')}>
                            {action.dry_run ? 'dry-run' : 'réel'}
                          </p>
                        </td>
                        <td className="font-mono text-2xs text-slate-400">{action.policy_id}</td>
                        <td className="whitespace-nowrap text-2xs text-slate-400">
                          {formatDateTime(action.requested_at)}
                          <p className="text-slate-500">{action.requested_by}</p>
                        </td>
                        <td className={clsx('whitespace-nowrap text-2xs', expired ? 'text-rose-300' : 'text-slate-400')}>
                          {action.expires_at ? formatDateTime(action.expires_at) : '—'}
                          {action.expires_at ? <p className="text-slate-500">{formatRelative(action.expires_at)}</p> : null}
                        </td>
                        <td className="soc-num text-2xs text-slate-400">
                          {action.audit_seq === null ? '—' : `#${action.audit_seq}`}
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {showApprove ? (
                              <Button
                                size="sm"
                                variant="primary"
                                onClick={() => setPending({ operation: 'approve', action })}
                              >
                                Approuver
                              </Button>
                            ) : null}
                            {showReject ? (
                              <Button
                                size="sm"
                                variant="danger"
                                onClick={() => setPending({ operation: 'reject', action })}
                              >
                                Rejeter
                              </Button>
                            ) : null}
                            {showExecute ? (
                              <Button
                                size="sm"
                                variant="warn"
                                title={
                                  action.dry_run
                                    ? 'Simulation : connecteur en mode dry-run'
                                    : 'Exécution réelle sur la cible'
                                }
                                onClick={() => setPending({ operation: 'execute', action })}
                              >
                                Exécuter
                              </Button>
                            ) : null}
                            {showRollback ? (
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={() => setPending({ operation: 'rollback', action })}
                              >
                                Rollback
                              </Button>
                            ) : null}
                            {!showApprove && !showExecute && !showRollback ? (
                              <span className="text-2xs text-slate-500">
                                {terminal ? 'aucune (statut terminal)' : 'selon capacité / statut'}
                              </span>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                      {expandedId === action.action_id ? (
                        <tr>
                          <td colSpan={9} className="bg-slate-950/60">
                            <div className="grid grid-cols-1 gap-2 lg:grid-cols-3">
                              <div>
                                <p className="text-2xs uppercase tracking-wider text-slate-500">Paramètres</p>
                                <CodeBlock className="mt-1" value={action.params} maxHeight={160} />
                              </div>
                              <div>
                                <p className="text-2xs uppercase tracking-wider text-slate-500">Résultat</p>
                                <CodeBlock className="mt-1" value={action.result} maxHeight={160} />
                              </div>
                              <div className="space-y-1 text-2xs text-slate-400">
                                <p className="text-2xs uppercase tracking-wider text-slate-500">Rollback</p>
                                <p>
                                  Disponible : {action.rollback.available ? 'oui' : 'non'}
                                  {action.rollback.token !== null ? ' · jeton émis' : ''}
                                </p>
                                <p>Exécuté le : {formatDateTime(action.executed_at)}</p>
                                <p>Approuvé par : {action.approved_by ?? '—'}</p>
                                <p>Clé d’idempotence :</p>
                                <p className="break-all font-mono">{action.idempotency_key}</p>
                                <p>
                                  Rollback effectué :{' '}
                                  {action.rollback.performed_at === null
                                    ? '—'
                                    : `${formatDateTime(action.rollback.performed_at)}`}
                                </p>
                              </div>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <nav className="mt-2 flex flex-wrap items-center justify-between gap-2" aria-label="Pagination des actions">
        <p className="text-2xs text-slate-400">
          Page {cursorStack.length} · curseur <code className="soc-code-inline">{cursor === null ? 'initial' : cursor}</code>
          {mutation.isError ? ` · dernière erreur : ${errorMessage(mutation.error)}` : ''}
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
        Rappels du contrat : l’exécution est refusée sur une action en attente d’approbation non approuvée (409), le
        rollback est refusé si l’action est déjà annulée (409), et les plafonds `max_actions_per_hour` / `cooldown`
        sont appliqués par le moteur de décision, non par cette interface.
        {canExecute ? '' : ' Votre rôle ne peut ni exécuter ni annuler une action.'}
      </p>

      <ActionApprovalDialog
        open={pending !== null}
        operation={pending?.operation ?? 'approve'}
        action={pending?.action ?? null}
        dryRunGlobal={dryRun}
        busy={mutation.isPending}
        error={pending !== null && mutation.error ? errorMessage(mutation.error) : null}
        onCancel={() => {
          mutation.reset();
          setPending(null);
        }}
        onConfirm={(payload) => mutation.mutate(payload)}
      />

      <p className="mt-2 text-2xs text-slate-500">
        Durée d’approbation par défaut du produit : <code className="soc-code-inline">THOT_APPROVE_TTL_SECONDS</code> = 1
        heure — au-delà, une approbation en attente expire côté serveur et l’action devra être replanifiée.
      </p>
    </Panel>
  );
}
