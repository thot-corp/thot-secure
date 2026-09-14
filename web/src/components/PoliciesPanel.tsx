/**
 * Politiques de décision policy-as-code (`GET /api/v1/policies`,
 * `POST /api/v1/policies/reload`, contrat §4.5 et §6).
 *
 * Lecture : `read:policies`. Rechargement : `admin:policies` (masqué sinon).
 *
 * Ce panneau rend visible ce qui décide à la place de l'humain :
 *  - l'ordre d'évaluation est celui de `priority` (**décroissante**, la plus
 *    grande d'abord) ;
 *  - une politique qui déclare `decision: auto` **et** `dry_run: false` exécute
 *    des contre-mesures sans approbation humaine : elle est signalée en rouge ;
 *  - les garde-fous d'exécution du contrat §6 (plafond horaire, cooldown,
 *    allowlist, priorité du dry-run global, cibles hors périmètre) sont rappelés
 *    ici, car ils ne sont **pas** contournables par une politique.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { useMemo, useState } from 'react';
import type { JSX } from 'react';

import { EmptyState } from './EmptyState';
import {
  Button,
  CodeBlock,
  ConfirmDialog,
  ErrorNotice,
  InlineNotice,
  KeyValueList,
  LoadingBlock,
  Panel,
  StatusPill,
} from './ui';
import { useAuth } from '@/lib/auth';
import { errorMessage } from '@/lib/api';
import { DECISION_CLASSES, DECISION_LABELS, formatDuration, formatNumber } from '@/lib/format';
import type { PolicyRecord } from '@/lib/types';

export interface PoliciesPanelProps {
  className?: string;
}

export function PoliciesPanel(props: PoliciesPanelProps): JSX.Element {
  const { className } = props;
  const { client, queryScope, can } = useAuth();
  const queryClient = useQueryClient();
  const canRead = can('read:policies');
  const canAdmin = can('admin:policies');

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [reloadOpen, setReloadOpen] = useState(false);

  const query = useQuery({
    queryKey: ['policies', queryScope],
    queryFn: ({ signal }) => client.listPolicies({ signal }),
    enabled: canRead,
  });

  const reloadMutation = useMutation({
    mutationFn: () => client.reloadPolicies(),
    onSuccess: () => {
      setReloadOpen(false);
      void queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
  });

  // Tableau stable entre deux rendus : sans ce `useMemo`, le repli `[]`
  // construirait un nouveau tableau à chaque rendu, et les `useMemo` qui en dépendent
  // se recalculeraient tous autant de fois.
  const policies = useMemo(() => query.data?.items ?? [], [query.data]);

  const ordered = useMemo(
    () => [...policies].sort((left, right) => right.priority - left.priority),
    [policies],
  );

  const unguarded = useMemo(
    () =>
      ordered.filter(
        (policy) => policy.then.decision === 'auto' && policy.then.dry_run !== true,
      ),
    [ordered],
  );

  if (!canRead) {
    return (
      <div className={className}>
        <EmptyState
          variant="locked"
          title="Politiques masquées — capacité « read:policies » requise"
          description="Les politiques contiennent la logique de décision du tenant ; leur lecture exige la capacité read:policies."
        />
      </div>
    );
  }

  return (
    <div className={clsx('space-y-3', className)}>
      <Panel
        title="Politiques de décision (policy-as-code)"
        description={`${formatNumber(ordered.length)} politique(s) chargée(s) · évaluation par priority décroissante · sans politique correspondante, la décision est notify_only (contrat §6)`}
        actions={
          <>
            <Button size="sm" variant="secondary" busy={query.isFetching} onClick={() => void query.refetch()}>
              Rafraîchir
            </Button>
            {canAdmin ? (
              <Button size="sm" variant="warn" onClick={() => setReloadOpen(true)}>
                Recharger les politiques
              </Button>
            ) : null}
          </>
        }
      >
        {unguarded.length > 0 ? (
          <InlineNotice tone="danger" className="mb-2" title="Exécution automatique hors dry-run détectée">
            <p>
              {formatNumber(unguarded.length)} politique(s) déclarent <code className="soc-code-inline">decision: auto</code>{' '}
              avec <code className="soc-code-inline">dry_run: false</code> : elles peuvent déclencher des
              contre-mesures réelles <strong>sans approbation humaine</strong>.
            </p>
            <ul className="list-inside list-disc space-y-0.5">
              {unguarded.map((policy) => (
                <li key={policy.id}>
                  <code className="soc-code-inline">{policy.id}</code>
                  {policy.then.playbook !== undefined && policy.then.playbook !== null
                    ? ` → playbook ${policy.then.playbook}`
                    : ''}
                </li>
              ))}
            </ul>
            <p>
              Le garde-fou global <code className="soc-code-inline">THOT_DRY_RUN=true</code> reste prioritaire sur
              toute politique (contrat §6, garde-fou 4) : vérifiez-le avec <code className="soc-code-inline">whoami</code>{' '}
              avant de considérer ces politiques comme réellement armées.
            </p>
          </InlineNotice>
        ) : null}

        {query.error ? (
          <ErrorNotice
            className="mb-2"
            error={query.error}
            title="Chargement des politiques impossible"
            onRetry={() => void query.refetch()}
          />
        ) : null}

        <div className={clsx(query.isFetching && 'opacity-60')}>
          {query.isLoading ? (
            <LoadingBlock label="Chargement des politiques…" rows={4} />
          ) : ordered.length === 0 ? (
            <EmptyState
              title="Aucune politique chargée"
              description="Sans politique correspondante, le moteur de décision retient notify_only : rien n’est exécuté automatiquement. Vérifiez THOT_POLICIES_DIR côté serveur."
            />
          ) : (
            <div className="soc-table-wrap">
              <table className="soc-table">
                <caption>
                  La priorité la plus élevée est évaluée en premier ; la première politique qui correspond décide.
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Priorité</th>
                    <th scope="col">Identifiant</th>
                    <th scope="col">Décision</th>
                    <th scope="col">Playbook</th>
                    <th scope="col">Dry-run</th>
                    <th scope="col">Cooldown</th>
                    <th scope="col">Plafond / h</th>
                    <th scope="col">Description</th>
                    <th scope="col">Chemin</th>
                  </tr>
                </thead>
                <tbody>
                  {ordered.map((policy) => (
                    <PolicyRow
                      key={policy.id}
                      policy={policy}
                      expanded={expandedId === policy.id}
                      onToggle={() => setExpandedId((previous) => (previous === policy.id ? null : policy.id))}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Garde-fous d’exécution (non contournables par une politique)">
        <ol className="list-inside list-decimal space-y-1 text-2xs text-slate-300">
          <li>
            Plafond <code className="soc-code-inline">max_actions_per_hour</code> par tenant (défaut 20,{' '}
            <code className="soc-code-inline">THOT_MAX_ACTIONS_PER_HOUR</code>).
          </li>
          <li>
            Cooldown par <code className="soc-code-inline">(tenant, playbook, cible)</code> — défaut{' '}
            {formatDuration(300)} (<code className="soc-code-inline">THOT_DEFAULT_COOLDOWN_SECONDS</code>).
          </li>
          <li>
            Aucune action sur une cible de l’<code className="soc-code-inline">autonomy_allowlist</code> (infra
            propre du tenant).
          </li>
          <li>
            <code className="soc-code-inline">dry_run</code> global prioritaire sur toute politique (
            <code className="soc-code-inline">THOT_DRY_RUN</code>).
          </li>
          <li>
            Toute cible hors périmètre déclaré (<code className="soc-code-inline">THOT_TARGETS_FILE</code>) impose{' '}
            <code className="soc-code-inline">require_approval</code>.
          </li>
        </ol>
        <p className="mt-2 text-2xs text-slate-500">
          Ces contrôles sont appliqués par le moteur de décision côté serveur. Cette interface ne peut ni les
          affaiblir ni les contourner : elle se contente de les rendre lisibles.
        </p>
      </Panel>

      <ConfirmDialog
        open={reloadOpen}
        title="Recharger les politiques"
        description="Le serveur relit THOT_POLICIES_DIR et remplace les politiques en mémoire. Une politique absente du répertoire cesse d’être appliquée : les décisions retomberont sur notify_only."
        tone="warn"
        confirmLabel="Recharger maintenant"
        acknowledgeLabel="Je confirme avoir vérifié les politiques sur disque et accepté l’effet immédiat du rechargement."
        details={
          <KeyValueList
            columns={1}
            items={[
              { label: 'Politiques chargées actuellement', value: formatNumber(ordered.length) },
              {
                label: 'Politiques en auto hors dry-run',
                value: formatNumber(unguarded.length),
              },
            ]}
          />
        }
        busy={reloadMutation.isPending}
        error={reloadMutation.error ? errorMessage(reloadMutation.error) : null}
        onCancel={() => {
          reloadMutation.reset();
          setReloadOpen(false);
        }}
        onConfirm={() => reloadMutation.mutate(undefined)}
      />

      {reloadMutation.data ? (
        <InlineNotice
          tone={reloadMutation.data.errors.length > 0 ? 'warn' : 'success'}
          title={`Rechargement terminé : ${formatNumber(reloadMutation.data.loaded)} politique(s) chargée(s)`}
        >
          {reloadMutation.data.errors.length === 0 ? (
            <p>Aucun diagnostic : toutes les politiques du répertoire se sont chargées.</p>
          ) : (
            <ul className="list-inside list-disc space-y-0.5">
              {reloadMutation.data.errors.map((error, index) => (
                <li key={index}>{error}</li>
              ))}
            </ul>
          )}
        </InlineNotice>
      ) : null}
    </div>
  );
}

interface PolicyRowProps {
  policy: PolicyRecord;
  expanded: boolean;
  onToggle: () => void;
}

function PolicyRow(props: PolicyRowProps): JSX.Element {
  const { policy, expanded, onToggle } = props;
  const { then: consequences, rollback } = policy;

  const dryRunLabel =
    consequences.dry_run === true ? 'oui (simulé)' : consequences.dry_run === false ? 'non (réel)' : 'hérité du tenant';

  return (
    <>
      <tr
        className="cursor-pointer"
        data-selected={expanded}
        data-tone={consequences.decision === 'auto' && consequences.dry_run === false ? 'danger' : undefined}
        onClick={onToggle}
      >
        <td className="soc-num text-2xs text-slate-300">{policy.priority}</td>
        <td className="font-mono text-2xs text-cyan-200">{policy.id}</td>
        <td>
          <StatusPill label={DECISION_LABELS[consequences.decision]} className={DECISION_CLASSES[consequences.decision]} />
        </td>
        <td className="font-mono text-2xs text-slate-300">{consequences.playbook ?? '—'}</td>
        <td className={clsx('text-2xs', consequences.dry_run === false ? 'text-rose-300' : 'text-amber-300')}>
          {dryRunLabel}
        </td>
        <td className="text-2xs text-slate-400">
          {consequences.cooldown_seconds === undefined ? '—' : formatDuration(consequences.cooldown_seconds)}
        </td>
        <td className="soc-num text-2xs text-slate-400">
          {consequences.max_actions_per_hour === undefined ? '—' : formatNumber(consequences.max_actions_per_hour)}
        </td>
        <td className="max-w-[22rem] truncate text-2xs text-slate-400" title={policy.description ?? undefined}>
          {policy.description ?? '—'}
        </td>
        <td className="soc-mono">{policy.path ?? '—'}</td>
      </tr>
      {expanded ? (
        <tr>
          <td colSpan={9} className="bg-slate-950/60">
            <div className="grid grid-cols-1 gap-2 lg:grid-cols-3">
              <div>
                <p className="text-2xs uppercase tracking-wider text-slate-500">
                  when — conditions (ET entre clés, OU dans une liste)
                </p>
                <CodeBlock className="mt-1" value={policy.when} maxHeight={220} />
              </div>
              <div>
                <p className="text-2xs uppercase tracking-wider text-slate-500">then — paramètres du playbook</p>
                <CodeBlock className="mt-1" value={consequences.params ?? {}} maxHeight={220} />
              </div>
              <div>
                <p className="text-2xs uppercase tracking-wider text-slate-500">rollback</p>
                <CodeBlock className="mt-1" value={rollback} maxHeight={220} />
              </div>
            </div>
            <KeyValueList
              className="mt-2"
              columns={3}
              items={[
                { label: 'Version', value: policy.version === null ? '—' : String(policy.version) },
                { label: 'Décision', value: DECISION_LABELS[consequences.decision] },
                {
                  label: 'Rollback automatique',
                  value:
                    rollback?.auto_after_seconds === undefined
                      ? 'non programmé'
                      : `après ${formatDuration(rollback.auto_after_seconds)}`,
                },
              ]}
            />
          </td>
        </tr>
      ) : null}
    </>
  );
}
