/**
 * Page « Collecteurs » : état des collecteurs défensifs et déclenchement d'un run
 * manuel (`GET /api/v1/collectors`, `POST /api/v1/collectors/{name}/run`).
 *
 * Sûreté : un run manuel peut générer du trafic vers des cibles. Il n'est donc
 * proposé qu'avec la capacité `execute:actions` et **après double confirmation**,
 * en rappelant que le serveur n'audite que les cibles déclarées du tenant
 * (`THOT_TARGETS_FILE`) — aucune capacité offensive n'existe dans le produit.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Fragment, useState } from 'react';
import type { JSX } from 'react';

import { EmptyState } from '@/components/EmptyState';
import {
  Button,
  ConfirmDialog,
  ErrorNotice,
  InlineNotice,
  KeyValueList,
  LoadingBlock,
  PageHeader,
  Panel,
  StatusPill,
} from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { errorMessage } from '@/lib/api';
import { formatDateTime, formatNumber, formatRelative } from '@/lib/format';
import type { CollectorRunResult, CollectorState } from '@/lib/types';

/** Intervalle de rafraîchissement de l'état des collecteurs. */
const COLLECTORS_REFETCH_MS = 30_000;

export function CollectorsPage(): JSX.Element {
  const { client, queryScope, can } = useAuth();
  const queryClient = useQueryClient();
  const canRead = can('read:stats');
  const canRun = can('execute:actions');

  const [pendingRun, setPendingRun] = useState<CollectorState | null>(null);
  const [expandedName, setExpandedName] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ['collectors', queryScope],
    queryFn: ({ signal }) => client.listCollectors({ signal }),
    enabled: canRead,
    refetchInterval: COLLECTORS_REFETCH_MS,
  });

  const runMutation = useMutation<CollectorRunResult, unknown, string>({
    mutationFn: (name: string) => client.runCollector(name),
    onSuccess: () => {
      setPendingRun(null);
      void queryClient.invalidateQueries({ queryKey: ['collectors'] });
      void queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const collectors = query.data?.items ?? [];
  const lastResult = runMutation.data ?? null;

  if (!canRead) {
    return (
      <div className="space-y-3">
        <PageHeader title="Collecteurs" description="État des collecteurs défensifs du tenant." />
        <EmptyState
          variant="locked"
          title="Collecteurs masqués — capacité « read:stats » requise"
          description="L’état des collecteurs est exposé sous la capacité read:stats (contrat §4.8)."
        />
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <PageHeader
        title="Collecteurs"
        description={`État des collecteurs défensifs (dernier run, items, erreurs) — rafraîchi toutes les ${Math.round(
          COLLECTORS_REFETCH_MS / 1_000,
        )} s. Le run manuel n’audite que les cibles déclarées du tenant.`}
        actions={
          <Button size="sm" variant="secondary" busy={query.isFetching} onClick={() => void query.refetch()}>
            Rafraîchir
          </Button>
        }
      />

      <InlineNotice tone="info" title="Périmètre des collecteurs">
        <p>
          Le produit est 100 % défensif : aucun collecteur ne réalise de scan agressif, d’exploitation ou de déni de
          service. L’audit de surface ne cible que les actifs déclarés dans{' '}
          <code className="soc-code-inline">THOT_TARGETS_FILE</code>, espacés par{' '}
          <code className="soc-code-inline">THOT_HTTP_PROBE_DELAY_SECONDS</code> (on n’inonde pas une cible).
        </p>
        <p>
          La planification automatique est désactivée par défaut (
          <code className="soc-code-inline">THOT_COLLECTORS_ENABLED=false</code>) : un run manuel reste possible
          depuis cette page.
        </p>
      </InlineNotice>

      {runMutation.error ? (
        <ErrorNotice error={runMutation.error} title="Exécution du collecteur impossible" />
      ) : null}

      {lastResult ? (
        <InlineNotice
          tone={lastResult.errors && lastResult.errors.length > 0 ? 'warn' : 'success'}
          title={`Run manuel « ${lastResult.collector} » — ${lastResult.status}`}
        >
          <KeyValueList
            columns={3}
            items={[
              { label: 'Items collectés', value: formatNumber(lastResult.items ?? 0) },
              { label: 'Findings créés', value: formatNumber(lastResult.findings ?? 0) },
              {
                label: 'Erreurs',
                value:
                  lastResult.errors === undefined || lastResult.errors.length === 0
                    ? 'aucune'
                    : lastResult.errors.join(' · '),
                wide: true,
              },
            ]}
          />
        </InlineNotice>
      ) : null}

      <Panel title="Collecteurs déclarés" description={`${formatNumber(collectors.length)} collecteur(s) connu(s) du serveur`}>
        {query.error ? (
          <ErrorNotice
            error={query.error}
            title="Chargement des collecteurs impossible"
            onRetry={() => void query.refetch()}
          />
        ) : query.isLoading ? (
          <LoadingBlock label="Chargement des collecteurs…" rows={4} />
        ) : collectors.length === 0 ? (
          <EmptyState
            title="Aucun collecteur déclaré"
            description="Les collecteurs se déclarent dans la configuration du serveur. Un run manuel ne peut viser qu’un collecteur connu."
          />
        ) : (
          <div className="soc-table-wrap">
            <table className="soc-table">
              <thead>
                <tr>
                  <th scope="col">Collecteur</th>
                  <th scope="col">Type</th>
                  <th scope="col">État</th>
                  <th scope="col">Dernier run</th>
                  <th scope="col">Statut</th>
                  <th scope="col">Items</th>
                  <th scope="col">Erreurs</th>
                  <th scope="col">Prochain run</th>
                  <th scope="col">Opérations</th>
                </tr>
              </thead>
              <tbody>
                {collectors.map((collector) => (
                  <Fragment key={collector.name}>
                    <tr>
                      <td className="font-mono text-2xs text-cyan-200">{collector.name}</td>
                      <td className="text-2xs text-slate-400">{collector.kind ?? '—'}</td>
                      <td>
                        <StatusPill
                          label={collector.enabled ? 'activé' : 'désactivé'}
                          className={
                            collector.enabled
                              ? 'border-emerald-800 bg-emerald-950/50 text-emerald-200'
                              : 'border-slate-700 bg-slate-800/70 text-slate-400'
                          }
                        />
                      </td>
                      <td className="whitespace-nowrap text-2xs text-slate-400">
                        {collector.last_run_at === null ? '—' : formatDateTime(collector.last_run_at)}
                        {collector.last_run_at !== null ? (
                          <p className="text-slate-500">{formatRelative(collector.last_run_at)}</p>
                        ) : null}
                      </td>
                      <td className="text-2xs text-slate-300">{collector.last_status ?? '—'}</td>
                      <td className="soc-num text-2xs text-slate-300">
                        {collector.items_last_run === null ? '—' : formatNumber(collector.items_last_run)}
                      </td>
                      <td>
                        {collector.errors.length === 0 ? (
                          <span className="text-2xs text-emerald-300">aucune</span>
                        ) : (
                          <Button
                            size="sm"
                            variant="ghost"
                            aria-expanded={expandedName === collector.name}
                            onClick={() =>
                              setExpandedName((previous) => (previous === collector.name ? null : collector.name))
                            }
                          >
                            {formatNumber(collector.errors.length)} erreur(s)
                          </Button>
                        )}
                      </td>
                      <td className="whitespace-nowrap text-2xs text-slate-400">
                        {collector.next_run_at === null ? 'manuel uniquement' : formatDateTime(collector.next_run_at)}
                      </td>
                      <td>
                        {canRun ? (
                          <Button
                            size="sm"
                            variant="warn"
                            busy={runMutation.isPending && pendingRun?.name === collector.name}
                            disabled={!collector.enabled}
                            title={
                              collector.enabled
                                ? 'Déclencher un run manuel (double confirmation)'
                                : 'Collecteur désactivé côté serveur'
                            }
                            onClick={() => setPendingRun(collector)}
                          >
                            Run manuel
                          </Button>
                        ) : (
                          <span className="text-2xs text-slate-500">capacité execute:actions requise</span>
                        )}
                      </td>
                    </tr>
                    {expandedName === collector.name ? (
                      <tr>
                        <td colSpan={9} className="bg-slate-950/60">
                          <p className="text-2xs uppercase tracking-wider text-slate-500">
                            Erreurs du dernier run
                          </p>
                          <ul className="mt-1 list-inside list-disc space-y-0.5 text-2xs text-rose-200">
                            {collector.errors.map((error, index) => (
                              <li key={index}>{error}</li>
                            ))}
                          </ul>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <ConfirmDialog
        open={pendingRun !== null}
        title={`Déclencher le run manuel de « ${pendingRun?.name ?? ''} »`}
        description="Le collecteur va s’exécuter immédiatement, sur les cibles déclarées du tenant. Cette opération est tracée dans l’audit et peut créer de nouveaux findings."
        tone="warn"
        confirmLabel="Lancer le run"
        confirmToken={pendingRun?.name ?? null}
        tokenLabel="Recopiez le nom du collecteur pour armer le lancement"
        acknowledgeLabel="Je confirme que ce run ne vise que des cibles possédées par le tenant et déclarées dans THOT_TARGETS_FILE."
        details={
          pendingRun !== null ? (
            <KeyValueList
              columns={1}
              items={[
                { label: 'Collecteur', value: pendingRun.name, mono: true },
                { label: 'Type', value: pendingRun.kind ?? '—' },
                { label: 'Dernier statut', value: pendingRun.last_status ?? '—' },
                {
                  label: 'Dernier run',
                  value: pendingRun.last_run_at === null ? '—' : formatDateTime(pendingRun.last_run_at),
                },
              ]}
            />
          ) : null
        }
        busy={runMutation.isPending}
        error={runMutation.error ? errorMessage(runMutation.error) : null}
        onCancel={() => {
          runMutation.reset();
          setPendingRun(null);
        }}
        onConfirm={() => {
          if (pendingRun !== null) runMutation.mutate(pendingRun.name);
        }}
      />
    </div>
  );
}
