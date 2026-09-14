/**
 * Règles de détection (`GET /api/v1/rules`, `GET /api/v1/rules/{id}`,
 * `POST /api/v1/rules/validate`, `POST /api/v1/rules/reload`, contrat §4.5).
 *
 * Lecture : `read:rules`. Validation et rechargement : `admin:rules` — les
 * contrôles correspondants sont masqués pour tout autre rôle, et le serveur les
 * refuse de toute façon.
 *
 * Sûreté :
 *  - le YAML de règle est affiché comme **texte** (bloc `<pre>`), jamais
 *    interprété : une règle est un artefact serveur, pas du balisage ;
 *  - les `references` d'une règle sont des URL fournies par le serveur : seules
 *    les URL `http(s)` sont transformées en liens cliquables, toute autre valeur
 *    (par exemple `javascript:`) reste du texte inerte ;
 *  - le rechargement est une opération d'administration : double confirmation
 *    explicite, puis restitution du nombre de règles chargées et des erreurs.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { useMemo, useState } from 'react';
import type { JSX } from 'react';

import { EmptyState } from './EmptyState';
import { SeverityBadge } from './SeverityBadge';
import {
  Button,
  CodeBlock,
  ConfirmDialog,
  ErrorNotice,
  Field,
  InlineNotice,
  KeyValueList,
  LoadingBlock,
  Panel,
  Select,
  StatusPill,
  TextArea,
  TextInput,
} from './ui';
import { useAuth } from '@/lib/auth';
import { errorMessage } from '@/lib/api';
import { SEVERITY_LABELS, formatNumber, toDisplayText } from '@/lib/format';
import type { RuleSummary, Severity } from '@/lib/types';
import { SEVERITIES } from '@/lib/types';

/** N'accepte que les schémas d'URL sûrs dans un `href` (anti `javascript:`). */
function safeHref(value: string): string | null {
  const trimmed = value.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : null;
}

type EnabledFilter = 'all' | 'enabled' | 'disabled';

export interface RulesPanelProps {
  className?: string;
}

export function RulesPanel(props: RulesPanelProps): JSX.Element {
  const { className } = props;
  const { client, queryScope, can } = useAuth();
  const queryClient = useQueryClient();
  const canRead = can('read:rules');
  const canAdmin = can('admin:rules');

  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [enabled, setEnabled] = useState<EnabledFilter>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [reloadOpen, setReloadOpen] = useState(false);

  const listQuery = useQuery({
    queryKey: ['rules', queryScope],
    queryFn: ({ signal }) => client.listRules({ signal }),
    enabled: canRead,
  });

  const detailQuery = useQuery({
    queryKey: ['rule', queryScope, selectedId],
    queryFn: ({ signal }) => client.getRule(selectedId ?? '', { signal }),
    enabled: canRead && selectedId !== null,
  });

  const validateMutation = useMutation({
    mutationFn: (source: string) => client.validateRule(source),
  });

  const reloadMutation = useMutation({
    mutationFn: () => client.reloadRules(),
    onSuccess: () => {
      setReloadOpen(false);
      void queryClient.invalidateQueries({ queryKey: ['rules'] });
      void queryClient.invalidateQueries({ queryKey: ['rule'] });
    },
  });

  // Tableau stable entre deux rendus : sans ce `useMemo`, le repli `[]`
  // construirait un nouveau tableau à chaque rendu, et les `useMemo` qui en dépendent
  // se recalculeraient tous autant de fois.
  const rules = useMemo(() => listQuery.data?.items ?? [], [listQuery.data]);
  const total = listQuery.data?.total ?? null;

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return rules.filter((rule) => {
      if (severity !== '' && rule.severity !== severity) return false;
      if (enabled === 'enabled' && !rule.enabled) return false;
      if (enabled === 'disabled' && rule.enabled) return false;
      if (needle === '') return true;
      const haystack = [rule.rule_id, rule.title, ...rule.tags, ...rule.source_types, ...rule.kinds]
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [enabled, rules, search, severity]);

  const detail = detailQuery.data ?? null;
  const detailPath = detail?.path ?? null;

  if (!canRead) {
    return (
      <div className={className}>
        <EmptyState
          variant="locked"
          title="Règles masquées — capacité « read:rules » requise"
          description="La bibliothèque de détection n’est lisible qu’avec la capacité read:rules (tous les rôles du contrat la possèdent)."
        />
      </div>
    );
  }

  return (
    <div className={clsx('space-y-3', className)}>
      <Panel
        title="Bibliothèque de règles"
        description={`${formatNumber(filtered.length)} règle(s) affichée(s)${
          total !== null ? ` sur ${formatNumber(total)}` : ''
        } · règles YAML chargées depuis THOT_RULES_DIR par le serveur`}
        actions={
          <>
            <Button size="sm" variant="secondary" busy={listQuery.isFetching} onClick={() => void listQuery.refetch()}>
              Rafraîchir
            </Button>
            {canAdmin ? (
              <Button size="sm" variant="warn" onClick={() => setReloadOpen(true)}>
                Recharger les règles
              </Button>
            ) : null}
          </>
        }
      >
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Recherche" className="w-64">
            <TextInput
              value={search}
              placeholder="identifiant, titre, tag, type de source…"
              onChange={(event) => setSearch(event.target.value)}
            />
          </Field>
          <Field label="Sévérité" className="w-36">
            <Select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | '')}>
              <option value="">Toutes</option>
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {SEVERITY_LABELS[value]}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="État" className="w-36">
            <Select value={enabled} onChange={(event) => setEnabled(event.target.value as EnabledFilter)}>
              <option value="all">Toutes</option>
              <option value="enabled">Activées</option>
              <option value="disabled">Désactivées</option>
            </Select>
          </Field>
        </div>

        {listQuery.error ? (
          <ErrorNotice
            className="mt-2"
            error={listQuery.error}
            title="Chargement des règles impossible"
            onRetry={() => void listQuery.refetch()}
          />
        ) : null}

        <div className={clsx('mt-2', listQuery.isFetching && 'opacity-60')}>
          {listQuery.isLoading ? (
            <LoadingBlock label="Chargement des règles…" rows={5} />
          ) : filtered.length === 0 ? (
            <EmptyState
              title="Aucune règle pour ces critères"
              description="Vérifiez le répertoire THOT_RULES_DIR côté serveur, puis utilisez « Recharger les règles » (admin:rules)."
            />
          ) : (
            <div className="soc-table-wrap">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th scope="col">Identifiant</th>
                    <th scope="col">Titre</th>
                    <th scope="col">Sévérité</th>
                    <th scope="col">État</th>
                    <th scope="col">Tags</th>
                    <th scope="col">Types de source</th>
                    <th scope="col">Kinds</th>
                    <th scope="col">Chemin</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((rule) => (
                    <RuleRow
                      key={rule.rule_id}
                      rule={rule}
                      selected={selectedId === rule.rule_id}
                      onSelect={() => setSelectedId((previous) => (previous === rule.rule_id ? null : rule.rule_id))}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Panel>

      {selectedId !== null ? (
        <Panel
          title={`Règle ${selectedId}`}
          description={
            detailPath !== null
              ? `Source : ${detailPath}`
              : 'Chargée depuis le répertoire de règles du serveur'
          }
          actions={
            <Button size="sm" variant="ghost" onClick={() => setSelectedId(null)}>
              Fermer le détail
            </Button>
          }
        >
          {detailQuery.isLoading ? (
            <LoadingBlock label="Chargement de la règle…" rows={4} />
          ) : detailQuery.error || !detail ? (
            <ErrorNotice
              error={detailQuery.error ?? 'Règle introuvable.'}
              title="Impossible de charger la règle"
              onRetry={() => void detailQuery.refetch()}
            />
          ) : (
            <div className="space-y-3">
              <KeyValueList
                columns={3}
                items={[
                  { label: 'Titre', value: detail.title },
                  { label: 'Sévérité', value: <SeverityBadge severity={detail.severity} size="md" /> },
                  { label: 'État', value: detail.enabled ? 'activée' : 'désactivée' },
                  { label: 'Statut de règle', value: detail.status ?? '—' },
                  {
                    label: 'Confiance',
                    value: detail.confidence === null ? '—' : `${(detail.confidence * 100).toFixed(0)} %`,
                  },
                  { label: 'Kinds', value: detail.kinds.join(', ') || '—' },
                  { label: 'Types de source', value: detail.source_types.join(', ') || '—' },
                  { label: 'Tags', value: detail.tags.join(' · ') || '—', wide: true },
                ]}
              />

              {detail.description ? (
                <p className="whitespace-pre-wrap break-words text-xs text-slate-200">{detail.description}</p>
              ) : null}

              {detail.remediation ? (
                <section>
                  <h3>Remédiation</h3>
                  <p className="mt-1 whitespace-pre-wrap break-words text-xs text-emerald-100">{detail.remediation}</p>
                </section>
              ) : null}

              {detail.false_positives.length > 0 ? (
                <section>
                  <h3>Faux positifs connus</h3>
                  <ul className="mt-1 list-inside list-disc space-y-0.5 text-2xs text-amber-100">
                    {detail.false_positives.map((item, index) => (
                      <li key={index}>{item}</li>
                    ))}
                  </ul>
                </section>
              ) : null}

              <div className="grid grid-cols-1 gap-2 lg:grid-cols-3">
                <div>
                  <p className="text-2xs uppercase tracking-wider text-slate-500">match</p>
                  <CodeBlock className="mt-1" value={detail.match} maxHeight={200} />
                </div>
                <div>
                  <p className="text-2xs uppercase tracking-wider text-slate-500">dedup</p>
                  <CodeBlock className="mt-1" value={detail.dedup} maxHeight={200} />
                </div>
                <div>
                  <p className="text-2xs uppercase tracking-wider text-slate-500">risk</p>
                  <CodeBlock className="mt-1" value={detail.risk} maxHeight={200} />
                </div>
              </div>

              {detail.references.length > 0 ? (
                <section>
                  <h3>Références</h3>
                  <ul className="mt-1 space-y-0.5">
                    {detail.references.map((reference, index) => {
                      const href = safeHref(reference);
                      return (
                        <li key={`${reference}-${index}`} className="text-2xs">
                          {href !== null ? (
                            <a href={href} target="_blank" rel="noopener noreferrer nofollow">
                              {reference} ↗
                            </a>
                          ) : (
                            <span className="break-all font-mono text-slate-400">
                              {toDisplayText(reference)}
                            </span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </section>
              ) : null}

              <section>
                <h3>Source YAML</h3>
                <p className="mt-1 text-2xs text-slate-400">
                  Affichée telle quelle, en texte : aucun rendu HTML, aucune évaluation de gabarit (contrat §10).
                </p>
                <CodeBlock className="mt-1" value={detail.yaml} emptyLabel="YAML non exposé par l’API." maxHeight={320} />
              </section>
            </div>
          )}
        </Panel>
      ) : null}

      {canAdmin ? (
        <Panel
          title="Validation et rechargement (admin:rules)"
          description="La validation n’a aucun effet de bord : elle analyse un YAML et retourne les diagnostics. Le rechargement remplace la bibliothèque en mémoire du serveur."
        >
          <TextArea
            label="YAML ou JSON de règle à valider"
            className="min-h-[160px]"
            value={draft}
            spellCheck={false}
            placeholder={'id: AO-WEB-001\ntitle: SQL injection attempt in query string\nseverity: high\n…'}
            onChange={(event) => setDraft(event.target.value)}
            hint="Le corps est envoyé tel quel en text/yaml (contrat §4.5). Aucune règle n’est activée par cette action."
          />

          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              busy={validateMutation.isPending}
              disabled={draft.trim() === ''}
              onClick={() => validateMutation.mutate(draft)}
            >
              Valider la règle
            </Button>
            <Button variant="secondary" onClick={() => validateMutation.reset()}>
              Effacer le verdict
            </Button>
            <Button variant="warn" className="ml-auto" onClick={() => setReloadOpen(true)}>
              Recharger depuis THOT_RULES_DIR
            </Button>
          </div>

          {validateMutation.error ? (
            <ErrorNotice className="mt-2" error={validateMutation.error} title="Validation impossible" />
          ) : null}

          {validateMutation.data ? (
            validateMutation.data.valid ? (
              <InlineNotice tone="success" className="mt-2" title="Règle valide">
                Aucun diagnostic. La règle peut être déposée dans <code className="soc-code-inline">THOT_RULES_DIR</code>{' '}
                puis rechargée.
              </InlineNotice>
            ) : (
              <InlineNotice tone="danger" className="mt-2" title="Règle invalide">
                <ul className="list-inside list-disc space-y-0.5">
                  {validateMutation.data.errors.map((error, index) => (
                    <li key={index}>{error}</li>
                  ))}
                </ul>
              </InlineNotice>
            )
          ) : null}
        </Panel>
      ) : (
        <InlineNotice tone="info" title="Administration des règles masquée">
          La validation et le rechargement exigent la capacité <code className="soc-code-inline">admin:rules</code>{' '}
          (rôle administrateur). Le serveur refuse ces routes pour tout autre rôle.
        </InlineNotice>
      )}

      <ConfirmDialog
        open={reloadOpen}
        title="Recharger la bibliothèque de règles"
        description="Le serveur relit THOT_RULES_DIR et remplace les règles en mémoire. Une règle invalide ne casse pas le chargement : elle est rejetée avec un diagnostic."
        tone="warn"
        confirmLabel="Recharger maintenant"
        acknowledgeLabel="Je confirme disposer d’une copie de sauvegarde des règles et du journal d’audit avant rechargement."
        details={
          <KeyValueList
            columns={1}
            items={[
              { label: 'Règles actuellement en mémoire', value: formatNumber(rules.length) },
              { label: 'Effet', value: 'Les règles absentes du répertoire cessent d’être appliquées.' },
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
          title={`Rechargement terminé : ${formatNumber(reloadMutation.data.loaded)} règle(s) chargée(s)`}
        >
          {reloadMutation.data.errors.length === 0 ? (
            <p>Aucun diagnostic : toutes les règles du répertoire se sont chargées.</p>
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

interface RuleRowProps {
  rule: RuleSummary;
  selected: boolean;
  onSelect: () => void;
}

function RuleRow(props: RuleRowProps): JSX.Element {
  const { rule, selected, onSelect } = props;

  return (
    <tr data-selected={selected} className="cursor-pointer" onClick={onSelect}>
      <td className="font-mono text-2xs text-cyan-200">{rule.rule_id}</td>
      <td className="max-w-[24rem] truncate" title={rule.title}>
        {rule.title}
      </td>
      <td>
        <SeverityBadge severity={rule.severity} />
      </td>
      <td>
        <StatusPill
          label={rule.enabled ? 'activée' : 'désactivée'}
          className={
            rule.enabled
              ? 'border-emerald-800 bg-emerald-950/50 text-emerald-200'
              : 'border-slate-700 bg-slate-800/70 text-slate-400'
          }
        />
      </td>
      <td className="max-w-[12rem]">
        <span className="flex flex-wrap gap-1">
          {rule.tags.slice(0, 3).map((tag) => (
            <span key={tag} className="soc-code-inline">
              {tag}
            </span>
          ))}
          {rule.tags.length > 3 ? <span className="text-2xs text-slate-500">+{rule.tags.length - 3}</span> : null}
        </span>
      </td>
      <td className="text-2xs text-slate-400">{rule.source_types.join(', ') || '—'}</td>
      <td className="text-2xs text-slate-400">{rule.kinds.join(', ') || '—'}</td>
      <td className="soc-mono">{rule.path ?? '—'}</td>
    </tr>
  );
}
