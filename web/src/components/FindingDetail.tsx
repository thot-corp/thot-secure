/**
 * Détail d'un finding : preuves, décomposition du score, décision courante et
 * garde-fous, transitions de statut, téléchargement du rapport.
 *
 * Sûreté — points non négociables de ce panneau :
 *  1. **Preuves** : les échantillons contiennent des charges d'attaque réelles
 *     (XSS, injection SQL…). Ils sont rendus exclusivement en nœuds texte et
 *     dans des blocs `<pre>` : aucun `dangerouslySetInnerHTML` n'existe dans ce
 *     projet, et le HTML d'un rapport est **téléchargé** (Blob) jamais rendu.
 *  2. **Garde-fous visibles** : mode d'autonomie, `dry_run`, allowlist d'infra
 *     protégée et décision courante (statut de la dernière action liée) sont
 *     affichés *avant* les boutons de mutation.
 *  3. **Double confirmation** : chaque transition passe par une boîte de
 *     confirmation explicite ; la suppression d'un finding (exception de règle)
 *     exige en plus la recopie manuelle de l'identifiant du finding.
 *  4. **Masquage RBAC** : les boutons dont la capacité manque ne sont pas
 *     affichés (`write:findings` pour les transitions, `read:rules` pour la
 *     décomposition du score issue de la règle).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { useMemo, useState } from 'react';
import type { JSX } from 'react';
import { Link } from 'react-router-dom';

import { EmptyState } from './EmptyState';
import { RiskGauge } from './RiskGauge';
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
} from './ui';
import type { KeyValueItem } from './ui';
import { useAuth } from '@/lib/auth';
import { errorMessage } from '@/lib/api';
import { downloadText, reportFileName, reportMimeType } from '@/lib/download';
import {
  ACTION_STATUS_CLASSES,
  ACTION_STATUS_LABELS,
  AUTONOMY_DESCRIPTIONS,
  AUTONOMY_LABELS,
  FINDING_STATUS_CLASSES,
  FINDING_STATUS_LABELS,
  formatDateTime,
  formatDuration,
  formatNumber,
  formatPercent,
  formatRelative,
  formatScore,
  toDisplayText,
} from '@/lib/format';
import type { JsonObject, ReportFormat, Resolution } from '@/lib/types';
import { REPORT_FORMATS, RESOLUTIONS } from '@/lib/types';

/** Libellés français des résolutions de clôture (contrat §4.4). */
const RESOLUTION_LABELS: Record<Resolution, string> = {
  true_positive: 'Vrai positif — menace confirmée',
  false_positive: 'Faux positif — détection erronée',
  mitigated: 'Mitigé — risque traité ou atténué',
};

/** Durées proposées pour une suppression (exception de règle, contrat §4.4). */
const SUPPRESS_DURATIONS: readonly { seconds: number; label: string }[] = [
  { seconds: 3_600, label: '1 heure' },
  { seconds: 28_800, label: '8 heures' },
  { seconds: 86_400, label: '24 heures' },
  { seconds: 604_800, label: '7 jours' },
  { seconds: 2_592_000, label: '30 jours' },
];

function readNumber(source: JsonObject | null | undefined, key: string): number | null {
  const value = source?.[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export interface FindingDetailProps {
  findingId: string;
  onClose: () => void;
  className?: string;
}

type TransitionKind = 'ack' | 'close' | 'suppress';

export function FindingDetail(props: FindingDetailProps): JSX.Element {
  const { findingId, onClose, className } = props;
  const { client, queryScope, tenantId, dryRun, autonomy, can } = useAuth();
  const queryClient = useQueryClient();

  const canRead = can('read:findings');
  const canWrite = can('write:findings');
  const canReadRules = can('read:rules');

  const [transition, setTransition] = useState<TransitionKind | null>(null);
  const [resolution, setResolution] = useState<Resolution>('true_positive');
  const [suppressSeconds, setSuppressSeconds] = useState<number>(86_400);
  const [reportFormat, setReportFormat] = useState<ReportFormat>('md');
  const [reportBusy, setReportBusy] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const findingQuery = useQuery({
    queryKey: ['finding', queryScope, findingId],
    queryFn: ({ signal }) => client.getFinding(findingId, { signal }),
    enabled: canRead,
  });

  // Métadonnées du tenant : mode, `dry_run`, allowlist d'infra protégée. Lecture
  // autorisée pour son propre tenant (capacité `read:stats`, contrat §4.2).
  const tenantQuery = useQuery({
    queryKey: ['tenant', queryScope, tenantId],
    queryFn: ({ signal }) => client.getTenant(tenantId ?? '', { signal }),
    enabled: canRead && tenantId !== null,
  });

  // Règle source : fournit `risk.base` / `risk.asset_criticality` et la
  // confiance déclarée, c'est-à-dire les entrées connues du scoring (contrat §5).
  const ruleId = findingQuery.data?.rule_id ?? null;
  const ruleQuery = useQuery({
    queryKey: ['rule', queryScope, ruleId],
    queryFn: ({ signal }) => client.getRule(ruleId ?? '', { signal }),
    enabled: canReadRules && ruleId !== null,
  });

  const invalidate = (): void => {
    void queryClient.invalidateQueries({ queryKey: ['finding', queryScope, findingId] });
    void queryClient.invalidateQueries({ queryKey: ['findings'] });
  };

  const ackMutation = useMutation({
    mutationFn: (comment: string) => client.ackFinding(findingId, { comment: comment === '' ? undefined : comment }),
    onSuccess: invalidate,
  });

  const closeMutation = useMutation({
    mutationFn: (payload: { resolution: Resolution; comment: string }) =>
      client.closeFinding(findingId, {
        resolution: payload.resolution,
        comment: payload.comment === '' ? undefined : payload.comment,
      }),
    onSuccess: invalidate,
  });

  const suppressMutation = useMutation({
    mutationFn: (payload: { durationSeconds: number; reason: string }) =>
      client.suppressFinding(findingId, {
        duration_seconds: payload.durationSeconds,
        reason: payload.reason,
      }),
    onSuccess: invalidate,
  });

  const activeMutation = transition === 'ack' ? ackMutation : transition === 'close' ? closeMutation : suppressMutation;
  const mutationError = activeMutation.error ? errorMessage(activeMutation.error) : null;

  const finding = findingQuery.data ?? null;
  const samples = useMemo(() => {
    const raw = finding?.evidence?.samples;
    return Array.isArray(raw) ? raw : [];
  }, [finding]);

  const linkedActions = useMemo(() => {
    const actions = finding?.actions;
    if (!Array.isArray(actions)) return [];
    // Décision « courante » = action la plus récemment demandée.
    return [...actions].sort((left, right) => right.requested_at.localeCompare(left.requested_at));
  }, [finding]);

  const currentAction = linkedActions.length > 0 ? linkedActions[0] ?? null : null;

  const closeTransition = (): void => {
    setTransition(null);
    ackMutation.reset();
    closeMutation.reset();
    suppressMutation.reset();
  };

  const handleDownloadReport = async (kind: ReportFormat): Promise<void> => {
    setReportBusy(true);
    setReportError(null);
    try {
      const content = await client.findingReport(findingId, kind);
      // Le rapport HTML est remis au navigateur comme fichier téléchargé : il
      // n'est jamais injecté dans le document (aucun `innerHTML`).
      downloadText(content, reportFileName(findingId, kind), reportMimeType(kind));
    } catch (cause) {
      setReportError(errorMessage(cause));
    } finally {
      setReportBusy(false);
    }
  };

  if (!canRead) {
    return (
      <div className={className}>
        <EmptyState
          variant="locked"
          title="Détail masqué — capacité « read:findings » requise"
          description="Votre clé API ne permet pas de consulter les findings ni leurs preuves."
        />
      </div>
    );
  }

  if (findingQuery.isLoading) {
    return (
      <Panel className={className} title="Détail du finding">
        <LoadingBlock label={`Chargement de ${findingId}…`} rows={4} />
      </Panel>
    );
  }

  if (findingQuery.error || !finding) {
    return (
      <Panel className={className} title="Détail du finding">
        <ErrorNotice
          error={findingQuery.error ?? 'Finding introuvable.'}
          title="Impossible de charger ce finding"
          onRetry={() => void findingQuery.refetch()}
        />
      </Panel>
    );
  }

  const effectiveDryRun = tenantQuery.data ? tenantQuery.data.dry_run : dryRun;
  const effectiveMode = tenantQuery.data ? tenantQuery.data.mode : autonomy;
  const allowlist = tenantQuery.data?.autonomy_allowlist ?? [];

  const ruleRiskBase = readNumber(ruleQuery.data?.risk ?? null, 'base');
  const ruleAssetCriticality = readNumber(ruleQuery.data?.risk ?? null, 'asset_criticality');

  const identityItems: KeyValueItem[] = [
    { label: 'Finding', value: finding.finding_id, mono: true, wide: true },
    { label: 'Règle', value: `${finding.rule_id} — ${finding.rule_name}`, mono: true, wide: true },
    { label: 'Statut', value: <StatusPill label={FINDING_STATUS_LABELS[finding.status]} className={FINDING_STATUS_CLASSES[finding.status]} /> },
    { label: 'Sévérité', value: <SeverityBadge severity={finding.severity} /> },
    { label: 'Première observation', value: formatDateTime(finding.first_seen) },
    { label: 'Dernière observation', value: `${formatDateTime(finding.last_seen)} (${formatRelative(finding.last_seen)})` },
    { label: 'Occurrences', value: formatNumber(finding.count) },
    { label: 'Événements liés', value: formatNumber(finding.event_ids.length) },
    { label: 'Confiance (finding)', value: formatPercent(finding.confidence) },
    { label: 'Score de risque', value: formatScore(finding.risk_score) },
  ];

  const decisionItems: KeyValueItem[] = [
    { label: 'Mode d’autonomie', value: `${AUTONOMY_LABELS[effectiveMode]} — ${AUTONOMY_DESCRIPTIONS[effectiveMode]}`, wide: true },
    {
      label: 'dry_run',
      value: effectiveDryRun ? 'actif — playbooks simulés, aucune action réelle' : 'inactif — exécution réelle possible',
    },
    {
      label: 'Décision courante',
      value: currentAction
        ? `${currentAction.policy_id} → ${currentAction.playbook}`
        : 'aucune action planifiée pour ce finding',
      mono: true,
      wide: true,
    },
    {
      label: 'Statut de l’action',
      value: currentAction ? (
        <StatusPill label={ACTION_STATUS_LABELS[currentAction.status]} className={ACTION_STATUS_CLASSES[currentAction.status]} />
      ) : (
        '—'
      ),
    },
    { label: 'Demandée par', value: currentAction ? `${currentAction.requested_by} (${formatDateTime(currentAction.requested_at)})` : '—' },
    { label: 'Approuvée par', value: currentAction?.approved_by ?? '—' },
    { label: 'Expiration', value: currentAction?.expires_at ? formatDateTime(currentAction.expires_at) : '—' },
    { label: 'Rollback disponible', value: currentAction ? (currentAction.rollback.available ? 'oui (réversible)' : 'non') : '—' },
    {
      label: 'Infra protégée (allowlist)',
      value: allowlist.length > 0 ? allowlist.join(', ') : 'aucune entrée — hors périmètre déclaré ⇒ approbation humaine',
      mono: true,
      wide: true,
    },
  ];

  return (
    <Panel
      className={className}
      title={`Finding ${finding.title}`}
      description={`${finding.rule_id} · ${finding.rule_name}`}
      actions={
        <>
          <Button size="sm" variant="ghost" onClick={onClose}>
            Fermer
          </Button>
          <Button size="sm" variant="secondary" busy={findingQuery.isFetching} onClick={() => void findingQuery.refetch()}>
            Rafraîchir
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {finding.description ? (
          <section>
            <h3>Description</h3>
            <p className="mt-1 whitespace-pre-wrap break-words text-xs text-slate-200">{finding.description}</p>
          </section>
        ) : null}

        <section>
          <h3>Synthèse</h3>
          <KeyValueList className="mt-1.5" columns={2} items={identityItems} />
        </section>

        {finding.tags.length > 0 || finding.mitre.length > 0 ? (
          <section className="flex flex-wrap gap-1">
            {finding.tags.map((tag) => (
              <span key={`tag-${tag}`} className="soc-code-inline">
                {tag}
              </span>
            ))}
            {finding.mitre.map((technique) => (
              <span key={`mitre-${technique}`} className="soc-code-inline text-rose-200">
                MITRE {technique}
              </span>
            ))}
          </section>
        ) : null}

        <section className="rounded-md border border-slate-800 bg-slate-950/50 p-2.5">
          <h3>Décision et garde-fous</h3>
          <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-[auto_1fr]">
            <RiskGauge score={finding.risk_score} confidence={finding.confidence} label="Risque" />
            <div className="space-y-2">
              <KeyValueList columns={1} items={decisionItems} />
              {!effectiveDryRun ? (
                <InlineNotice tone="danger" title="Exécution réelle armée (dry_run = false)">
                  Toute action sur ce finding agira réellement sur la cible. Le serveur exige une approbation
                  explicite pour les cibles hors périmètre déclaré (contrat §6, garde-fou 5).
                </InlineNotice>
              ) : (
                <InlineNotice tone="warn" title="Dry-run actif">
                  Les playbooks sont simulés : aucun effet réel sur les cibles. C’est le comportement par défaut du
                  produit (invariant 1, contrat §1).
                </InlineNotice>
              )}
            </div>
          </div>
        </section>

        <section className="rounded-md border border-slate-800 bg-slate-950/50 p-2.5">
          <h3>Décomposition du score</h3>
          <p className="mt-1 text-2xs text-slate-400">
            Le score final est calculé par le moteur de scoring serveur ; cette vue expose les entrées connues du
            contrat (§5 <code className="soc-code-inline">risk.base</code>,{' '}
            <code className="soc-code-inline">risk.asset_criticality</code>, confiance, sévérité). Aucun recalcul
            n’est effectué côté client.
          </p>
          <KeyValueList
            className="mt-2"
            columns={3}
            items={[
              { label: 'Score final', value: formatScore(finding.risk_score) },
              { label: 'Base de règle', value: ruleRiskBase === null ? '—' : formatScore(ruleRiskBase) },
              {
                label: 'Criticité d’actif',
                value: ruleAssetCriticality === null ? '—' : `×${formatScore(ruleAssetCriticality)}`,
              },
              { label: 'Confiance (règle)', value: ruleQuery.data?.confidence ? formatPercent(ruleQuery.data.confidence) : formatPercent(finding.confidence) },
              { label: 'Sévérité', value: <SeverityBadge severity={finding.severity} /> },
              { label: 'Occurrences', value: formatNumber(finding.count) },
            ]}
          />
          {canReadRules && ruleQuery.error ? (
            <p className="mt-1 text-2xs text-amber-300">
              Règle source non lisible ({errorMessage(ruleQuery.error)}) : seules les valeurs du finding sont
              affichées.
            </p>
          ) : null}
        </section>

        {finding.remediation ? (
          <section>
            <h3>Remédiation recommandée</h3>
            <p className="mt-1 whitespace-pre-wrap break-words text-xs text-emerald-100">{finding.remediation}</p>
          </section>
        ) : null}

        <section>
          <h3>Preuves ({samples.length} échantillon(s))</h3>
          <p className="mt-1 text-2xs text-slate-400">
            Charges brutes affichées en texte : une charge XSS présente dans une preuve est inerte ici (aucun
            <code className="soc-code-inline">dangerouslySetInnerHTML</code> dans le projet).
          </p>
          {samples.length === 0 ? (
            <p className="mt-2 text-2xs text-slate-500">Aucun échantillon détaillé dans ce finding.</p>
          ) : (
            <ul className="mt-2 space-y-2">
              {samples.map((sample, index) => (
                <li key={index} className="soc-subpanel">
                  <p className="text-2xs text-slate-400">
                    Échantillon #{index + 1}
                    {sample.ts ? ` — ${formatDateTime(sample.ts)}` : ''}
                  </p>
                  {sample.labels ? (
                    <table className="soc-table mt-1">
                      <caption>labels</caption>
                      <tbody>
                        {Object.entries(sample.labels).map(([key, value]) => (
                          <tr key={key}>
                            <td className="w-40 font-mono text-2xs text-slate-400">{key}</td>
                            <td className="soc-mono">{toDisplayText(value)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : null}
                  {sample.payload !== undefined ? (
                    <div className="mt-1">
                      <p className="text-2xs uppercase tracking-wider text-slate-500">payload</p>
                      <CodeBlock value={sample.payload} maxHeight={200} />
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          <details className="mt-2">
            <summary className="cursor-pointer text-2xs text-slate-400">
              Objet `evidence` complet (JSON, texte brut)
            </summary>
            <CodeBlock className="mt-1" value={finding.evidence} maxHeight={240} />
          </details>
        </section>

        <section>
          <h3>Actions liées ({linkedActions.length})</h3>
          {linkedActions.length === 0 ? (
            <p className="mt-1 text-2xs text-slate-500">
              Aucune action planifiée. Une action se planifie depuis la page{' '}
              <Link to="/actions">Actions</Link> (capacité <code className="soc-code-inline">execute:actions</code>).
            </p>
          ) : (
            <div className="soc-table-wrap mt-1">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th scope="col">Action</th>
                    <th scope="col">Playbook</th>
                    <th scope="col">Statut</th>
                    <th scope="col">Mode</th>
                    <th scope="col">Dry-run</th>
                    <th scope="col">Demandée</th>
                    <th scope="col">Exécutée</th>
                  </tr>
                </thead>
                <tbody>
                  {linkedActions.map((action) => (
                    <tr key={action.action_id}>
                      <td className="font-mono text-2xs text-slate-400">{action.action_id}</td>
                      <td className="font-mono text-2xs">{action.playbook}</td>
                      <td>
                        <StatusPill label={ACTION_STATUS_LABELS[action.status]} className={ACTION_STATUS_CLASSES[action.status]} />
                      </td>
                      <td className="text-2xs">{AUTONOMY_LABELS[action.mode]}</td>
                      <td className={clsx('text-2xs', action.dry_run ? 'text-amber-300' : 'text-rose-300')}>
                        {action.dry_run ? 'oui' : 'non'}
                      </td>
                      <td className="whitespace-nowrap text-2xs text-slate-400">{formatDateTime(action.requested_at)}</td>
                      <td className="whitespace-nowrap text-2xs text-slate-400">{formatDateTime(action.executed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="rounded-md border border-slate-800 bg-slate-950/50 p-2.5">
          <h3>Transitions et rapport</h3>
          <div className="mt-2 flex flex-wrap items-end gap-2">
            {canWrite ? (
              <>
                <Button
                  variant="primary"
                  disabled={finding.status === 'acked'}
                  title={finding.status === 'acked' ? 'Finding déjà pris en compte' : 'Marquer comme pris en compte'}
                  onClick={() => setTransition('ack')}
                >
                  Acquitter
                </Button>
                <Button
                  variant="secondary"
                  disabled={finding.status === 'closed'}
                  title={finding.status === 'closed' ? 'Finding déjà clôturé' : 'Clôturer avec une résolution'}
                  onClick={() => setTransition('close')}
                >
                  Clôturer
                </Button>
                <Button
                  variant="danger"
                  disabled={finding.status === 'suppressed'}
                  title={
                    finding.status === 'suppressed'
                      ? 'Finding déjà supprimé'
                      : 'Supprimer : crée une exception de règle (double confirmation)'
                  }
                  onClick={() => setTransition('suppress')}
                >
                  Supprimer
                </Button>
              </>
            ) : (
              <p className="text-2xs text-slate-400">
                Transitions masquées : la capacité <code className="soc-code-inline">write:findings</code> est requise
                (rôle analyste ou supérieur).
              </p>
            )}

            <div className="ml-auto flex flex-wrap items-end gap-2">
              <Field label="Format du rapport" className="w-44">
                <Select
                  value={reportFormat}
                  onChange={(event) => setReportFormat(event.target.value as ReportFormat)}
                >
                  {REPORT_FORMATS.map((format) => (
                    <option key={format} value={format}>
                      {format === 'md'
                        ? 'Markdown'
                        : format === 'html'
                          ? 'HTML'
                          : format === 'json'
                            ? 'JSON'
                            : 'SARIF 2.1.0'}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button variant="secondary" busy={reportBusy} onClick={() => void handleDownloadReport(reportFormat)}>
                Télécharger le rapport
              </Button>
            </div>
          </div>
          {reportError ? <ErrorNotice className="mt-2" error={reportError} title="Rapport indisponible" /> : null}
          <p className="mt-2 text-2xs text-slate-500">
            Le rapport est téléchargé comme fichier (Blob) : un rapport HTML n’est jamais rendu dans cette page, donc
            il ne peut pas exécuter de script dans l’origine de la console.
          </p>
        </section>
      </div>

      {/* --- Confirmations : une boîte dédiée par transition ---------------- */}

      <ConfirmDialog
        open={transition === 'ack'}
        title="Acquitter le finding"
        description="Le finding passe au statut « Pris en compte » (acked). Aucune contre-mesure n’est déclenchée."
        tone="primary"
        confirmLabel="Acquitter"
        acknowledgeLabel="Je confirme avoir pris connaissance de ce finding et de ses preuves."
        commentLabel="Commentaire d’acquittement"
        commentPlaceholder="Ex. : pris en charge par l’astreinte SOC, analyse en cours."
        details={
          <KeyValueList
            columns={1}
            items={[
              { label: 'Finding', value: finding.finding_id, mono: true },
              { label: 'Titre', value: finding.title },
              { label: 'Sévérité / score', value: `${finding.severity} — ${formatScore(finding.risk_score)}` },
            ]}
          />
        }
        busy={ackMutation.isPending}
        error={mutationError}
        onCancel={closeTransition}
        onConfirm={(comment) => ackMutation.mutate(comment, { onSuccess: closeTransition })}
      />

      <ConfirmDialog
        open={transition === 'close'}
        title="Clôturer le finding"
        description="La clôture est une décision d’analyse : elle est journalisée dans l’audit avec la résolution choisie."
        tone="warn"
        confirmLabel="Clôturer"
        acknowledgeLabel="Je confirme la résolution choisie ; une clôture erronée faussera les métriques MTTR."
        commentLabel="Commentaire de clôture"
        commentPlaceholder="Ex. : correctif déployé en production, vérifié par rejeu des journaux."
        extra={
          <Field label="Résolution" hint="Resolution au sens du contrat §4.4.">
            <Select value={resolution} onChange={(event) => setResolution(event.target.value as Resolution)}>
              {RESOLUTIONS.map((value) => (
                <option key={value} value={value}>
                  {RESOLUTION_LABELS[value]}
                </option>
              ))}
            </Select>
          </Field>
        }
        details={
          <KeyValueList
            columns={1}
            items={[
              { label: 'Finding', value: finding.finding_id, mono: true },
              { label: 'Règle', value: finding.rule_id, mono: true },
              { label: 'Occurrences', value: formatNumber(finding.count) },
            ]}
          />
        }
        busy={closeMutation.isPending}
        error={mutationError}
        onCancel={closeTransition}
        onConfirm={(comment) =>
          closeMutation.mutate({ resolution, comment }, { onSuccess: closeTransition })
        }
      />

      <ConfirmDialog
        open={transition === 'suppress'}
        title="Supprimer le finding (exception de règle)"
        description="La suppression crée une exception sur la règle : les détections correspondantes ne remonteront plus pendant la durée choisie. C’est une action à effet durable — d’où la recopie manuelle de l’identifiant."
        tone="danger"
        confirmLabel="Supprimer définitivement"
        confirmToken={finding.finding_id}
        tokenLabel="Recopiez l’identifiant du finding pour armer la suppression"
        acknowledgeLabel="Je comprends qu’une suppression masque de futures détections de cette règle et qu’elle est journalisée."
        commentLabel="Motif de la suppression"
        commentPlaceholder="Ex. : faux positif confirmé — requête légitime de l’outil de supervision interne."
        commentRequired
        extra={
          <Field label="Durée de l’exception">
            <Select
              value={String(suppressSeconds)}
              onChange={(event) => setSuppressSeconds(Number(event.target.value))}
            >
              {SUPPRESS_DURATIONS.map((duration) => (
                <option key={duration.seconds} value={duration.seconds}>
                  {duration.label}
                </option>
              ))}
            </Select>
          </Field>
        }
        details={
          <KeyValueList
            columns={1}
            items={[
              { label: 'Finding', value: finding.finding_id, mono: true },
              { label: 'Règle concernée', value: finding.rule_id, mono: true },
              { label: 'Durée', value: formatDuration(suppressSeconds) },
              { label: 'Infra protégée', value: allowlist.length > 0 ? allowlist.join(', ') : '—', mono: true },
            ]}
          />
        }
        busy={suppressMutation.isPending}
        error={mutationError}
        onCancel={closeTransition}
        onConfirm={(comment) =>
          suppressMutation.mutate(
            { durationSeconds: suppressSeconds, reason: comment },
            { onSuccess: closeTransition },
          )
        }
      />
    </Panel>
  );
}
