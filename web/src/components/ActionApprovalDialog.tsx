/**
 * Boîte d'approbation / exécution / rejet / rollback d'une action SOAR.
 *
 * Exigence produit : **aucune action destructive sans double confirmation
 * explicite**. La boîte impose donc deux étapes distinctes :
 *  1. **Revue** — rappel de la cible, du playbook, du statut, des paramètres et
 *     de l'état `dry_run` ; l'opérateur saisit un motif (obligatoire lorsque
 *     l'API accepte un corps : `approve`, `reject`) et coche un engagement ;
 *  2. **Confirmation finale** — l'opérateur doit **recopier à la main** la cible
 *     (ou l'identifiant d'action), ce qu'aucun double-clic réflexe ne produit.
 *
 * L'API `POST /actions/{id}/execute` et `.../rollback` n'acceptent pas de corps
 * (contrat §4.6) : le motif n'est donc affiché que pour `approve` et `reject`,
 * où il est réellement transmis et journalisé.
 */
import clsx from 'clsx';
import { useEffect, useState } from 'react';
import type { JSX } from 'react';

import { Button, Checkbox, CodeBlock, Field, InlineNotice, KeyValueList } from './ui';
import type { KeyValueItem } from './ui';
import {
  ACTION_STATUS_CLASSES,
  ACTION_STATUS_LABELS,
  AUTONOMY_LABELS,
  formatDateTime,
  formatRelative,
} from '@/lib/format';
import type { Action } from '@/lib/types';

export type ActionOperation = 'approve' | 'reject' | 'execute' | 'rollback';

interface OperationMeta {
  title: string;
  description: string;
  confirmLabel: string;
  /** Libellé de l'étape 2 (confirmation finale). */
  finalLabel: string;
  tone: 'primary' | 'warn' | 'danger';
  /** `null` : l'API n'accepte pas de corps pour cette opération. */
  comment: { label: string; placeholder: string; required: boolean } | null;
  acknowledge: string;
}

export const ACTION_OPERATION_META: Record<ActionOperation, OperationMeta> = {
  approve: {
    title: 'Approuver l’action',
    description:
      'L’approbation engage l’organisation : l’action pourra ensuite être exécutée sur la cible désignée. Elle est journalisée dans l’audit chaîné (acteur, ancien et nouvel état).',
    confirmLabel: 'Continuer vers la confirmation',
    finalLabel: 'Approuver définitivement',
    tone: 'primary',
    comment: {
      label: 'Commentaire d’approbation',
      placeholder: 'Ex. : bloqué après analyse des journaux WAF, cible hors allowlist, portée limitée à 1 h.',
      required: true,
    },
    acknowledge: 'Je confirme que la cible et la portée du playbook correspondent à l’incident traité.',
  },
  reject: {
    title: 'Rejeter l’action',
    description:
      'Le rejet est **terminal** (contrat §3.4) : aucune exécution ultérieure ne sera possible sur cette action. Le motif est transmis à l’API et journalisé.',
    confirmLabel: 'Continuer vers la confirmation',
    finalLabel: 'Rejeter définitivement',
    tone: 'danger',
    comment: {
      label: 'Motif du rejet',
      placeholder: 'Ex. : faux positif, cible appartenant à un partenaire, hors périmètre autorisé.',
      required: true,
    },
    acknowledge: 'Je comprends que ce rejet est définitif et qu’il faudra planifier une nouvelle action si nécessaire.',
  },
  execute: {
    title: 'Exécuter le playbook',
    description:
      'L’exécution déclenche le playbook sur la cible. En `dry_run`, le connecteur est simulé et retourne un jeton de rollback sans effet réel (contrat §7).',
    confirmLabel: 'Continuer vers la confirmation',
    finalLabel: 'Exécuter maintenant',
    tone: 'danger',
    comment: null,
    acknowledge: 'Je confirme que l’action est approuvée et que la cible est bien celle de l’incident.',
  },
  rollback: {
    title: 'Annuler l’action (rollback)',
    description:
      'Le rollback applique l’opération inverse du playbook. Il reste possible tant que le délai de rollback n’a pas expiré (invariant 3, contrat §1).',
    confirmLabel: 'Continuer vers la confirmation',
    finalLabel: 'Lancer le rollback',
    tone: 'warn',
    comment: null,
    acknowledge: 'Je confirme vouloir rétablir l’état antérieur sur cette cible.',
  },
};

export interface ActionApprovalDialogProps {
  open: boolean;
  operation: ActionOperation;
  action: Action | null;
  /** `dry_run` global (`whoami.dry_run`) : prioritaire sur toute politique. */
  dryRunGlobal: boolean;
  busy?: boolean;
  error?: string | null;
  onCancel: () => void;
  onConfirm: (payload: { operation: ActionOperation; actionId: string; comment: string }) => void;
}

export function ActionApprovalDialog(props: ActionApprovalDialogProps): JSX.Element | null {
  const { open, operation, action, dryRunGlobal, busy = false, error = null, onCancel, onConfirm } = props;
  const meta = ACTION_OPERATION_META[operation];

  const [step, setStep] = useState<'review' | 'final'>('review');
  const [comment, setComment] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [tokenInput, setTokenInput] = useState('');

  const actionId = action?.action_id ?? '';
  const confirmToken = action === null ? '' : action.target.value !== '' ? action.target.value : action.action_id;

  // Toute ouverture repart de l'étape 1 : aucune confirmation ne peut être
  // « rejouée » depuis une opération précédente (même cible, même action).
  useEffect(() => {
    if (!open) return;
    setStep('review');
    setComment('');
    setAcknowledged(false);
    setTokenInput('');
  }, [open, actionId, operation]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape' && !busy) onCancel();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [busy, onCancel, open]);

  if (!open || action === null) return null;

  const commentSatisfied = meta.comment === null || !meta.comment.required || comment.trim() !== '';
  const reviewReady = commentSatisfied && acknowledged && !busy;
  const tokenSatisfied = tokenInput.trim() === confirmToken && confirmToken !== '';
  const finalReady = tokenSatisfied && !busy;
  const rollbackBlocked = operation === 'rollback' && !action.rollback.available;

  const simulated = action.dry_run || dryRunGlobal;

  const details: KeyValueItem[] = [
    { label: 'Action', value: action.action_id, mono: true, wide: true },
    { label: 'Playbook', value: action.playbook, mono: true },
    {
      label: 'Cible',
      value: `${action.target.value} (${action.target.type})`,
      mono: true,
    },
    {
      label: 'Statut',
      value: (
        <span
          className={clsx(
            'rounded border px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide',
            ACTION_STATUS_CLASSES[action.status],
          )}
        >
          {ACTION_STATUS_LABELS[action.status]}
        </span>
      ),
    },
    { label: 'Policy', value: action.policy_id, mono: true },
    { label: 'Mode', value: AUTONOMY_LABELS[action.mode] },
    { label: 'Demandée par', value: `${action.requested_by} — ${formatDateTime(action.requested_at)}` },
    { label: 'Approuvée par', value: action.approved_by ?? '—' },
    { label: 'Expiration', value: action.expires_at ? `${formatDateTime(action.expires_at)} (${formatRelative(action.expires_at)})` : '—' },
    { label: 'Expire dans', value: action.expires_at ? formatRelative(action.expires_at) : '—' },
    {
      label: 'Rollback',
      value: action.rollback.available
        ? `disponible${action.rollback.token !== null ? ' (jeton émis)' : ''}`
        : 'indisponible',
    },
    { label: 'Clé d’idempotence', value: action.idempotency_key, mono: true, wide: true },
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/85 p-4 backdrop-blur-sm"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={meta.title}
        className="my-8 w-full max-w-2xl rounded-lg border border-slate-700 bg-slate-900 shadow-panel"
      >
        <header className="border-b border-slate-800 px-3 py-2">
          <h2 className="flex flex-wrap items-center gap-2">
            {meta.title}
            <span className="rounded border border-cyan-800 bg-cyan-950/60 px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide text-cyan-200">
              Étape {step === 'review' ? '1/2 — revue' : '2/2 — confirmation'}
            </span>
          </h2>
          <p className="mt-0.5 text-2xs leading-relaxed text-slate-400">{meta.description}</p>
        </header>

        <div className="space-y-3 px-3 py-3">
          {simulated ? (
            <InlineNotice
              tone="warn"
              title={action.dry_run ? 'Action planifiée en dry-run' : 'Dry-run global actif'}
            >
              {action.dry_run
                ? 'Cette action a été planifiée avec dry_run = true : le connecteur est simulé, aucun effet réel sur la cible.'
                : 'THOT_DRY_RUN=true : le garde-fou global prime sur la politique et sur la demande d’exécution (contrat §6, garde-fou 4).'}
            </InlineNotice>
          ) : (
            <InlineNotice tone="danger" title="Exécution réelle armée (dry_run = false)">
              Cette opération agira réellement sur <span className="font-mono">{action.target.value}</span>. Un
              rollback n’est possible que tant qu’il n’a pas expiré.
            </InlineNotice>
          )}

          {rollbackBlocked ? (
            <InlineNotice tone="danger" title="Rollback indisponible">
              Le serveur indique <code className="soc-code-inline">rollback.available = false</code> : l’annulation
              n’est pas possible pour cette action (playbook non réversible ou délai expiré).
            </InlineNotice>
          ) : null}

          <KeyValueList columns={2} items={details} />

          <div>
            <p className="text-2xs uppercase tracking-wider text-slate-500">Paramètres transmis au playbook</p>
            <CodeBlock className="mt-1" value={action.params} maxHeight={160} />
          </div>

          {step === 'review' ? (
            <>
              {meta.comment !== null ? (
                <div>
                  <label className="soc-label" htmlFor="action-dialog-comment">
                    {meta.comment.label}
                    {meta.comment.required ? ' — obligatoire' : ' — facultatif'}
                  </label>
                  <textarea
                    id="action-dialog-comment"
                    className="soc-textarea"
                    value={comment}
                    autoFocus
                    placeholder={meta.comment.placeholder}
                    onChange={(event) => setComment(event.target.value)}
                  />
                </div>
              ) : (
                <p className="text-2xs text-slate-500">
                  L’API <code className="soc-code-inline">POST /actions/{'{id}'}/{operation}</code> n’accepte pas de
                  corps : aucun motif n’est transmis. L’exécution est journalisée côté serveur (acteur, policy,
                  avant/après).
                </p>
              )}

              <Checkbox checked={acknowledged} onChange={setAcknowledged} label={meta.acknowledge} />

              {error ? <InlineNotice tone="danger">{error}</InlineNotice> : null}

              <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-800 pt-2.5">
                {!reviewReady ? (
                  <p className="mr-auto text-2xs text-slate-500">
                    {!commentSatisfied
                      ? 'Un motif est obligatoire pour continuer.'
                      : 'Cochez la case d’engagement pour continuer.'}
                  </p>
                ) : null}
                <Button variant="ghost" onClick={onCancel} disabled={busy}>
                  Annuler
                </Button>
                <Button
                  variant={meta.tone === 'danger' ? 'danger' : meta.tone === 'warn' ? 'warn' : 'primary'}
                  onClick={() => setStep('final')}
                  disabled={!reviewReady}
                >
                  {meta.confirmLabel}
                </Button>
              </footer>
            </>
          ) : (
            <>
              <InlineNotice tone="info" title="Confirmation finale">
                Recopiez la cible ci-dessous pour armer le bouton. Cette seconde validation ne peut pas être
                déclenchée par un simple double-clic.
              </InlineNotice>

              <Field
                label="Cible à recopier"
                htmlFor="action-dialog-token"
                hint="Copie exacte attendue : identifiant d’action si la cible n’est pas renseignée."
              >
                <p className="soc-code-inline mb-1 inline-block select-all">{confirmToken}</p>
                <input
                  id="action-dialog-token"
                  className="soc-input font-mono"
                  value={tokenInput}
                  autoFocus
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="saisie manuelle"
                  onChange={(event) => setTokenInput(event.target.value)}
                />
              </Field>

              {error ? <InlineNotice tone="danger">{error}</InlineNotice> : null}

              <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-800 pt-2.5">
                <Button variant="ghost" onClick={() => setStep('review')} disabled={busy}>
                  Retour
                </Button>
                <Button variant="ghost" onClick={onCancel} disabled={busy}>
                  Annuler
                </Button>
                <Button
                  variant={meta.tone === 'danger' ? 'danger' : meta.tone === 'warn' ? 'warn' : 'primary'}
                  busy={busy}
                  disabled={!finalReady || rollbackBlocked}
                  onClick={() => onConfirm({ operation, actionId: action.action_id, comment: comment.trim() })}
                >
                  {meta.finalLabel}
                </Button>
              </footer>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
