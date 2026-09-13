/**
 * Primitives d'interface partagées (panneaux, boutons, champs, avis, boîte de
 * confirmation).
 *
 * Règles de sûreté appliquées ici :
 *  - **aucun** `dangerouslySetInnerHTML` : tout contenu serveur (titres de
 *    finding, charges d'attaque des preuves, YAML de règle) est rendu comme
 *    nœud texte React, donc échappé par construction ;
 *  - `ConfirmDialog` impose une **double confirmation explicite** : un
 *    engagement explicite (case à cocher), puis la recopie manuelle d'un jeton
 *    (identifiant d'action ou cible). Il est utilisé pour toute opération
 *    destructive ou irréversible ;
 *  - `LockedNotice` matérialise le masquage RBAC : quand la capacité manque, on
 *    explique l'absence au lieu d'afficher un contrôle qui échouerait en 403.
 */
import clsx from 'clsx';
import { useEffect, useId, useState } from 'react';
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react';

import { EmptyState } from './EmptyState';
import { errorMessage } from '@/lib/api';
import { CAPABILITY_LABELS } from '@/lib/capabilities';
import type { Capability } from '@/lib/types';

/* -------------------------------------------------------------------------- */
/* Panneau                                                                     */
/* -------------------------------------------------------------------------- */

export interface PanelProps {
  title?: ReactNode;
  description?: ReactNode;
  /** Contrôles alignés à droite de l'en-tête (filtres, boutons). */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  id?: string;
}

export function Panel(props: PanelProps): JSX.Element {
  const { title, description, actions, children, className, bodyClassName, id } = props;
  const hasHeader = Boolean(title || description || actions);

  return (
    <section id={id} className={clsx('soc-panel', className)}>
      {hasHeader ? (
        <header className="soc-panel-header">
          <div className="min-w-0">
            {title ? <h2 className="truncate">{title}</h2> : null}
            {description ? (
              <p className="mt-0.5 text-2xs leading-relaxed text-slate-400">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex flex-wrap items-center gap-1.5">{actions}</div> : null}
        </header>
      ) : null}
      <div className={clsx('soc-panel-body', bodyClassName)}>{children}</div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Boutons                                                                     */
/* -------------------------------------------------------------------------- */

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'warn' | 'ghost';

const BUTTON_VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: 'soc-btn-primary',
  secondary: 'soc-btn-secondary',
  danger: 'soc-btn-danger',
  warn: 'soc-btn-warn',
  ghost: 'soc-btn-ghost',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: 'sm' | 'md';
  /** Affiche un indicateur et neutralise le bouton pendant la mutation. */
  busy?: boolean;
}

export function Button(props: ButtonProps): JSX.Element {
  const {
    variant = 'secondary',
    size = 'md',
    busy = false,
    className,
    children,
    disabled,
    type,
    ...rest
  } = props;

  return (
    <button
      {...rest}
      type={type ?? 'button'}
      disabled={disabled === true || busy}
      aria-busy={busy ? true : undefined}
      className={clsx('soc-btn', size === 'sm' && 'soc-btn-sm', BUTTON_VARIANT_CLASS[variant], className)}
    >
      {busy ? (
        <span
          aria-hidden="true"
          className="inline-block h-2 w-2 animate-spin rounded-full border border-current border-t-transparent"
        />
      ) : null}
      {children}
    </button>
  );
}

/* -------------------------------------------------------------------------- */
/* Champs                                                                      */
/* -------------------------------------------------------------------------- */

export interface FieldProps {
  label: ReactNode;
  htmlFor?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function Field(props: FieldProps): JSX.Element {
  const { label, htmlFor, hint, children, className } = props;
  return (
    <div className={clsx('min-w-0', className)}>
      <label className="soc-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {hint ? <p className="mt-0.5 text-2xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

export interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: ReactNode;
  hint?: ReactNode;
}

export function TextInput(props: TextInputProps): JSX.Element {
  const { label, hint, className, id, ...rest } = props;
  const generatedId = useId();
  const inputId = id ?? generatedId;
  const control = <input id={inputId} className={clsx('soc-input', className)} {...rest} />;
  if (!label) return control;
  return (
    <Field label={label} htmlFor={inputId} hint={hint}>
      {control}
    </Field>
  );
}

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: ReactNode;
  hint?: ReactNode;
}

export function Select(props: SelectProps): JSX.Element {
  const { label, hint, className, id, children, ...rest } = props;
  const generatedId = useId();
  const selectId = id ?? generatedId;
  const control = (
    <select id={selectId} className={clsx('soc-select', className)} {...rest}>
      {children}
    </select>
  );
  if (!label) return control;
  return (
    <Field label={label} htmlFor={selectId} hint={hint}>
      {control}
    </Field>
  );
}

export interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: ReactNode;
  hint?: ReactNode;
}

export function TextArea(props: TextAreaProps): JSX.Element {
  const { label, hint, className, id, ...rest } = props;
  const generatedId = useId();
  const areaId = id ?? generatedId;
  const control = <textarea id={areaId} className={clsx('soc-textarea', className)} {...rest} />;
  if (!label) return control;
  return (
    <Field label={label} htmlFor={areaId} hint={hint}>
      {control}
    </Field>
  );
}

export interface CheckboxProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: ReactNode;
  disabled?: boolean;
  className?: string;
}

export function Checkbox(props: CheckboxProps): JSX.Element {
  const { checked, onChange, label, disabled = false, className } = props;
  const id = useId();
  return (
    <div className={clsx('flex items-start gap-2', className)}>
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-0.5 h-3.5 w-3.5 shrink-0 cursor-pointer rounded border-slate-600 bg-slate-950 accent-cyan-500 disabled:cursor-not-allowed"
      />
      <label htmlFor={id} className="cursor-pointer text-2xs leading-snug text-slate-300">
        {label}
      </label>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Avis, états                                                                 */
/* -------------------------------------------------------------------------- */

export type NoticeTone = 'info' | 'warn' | 'danger' | 'success';

const NOTICE_TONE_CLASS: Record<NoticeTone, string> = {
  info: 'border-cyan-800 bg-cyan-950/40 text-cyan-100',
  warn: 'border-amber-700 bg-amber-950/40 text-amber-100',
  danger: 'border-rose-800 bg-rose-950/50 text-rose-100',
  success: 'border-emerald-800 bg-emerald-950/40 text-emerald-100',
};

const NOTICE_TONE_TITLE_CLASS: Record<NoticeTone, string> = {
  info: 'text-cyan-200',
  warn: 'text-amber-200',
  danger: 'text-rose-200',
  success: 'text-emerald-200',
};

export interface InlineNoticeProps {
  tone: NoticeTone;
  title?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Par défaut : `alert` pour `danger`, sinon `status`. */
  role?: 'status' | 'alert' | 'note';
}

export function InlineNotice(props: InlineNoticeProps): JSX.Element {
  const { tone, title, children, className, role } = props;
  return (
    <div
      role={role ?? (tone === 'danger' ? 'alert' : 'status')}
      className={clsx('rounded-md border px-2.5 py-2 text-2xs leading-relaxed', NOTICE_TONE_CLASS[tone], className)}
    >
      {title ? <p className={clsx('mb-0.5 font-semibold', NOTICE_TONE_TITLE_CLASS[tone])}>{title}</p> : null}
      <div className="space-y-1">{children}</div>
    </div>
  );
}

export interface LoadingBlockProps {
  label?: string;
  rows?: number;
  className?: string;
}

export function LoadingBlock(props: LoadingBlockProps): JSX.Element {
  const { label = 'Chargement…', rows = 3, className } = props;
  const placeholders = Array.from({ length: Math.max(1, rows) }, (_, index) => index);
  return (
    <div className={clsx('space-y-1.5', className)} role="status" aria-live="polite">
      <p className="text-2xs text-slate-400">{label}</p>
      {placeholders.map((index) => (
        <div key={index} className="h-3 w-full animate-pulse rounded bg-slate-800/70" />
      ))}
    </div>
  );
}

export interface ErrorNoticeProps {
  error: unknown;
  title?: string;
  onRetry?: () => void;
  className?: string;
}

/** Affiche une erreur d'API sous forme de texte brut (jamais de HTML injecté). */
export function ErrorNotice(props: ErrorNoticeProps): JSX.Element | null {
  const { error, title = 'Échec du chargement', onRetry, className } = props;
  if (!error) return null;
  return (
    <div className={clsx('rounded-md border border-rose-800 bg-rose-950/40 p-2.5', className)} role="alert">
      <p className="text-xs font-semibold text-rose-100">{title}</p>
      <p className="mt-0.5 break-words text-2xs text-rose-200/90">{errorMessage(error)}</p>
      {onRetry ? (
        <Button variant="danger" size="sm" className="mt-2" onClick={onRetry}>
          Réessayer
        </Button>
      ) : null}
    </div>
  );
}

export interface LockedNoticeProps {
  /** Capacité manquante qui justifie le masquage. */
  capability: Capability;
  description?: string;
  className?: string;
}

/**
 * Écran « accès masqué ». Défense en profondeur : le masquage côté client évite
 * qu'un utilisateur déclenche par erreur une action qui lui sera refusée ; le
 * serveur revérifie de toute façon (`403 forbidden`).
 */
export function LockedNotice(props: LockedNoticeProps): JSX.Element {
  const { capability, description, className } = props;
  return (
    <EmptyState
      variant="locked"
      className={className}
      title={`Accès masqué — capacité « ${capability} » requise`}
      description={
        description ??
        `Votre rôle ne dispose pas de la capacité « ${CAPABILITY_LABELS[capability]} ». Contactez un administrateur pour obtenir une clé API au rôle adapté. Le serveur applique ce contrôle indépendamment de cette interface.`
      }
    />
  );
}

/* -------------------------------------------------------------------------- */
/* Affichage de données                                                        */
/* -------------------------------------------------------------------------- */

export interface StatusPillProps {
  label: ReactNode;
  className?: string;
  title?: string;
}

export function StatusPill(props: StatusPillProps): JSX.Element {
  const { label, className, title } = props;
  return (
    <span
      title={title}
      className={clsx(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide',
        className ?? 'border-slate-700 bg-slate-800/70 text-slate-300',
      )}
    >
      {label}
    </span>
  );
}

export interface KeyValueItem {
  label: ReactNode;
  value: ReactNode;
  /** Occupe toute la largeur (JSON, listes, adresses). */
  wide?: boolean;
  mono?: boolean;
}

export interface KeyValueListProps {
  items: readonly KeyValueItem[];
  columns?: 1 | 2 | 3;
  className?: string;
}

export function KeyValueList(props: KeyValueListProps): JSX.Element {
  const { items, columns = 2, className } = props;
  const gridClass =
    columns === 1 ? 'grid-cols-1' : columns === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-3';

  return (
    <dl className={clsx('grid gap-x-4 gap-y-1.5', gridClass, className)}>
      {items.map((item, index) => (
        <div key={index} className={clsx('min-w-0', item.wide === true && 'sm:col-span-full')}>
          <dt className="text-2xs uppercase tracking-wider text-slate-500">{item.label}</dt>
          <dd className={clsx('break-words text-xs text-slate-200', item.mono === true && 'font-mono text-2xs')}>
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export interface CodeBlockProps {
  /**
   * Valeur quelconque : chaîne (YAML, rapport), objet JSON (`params`, `result`,
   * `evidence`). Elle est **sérialisée en texte** puis rendue comme nœud texte :
   * aucune interprétation HTML, donc aucune exécution possible.
   */
  value: unknown;
  /** Rendu à la place d'une valeur absente. */
  emptyLabel?: string;
  className?: string;
  /** Hauteur maximale en pixels (défilement au-delà). */
  maxHeight?: number;
}

function serializeForDisplay(value: unknown, emptyLabel: string): string {
  if (value === null || value === undefined) return emptyLabel;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value, null, 2) ?? emptyLabel;
  } catch {
    return '[valeur non sérialisable]';
  }
}

/**
 * Bloc de texte monospace. Utilisé pour les preuves de finding (charges
 * d'attaque réelles), le YAML de règle et les objets JSON `params`/`result` :
 * le contenu est toujours rendu comme **texte**, jamais comme balisage.
 */
export function CodeBlock(props: CodeBlockProps): JSX.Element {
  const { value, emptyLabel = '—', className, maxHeight } = props;
  const text = serializeForDisplay(value, emptyLabel);

  return (
    <pre
      className={clsx('soc-pre', className)}
      style={maxHeight === undefined ? undefined : { maxHeight: `${maxHeight}px` }}
    >
      {text}
    </pre>
  );
}

export interface BarSegment {
  label: string;
  value: number;
  className: string;
}

/** Barre de répartition (sévérités, statuts) — un segment par catégorie. */
export function DistributionBar(props: { segments: readonly BarSegment[]; className?: string }): JSX.Element {
  const { segments, className } = props;
  const total = segments.reduce((sum, segment) => sum + Math.max(0, segment.value), 0);

  return (
    <div className={clsx('space-y-1', className)}>
      <div className="soc-bar" role="img" aria-label={segments.map((s) => `${s.label}: ${s.value}`).join(', ')}>
        {total === 0
          ? null
          : segments.map((segment) =>
              segment.value <= 0 ? null : (
                <span
                  key={segment.label}
                  className={segment.className}
                  style={{ width: `${(segment.value / total) * 100}%` }}
                  title={`${segment.label} : ${segment.value}`}
                />
              ),
            )}
      </div>
      <ul className="flex flex-wrap gap-x-3 gap-y-0.5">
        {segments.map((segment) => (
          <li key={segment.label} className="flex items-center gap-1 text-2xs text-slate-400">
            <span aria-hidden="true" className={clsx('h-1.5 w-1.5 rounded-full', segment.className)} />
            {segment.label}
            <span className="font-mono text-slate-200">{segment.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface PageHeaderProps {
  title: string;
  description?: ReactNode;
  /** Contrôles à droite (boutons d'action, filtres globaux). */
  actions?: ReactNode;
  className?: string;
}

/** En-tête de page homogène (titre, rappel de contexte, actions). */
export function PageHeader(props: PageHeaderProps): JSX.Element {
  const { title, description, actions, className } = props;
  return (
    <div className={clsx('flex flex-wrap items-end justify-between gap-2', className)}>
      <div className="min-w-0">
        <h1>{title}</h1>
        {description ? (
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-slate-400">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-1.5">{actions}</div> : null}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Boîte de confirmation à double validation                                   */
/* -------------------------------------------------------------------------- */

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description?: ReactNode;
  /** Détails techniques (cible, identifiant, paramètres) affichés avant décision. */
  details?: ReactNode;
  /** Contenu additionnel : sélecteur de résolution, durée de suppression… */
  extra?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: 'primary' | 'warn' | 'danger';
  /**
   * Jeton que l'utilisateur doit recopier à l'identique (identifiant d'action,
   * cible…). Seconde confirmation explicite, non contournable au clavier seul.
   */
  confirmToken?: string | null;
  tokenLabel?: string;
  commentLabel?: string;
  commentPlaceholder?: string;
  commentRequired?: boolean;
  /** Case d'engagement obligatoire (responsabilité explicite de l'opérateur). */
  acknowledgeLabel?: string;
  busy?: boolean;
  error?: string | null;
  onCancel: () => void;
  onConfirm: (comment: string) => void;
}

export function ConfirmDialog(props: ConfirmDialogProps): JSX.Element | null {
  const {
    open,
    title,
    description,
    details,
    extra,
    confirmLabel,
    cancelLabel = 'Annuler',
    tone = 'danger',
    confirmToken = null,
    tokenLabel,
    commentLabel,
    commentPlaceholder,
    commentRequired = false,
    acknowledgeLabel,
    busy = false,
    error = null,
    onCancel,
    onConfirm,
  } = props;

  const [comment, setComment] = useState('');
  const [tokenInput, setTokenInput] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const commentId = useId();
  const tokenId = useId();

  // Toute ouverture (ou changement de cible) repart d'un état vierge : aucune
  // confirmation ne peut être « réutilisée » d'une opération précédente.
  useEffect(() => {
    if (!open) return;
    setComment('');
    setTokenInput('');
    setAcknowledged(false);
  }, [open, confirmToken]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onCancel]);

  if (!open) return null;

  const tokenSatisfied = confirmToken === null || tokenInput.trim() === confirmToken;
  const commentSatisfied = !commentRequired || comment.trim() !== '';
  const acknowledgementSatisfied = !acknowledgeLabel || acknowledged;
  const canConfirm = tokenSatisfied && commentSatisfied && acknowledgementSatisfied && !busy;

  const variant: ButtonVariant = tone === 'danger' ? 'danger' : tone === 'warn' ? 'warn' : 'primary';
  const confirmDisabledReason = !tokenSatisfied
    ? 'Recopiez le jeton de confirmation pour armer le bouton.'
    : !commentSatisfied
      ? 'Un commentaire est obligatoire.'
      : !acknowledgementSatisfied
        ? 'Cochez la case d’engagement.'
        : null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/80 p-4 backdrop-blur-sm"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="my-8 w-full max-w-xl rounded-lg border border-slate-700 bg-slate-900 shadow-panel"
      >
        <header className="border-b border-slate-800 px-3 py-2">
          <h2 className="text-slate-50">{title}</h2>
          {description ? <p className="mt-0.5 text-2xs text-slate-400">{description}</p> : null}
        </header>

        <form
          className="space-y-3 px-3 py-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (canConfirm) onConfirm(comment.trim());
          }}
        >
          {details ? <div className="soc-subpanel">{details}</div> : null}
          {extra}

          {commentLabel ? (
            <div>
              <label className="soc-label" htmlFor={commentId}>
                {commentLabel}
                {commentRequired ? ' — obligatoire' : ' — facultatif'}
              </label>
              <textarea
                id={commentId}
                className="soc-textarea"
                value={comment}
                autoFocus
                placeholder={commentPlaceholder}
                onChange={(event) => setComment(event.target.value)}
              />
            </div>
          ) : null}

          {confirmToken !== null ? (
            <div>
              <label className="soc-label" htmlFor={tokenId}>
                {tokenLabel ?? 'Recopiez le jeton de confirmation'}
              </label>
              <p className="soc-code-inline mb-1 inline-block select-all">{confirmToken}</p>
              <input
                id={tokenId}
                className="soc-input font-mono"
                value={tokenInput}
                autoComplete="off"
                spellCheck={false}
                placeholder="saisie manuelle"
                onChange={(event) => setTokenInput(event.target.value)}
              />
            </div>
          ) : null}

          {acknowledgeLabel ? (
            <Checkbox checked={acknowledged} onChange={setAcknowledged} label={acknowledgeLabel} />
          ) : null}

          {error ? <InlineNotice tone="danger">{error}</InlineNotice> : null}

          <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-800 pt-2.5">
            {confirmDisabledReason ? (
              <p className="mr-auto text-2xs text-slate-500">{confirmDisabledReason}</p>
            ) : null}
            <Button variant="ghost" onClick={onCancel} disabled={busy}>
              {cancelLabel}
            </Button>
            <Button type="submit" variant={variant} busy={busy} disabled={!canConfirm}>
              {confirmLabel}
            </Button>
          </footer>
        </form>
      </div>
    </div>
  );
}
