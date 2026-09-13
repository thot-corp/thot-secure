/**
 * Helpers de présentation : couleurs par sévérité/statut, formats de date et de
 * durée, sérialisation sûre. **Aucune** de ces fonctions ne produit de HTML :
 * tout passe par des nœuds texte React, ce qui neutralise les payloads
 * d'attaque contenus dans les preuves de finding.
 */
import type {
  ActionStatus,
  AutonomyMode,
  DecisionKind,
  FindingStatus,
  JsonValue,
  Severity,
} from './types';

/* -------------------------------------------------------------------------- */
/* Sévérité                                                                    */
/* -------------------------------------------------------------------------- */

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  info: 'Info',
  low: 'Faible',
  medium: 'Moyenne',
  high: 'Élevée',
  critical: 'Critique',
};

/** Classes de la pastille de sévérité (fond + texte + bordure). */
export const SEVERITY_BADGE_CLASSES: Record<Severity, string> = {
  info: 'bg-sky-950/70 text-sky-300 border-sky-800',
  low: 'bg-emerald-950/70 text-emerald-300 border-emerald-800',
  medium: 'bg-amber-950/70 text-amber-300 border-amber-800',
  high: 'bg-orange-950/70 text-orange-300 border-orange-800',
  critical: 'bg-rose-950/80 text-rose-300 border-rose-700',
};

export const SEVERITY_TEXT_CLASSES: Record<Severity, string> = {
  info: 'text-sky-300',
  low: 'text-emerald-300',
  medium: 'text-amber-300',
  high: 'text-orange-300',
  critical: 'text-rose-300',
};

export const SEVERITY_DOT_CLASSES: Record<Severity, string> = {
  info: 'bg-sky-400',
  low: 'bg-emerald-400',
  medium: 'bg-amber-400',
  high: 'bg-orange-400',
  critical: 'bg-rose-500',
};

/** Couleur de l'anneau de risque (jauge). */
export function riskColor(score: number): string {
  if (score >= 85) return '#f43f5e';
  if (score >= 70) return '#fb923c';
  if (score >= 45) return '#f59e0b';
  if (score >= 20) return '#22d3ee';
  return '#34d399';
}

/* -------------------------------------------------------------------------- */
/* Statuts                                                                     */
/* -------------------------------------------------------------------------- */

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  open: 'Ouvert',
  acked: 'Pris en compte',
  closed: 'Clôturé',
  suppressed: 'Supprimé',
};

export const FINDING_STATUS_CLASSES: Record<FindingStatus, string> = {
  open: 'bg-rose-950/60 text-rose-300 border-rose-800',
  acked: 'bg-cyan-950/60 text-cyan-300 border-cyan-800',
  closed: 'bg-slate-800/70 text-slate-300 border-slate-700',
  suppressed: 'bg-violet-950/60 text-violet-300 border-violet-800',
};

export const ACTION_STATUS_LABELS: Record<ActionStatus, string> = {
  planned: 'Planifiée',
  pending_approval: 'En attente d’approbation',
  approved: 'Approuvée',
  rejected: 'Rejetée',
  executing: 'En cours',
  succeeded: 'Réussie',
  failed: 'Échouée',
  expired: 'Expirée',
  rolled_back: 'Annulée',
};

export const ACTION_STATUS_CLASSES: Record<ActionStatus, string> = {
  planned: 'bg-slate-800/70 text-slate-300 border-slate-700',
  pending_approval: 'bg-amber-950/70 text-amber-300 border-amber-800',
  approved: 'bg-cyan-950/60 text-cyan-300 border-cyan-800',
  rejected: 'bg-slate-800/70 text-slate-400 border-slate-700',
  executing: 'bg-sky-950/70 text-sky-300 border-sky-800',
  succeeded: 'bg-emerald-950/70 text-emerald-300 border-emerald-800',
  failed: 'bg-rose-950/80 text-rose-300 border-rose-700',
  expired: 'bg-slate-800/70 text-slate-400 border-slate-700',
  rolled_back: 'bg-violet-950/60 text-violet-300 border-violet-800',
};

/** Statuts terminaux : aucune transition possible (contrat §3.4). */
export const ACTION_TERMINAL_STATUSES: readonly ActionStatus[] = [
  'rejected',
  'succeeded',
  'failed',
  'expired',
  'rolled_back',
];

export function isActionTerminal(status: ActionStatus): boolean {
  return ACTION_TERMINAL_STATUSES.includes(status);
}

export const DECISION_LABELS: Record<DecisionKind, string> = {
  auto: 'Automatique',
  require_approval: 'Approbation requise',
  notify_only: 'Notification seule',
  ignore: 'Ignorée',
};

export const DECISION_CLASSES: Record<DecisionKind, string> = {
  auto: 'bg-rose-950/70 text-rose-300 border-rose-800',
  require_approval: 'bg-amber-950/70 text-amber-300 border-amber-800',
  notify_only: 'bg-cyan-950/60 text-cyan-300 border-cyan-800',
  ignore: 'bg-slate-800/70 text-slate-400 border-slate-700',
};

export const AUTONOMY_LABELS: Record<AutonomyMode, string> = {
  manual: 'Manuel',
  supervised: 'Supervisé',
  auto: 'Automatique',
};

export const AUTONOMY_CLASSES: Record<AutonomyMode, string> = {
  manual: 'bg-slate-800/70 text-slate-200 border-slate-600',
  supervised: 'bg-cyan-950/70 text-cyan-200 border-cyan-700',
  auto: 'bg-rose-950/80 text-rose-200 border-rose-700',
};

export const AUTONOMY_DESCRIPTIONS: Record<AutonomyMode, string> = {
  manual: 'Toute action doit être planifiée puis approuvée explicitement.',
  supervised: 'Les actions sont proposées et exécutées après approbation humaine.',
  auto: 'Les politiques peuvent exécuter des actions sans approbation humaine.',
};

/* -------------------------------------------------------------------------- */
/* Dates, durées, nombres                                                      */
/* -------------------------------------------------------------------------- */

const DASH = '—';

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** `2026-02-14T10:00:00Z` → `14/02/2026 10:00:00` (heure locale). */
export function formatDateTime(value: string | null | undefined): string {
  const date = parseDate(value);
  if (!date) return DASH;
  return new Intl.DateTimeFormat('fr-FR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

/** `10:00:00.123` (précision milliseconde, pour le flux live). */
export function formatClockTime(value: string | number | null | undefined): string {
  const date = typeof value === 'number' ? new Date(value) : parseDate(value);
  if (!date) return DASH;
  return new Intl.DateTimeFormat('fr-FR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
    hour12: false,
  }).format(date);
}

/** « il y a 3 min », « dans 2 h ». */
export function formatRelative(value: string | number | null | undefined, now = Date.now()): string {
  const target =
    typeof value === 'number' ? value : (parseDate(value ?? null)?.getTime() ?? null);
  if (target === null) return DASH;
  const deltaSeconds = Math.round((target - now) / 1000);
  const absolute = Math.abs(deltaSeconds);
  const suffix = deltaSeconds < 0 ? 'il y a' : 'dans';
  if (absolute < 5) return 'à l’instant';
  if (absolute < 60) return `${suffix} ${absolute} s`;
  if (absolute < 3600) return `${suffix} ${Math.round(absolute / 60)} min`;
  if (absolute < 86400) return `${suffix} ${Math.round(absolute / 3600)} h`;
  return `${suffix} ${Math.round(absolute / 86400)} j`;
}

/** Durée en secondes → `1 h 30 min`, `45 s`. */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return DASH;
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) return `${total} s`;
  if (total < 3600) {
    const minutes = Math.floor(total / 60);
    const rest = total % 60;
    return rest === 0 ? `${minutes} min` : `${minutes} min ${rest} s`;
  }
  const hours = Math.floor(total / 3600);
  const minutes = Math.round((total % 3600) / 60);
  return minutes === 0 ? `${hours} h` : `${hours} h ${minutes} min`;
}

export function formatNumber(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return new Intl.NumberFormat('fr-FR', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(value);
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  // `confidence` du contrat est une fraction 0→1.
  return `${formatNumber(value * 100, digits)} %`;
}

export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return formatNumber(value, 1);
}

/* -------------------------------------------------------------------------- */
/* Divers                                                                      */
/* -------------------------------------------------------------------------- */

/** Tronque une chaîne longue pour un affichage en cellule (jamais de HTML). */
export function truncate(value: string | null | undefined, max = 80): string {
  if (!value) return DASH;
  return value.length <= max ? value : `${value.slice(0, Math.max(0, max - 1))}…`;
}

/** Hash d'audit : `sha256:abcd…` → `sha256:abcd…wxyz` (gardé lisible). */
export function abbreviateHash(hash: string | null | undefined, keep = 8): string {
  if (!hash) return DASH;
  const [prefix, digest] = hash.includes(':') ? hash.split(':', 2) : ['', hash];
  const head = (digest ?? '').slice(0, keep);
  const tail = (digest ?? '').slice(-keep);
  return prefix ? `${prefix}:${head}…${tail}` : `${head}…${tail}`;
}

/** Sérialise une valeur JSON quelconque pour affichage — jamais de HTML. */
export function stringifyJson(value: JsonValue | undefined | null, space = 2): string {
  if (value === undefined || value === null) return DASH;
  try {
    return JSON.stringify(value, null, space);
  } catch {
    return '[valeur non sérialisable]';
  }
}

/** Convertit une valeur inconnue en texte sûr (utilisé pour les preuves). */
export function toDisplayText(value: unknown): string {
  if (value === null || value === undefined) return DASH;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return stringifyJson(value as JsonValue, 0);
}

/** Clamp utilitaire pour la jauge de risque (bornes 0–100 du contrat). */
export function clampScore(score: number | null | undefined): number {
  if (score === null || score === undefined || !Number.isFinite(score)) return 0;
  return Math.min(100, Math.max(0, score));
}

export { DASH as EMPTY_DISPLAY };
