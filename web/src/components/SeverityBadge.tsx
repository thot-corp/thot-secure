import clsx from 'clsx';

import { SEVERITY_BADGE_CLASSES, SEVERITY_LABELS } from '@/lib/format';
import type { Severity } from '@/lib/types';
import type { JSX } from 'react';

export interface SeverityBadgeProps {
  severity: Severity | null | undefined;
  /** Contexte `severity_hint` d'un événement (valeur possiblement absente). */
  hint?: boolean;
  size?: 'sm' | 'md';
  className?: string;
}

/**
 * Pastille de sévérité. `severity` provient de données serveur ; en son absence
 * on affiche explicitement « non qualifiée » plutôt qu'une couleur trompeuse.
 */
export function SeverityBadge(props: SeverityBadgeProps): JSX.Element {
  const { severity, hint = false, size = 'sm', className } = props;

  const base = clsx(
    'inline-flex items-center gap-1 rounded border px-1.5 font-medium uppercase tracking-wide',
    size === 'sm' ? 'py-0.5 text-2xs' : 'py-1 text-xs',
    className,
  );

  if (!severity) {
    return (
      <span
        className={clsx(base, 'border-slate-700 bg-slate-800/60 text-slate-400')}
        title={hint ? 'Aucune sévérité fournie par le collecteur' : 'Sévérité inconnue'}
      >
        {hint ? 'non qualifiée' : '—'}
      </span>
    );
  }

  return (
    <span className={clsx(base, SEVERITY_BADGE_CLASSES[severity])} title={`Sévérité : ${SEVERITY_LABELS[severity]}`}>
      <span aria-hidden="true" className="text-[0.6rem] leading-none">
        ●
      </span>
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
