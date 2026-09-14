import clsx from 'clsx';
import type { ReactNode } from 'react';
import type { JSX } from 'react';

export interface EmptyStateProps {
  title: string;
  description?: string;
  /** Contenu additionnel : bouton, lien, rappel de capacité requise… */
  action?: ReactNode;
  variant?: 'neutral' | 'locked';
  className?: string;
}

/**
 * État vide partagé. La variante `locked` sert aux écrans inaccessibles par
 * capacité manquante (RBAC) : on explique l'absence plutôt que d'afficher un
 * écran blanc.
 */
export function EmptyState(props: EmptyStateProps): JSX.Element {
  const { title, description, action, variant = 'neutral', className } = props;

  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed px-6 py-10 text-center',
        variant === 'locked'
          ? 'border-amber-800/60 bg-amber-950/20'
          : 'border-slate-800 bg-slate-900/40',
        className,
      )}
    >
      <p
        className={clsx(
          'text-sm font-medium',
          variant === 'locked' ? 'text-amber-200' : 'text-slate-200',
        )}
      >
        {title}
      </p>
      {description ? (
        <p className="max-w-xl text-xs text-slate-400">{description}</p>
      ) : null}
      {action}
    </div>
  );
}
