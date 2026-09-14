import clsx from 'clsx';

import {
  AUTONOMY_CLASSES,
  AUTONOMY_DESCRIPTIONS,
  AUTONOMY_LABELS,
} from '@/lib/format';
import type { AutonomyMode } from '@/lib/types';
import type { JSX } from 'react';

export interface AutonomyBannerProps {
  mode: AutonomyMode;
  /** `true` : aucune action réelle ne sera exécutée par le moteur. */
  dryRun: boolean;
  tenantId?: string | null;
  /** Variante compacte pour la barre supérieure. */
  compact?: boolean;
  className?: string;
}

/**
 * Bandeau de sûreté **permanent** : il rappelle en continu le mode d'autonomie
 * et l'état `dry_run` du tenant courant. Exigence produit non négociable : ces
 * deux informations ne doivent jamais être masquées ni reléguées à une page de
 * réglages. En cas de doute (données non chargées), l'appelant passe
 * `mode="manual"` et `dryRun={true}` : le doute penche du côté sûr.
 */
export function AutonomyBanner(props: AutonomyBannerProps): JSX.Element {
  const { mode, dryRun, tenantId, compact = false, className } = props;

  return (
    <div
      className={clsx(
        'flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs',
        compact ? '' : 'shadow-panel',
        className,
      )}
      role="status"
      aria-live="polite"
    >
      <span
        className={clsx(
          'inline-flex items-center gap-1 rounded border px-2 py-0.5 font-semibold uppercase tracking-wide',
          AUTONOMY_CLASSES[mode],
        )}
        title={AUTONOMY_DESCRIPTIONS[mode]}
      >
        Autonomie : {AUTONOMY_LABELS[mode]}
      </span>

      {dryRun ? (
        <span
          className="inline-flex items-center gap-1 rounded border border-amber-600 bg-amber-950/70 px-2 py-0.5 font-semibold uppercase tracking-wide text-amber-200"
          title="THOT_DRY_RUN=true : les playbooks sont simulés, aucune contre-mesure réelle n'est appliquée."
        >
          <span aria-hidden="true">🛡</span> Dry-run actif — aucune action réelle
        </span>
      ) : (
        <span
          className="inline-flex items-center gap-1 rounded border border-rose-600 bg-rose-950/80 px-2 py-0.5 font-semibold uppercase tracking-wide text-rose-200"
          title="DRY_RUN=false : les playbooks agissent réellement sur les cibles. Toute exécution exige une double confirmation."
        >
          <span aria-hidden="true">⚠</span> Exécution réelle armée
        </span>
      )}

      {tenantId ? (
        <span className="text-slate-400">
          tenant <span className="font-mono text-slate-200">{tenantId}</span>
        </span>
      ) : null}
    </div>
  );
}
