/**
 * Page « Audit » : journal chaîné append-only et vérification d'intégrité.
 */
import { AuditLog } from '@/components/AuditLog';
import { PageHeader } from '@/components/ui';

export function AuditPage(): JSX.Element {
  return (
    <div className="space-y-3">
      <PageHeader
        title="Journal d’audit"
        description="Journal append-only chaîné par hash : chaque enregistrement référence le précédent (`prev_hash`) et porte son propre `hash`. La vérification d’intégrité interroge GET /api/v1/audit/verify et affiche un verdict — en rouge si la chaîne est rompue."
      />

      <AuditLog />
    </div>
  );
}
