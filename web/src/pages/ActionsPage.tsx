/**
 * Page « Actions » : cycle de vie SOAR complet.
 *
 * Rappel affiché à l'opérateur : planifier (`POST /actions/plan`) est sans effet
 * de bord ; approuver, exécuter et annuler sont des mutations journalisées, et
 * chaque exécution exige ici une double confirmation explicite. Le bandeau
 * `dry_run` / mode d'autonomie est dupliqué en version complète, car c'est sur
 * cette page qu'une levée de garde-fou aurait des conséquences réelles.
 */
import { ActionsTable } from '@/components/ActionsTable';
import { AutonomyBanner } from '@/components/AutonomyBanner';
import { PageHeader, Panel } from '@/components/ui';
import { useAuth } from '@/lib/auth';

const LIFECYCLE: readonly { status: string; meaning: string }[] = [
  { status: 'planned', meaning: 'Planifiée sans effet de bord (`POST /actions/plan`).' },
  { status: 'pending_approval', meaning: 'Une décision humaine est requise ; l’exécution est refusée (409).' },
  { status: 'approved', meaning: 'Approuvée : l’exécution est possible, sous réserve du dry-run global.' },
  { status: 'rejected', meaning: 'Rejetée — statut terminal, aucune exécution ultérieure.' },
  { status: 'executing', meaning: 'Exécution en cours (playbook appliqué par le connecteur).' },
  { status: 'succeeded', meaning: 'Réussie ; le rollback reste disponible tant qu’il n’a pas expiré.' },
  { status: 'failed', meaning: 'Échec ; consulter `result` et le journal d’audit associé.' },
  { status: 'expired', meaning: 'Approbation expirée (THOT_APPROVE_TTL_SECONDS) : à replanifier.' },
  { status: 'rolled_back', meaning: 'Annulée — statut terminal ; le rollback ne peut pas être rejoué.' },
];

export function ActionsPage(): JSX.Element {
  const { tenantId, autonomy, dryRun } = useAuth();

  return (
    <div className="space-y-3">
      <PageHeader
        title="Actions SOAR"
        description="Approbation, exécution et rollback des playbooks. Chaque opération est journalisée dans l’audit chaîné (acteur, policy, état avant/après) et exige une double confirmation explicite."
      />

      <AutonomyBanner mode={autonomy} dryRun={dryRun} tenantId={tenantId} />

      <ActionsTable />

      <Panel title="Cycle de vie d’une action (contrat §3.4)">
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
          {LIFECYCLE.map((entry) => (
            <div key={entry.status} className="flex gap-2">
              <dt className="w-32 shrink-0">
                <code className="soc-code-inline">{entry.status}</code>
              </dt>
              <dd className="text-2xs text-slate-300">{entry.meaning}</dd>
            </div>
          ))}
        </dl>
        <p className="mt-2 text-2xs text-slate-500">
          Toute action dispose d’un rollback : si le connecteur n’est pas configuré, il fonctionne en mode simulé et
          retourne malgré tout un jeton de rollback (contrat §7). Thot Secure est donc sûr à brancher avant d’avoir
          des identifiants réels.
        </p>
      </Panel>
    </div>
  );
}
