/**
 * Page « Règles & politiques » : bibliothèque de détection YAML et décision
 * policy-as-code. Chaque panneau gère lui-même le masquage lié à ses capacités
 * (`read:rules` / `read:policies`, administration `admin:rules` /
 * `admin:policies`).
 */
import { PoliciesPanel } from '@/components/PoliciesPanel';
import { RulesPanel } from '@/components/RulesPanel';
import { PageHeader } from '@/components/ui';
import type { JSX } from 'react';

export function RulesPage(): JSX.Element {
  return (
    <div className="space-y-3">
      <PageHeader
        title="Règles & politiques"
        description="Les règles décident de ce qui devient un finding ; les politiques décident de ce qui en est fait. Toute règle invalide est rejetée avec un diagnostic sans casser le chargement, et une politique absente laisse la décision à notify_only."
      />

      <RulesPanel />
      <PoliciesPanel />
    </div>
  );
}
