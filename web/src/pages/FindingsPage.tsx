/**
 * Page « Findings » : liste filtrable (table) + panneau de détail.
 *
 * Le finding ouvert est reflété dans l'URL (`/findings?focus=<finding_id>`), ce
 * qui permet de pointer un finding précis depuis le tableau de bord, de partager
 * le lien et de conserver la sélection après un rafraîchissement — sans jamais
 * mettre d'identifiant de tenant ni de clé dans l'URL.
 */
import { useCallback } from 'react';
import type { JSX } from 'react';
import { useSearchParams } from 'react-router-dom';

import { FindingDetail } from '@/components/FindingDetail';
import { FindingsTable } from '@/components/FindingsTable';
import { PageHeader } from '@/components/ui';

export function FindingsPage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const focus = searchParams.get('focus');

  const selectFinding = useCallback(
    (findingId: string) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          next.set('focus', findingId);
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const closeDetail = useCallback(() => {
    setSearchParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        next.delete('focus');
        return next;
      },
      { replace: true },
    );
  }, [setSearchParams]);

  return (
    <div className="space-y-3">
      <PageHeader
        title="Findings"
        description="Détections agrégées par règle. Les preuves contiennent des charges d’attaque brutes : elles sont affichées en texte, jamais interprétées. Sélectionnez une ligne pour ouvrir le détail, la décision, les garde-fous et le rapport."
      />

      <FindingsTable selectedId={focus} onSelect={selectFinding} />

      {focus !== null ? <FindingDetail findingId={focus} onClose={closeDetail} /> : null}
    </div>
  );
}
