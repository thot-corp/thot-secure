/**
 * Page « Soutien » : enveloppe de `components/SupportPage.tsx`, qui porte la
 * source unique de vérité des adresses de dons de l'interface riche.
 *
 * Adresses officielles rendues par cette page (reproduction de contrôle :
 * **la valeur de référence reste celle de `src/components/SupportPage.tsx`,
 * identique à `FUNDING_ADDRESSES` côté serveur et à `docs/support.md`**) :
 *
 *   Bitcoin (BTC, réseau Bitcoin mainnet) : 33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR
 *   Solana  (SOL, réseau Solana mainnet)  : 95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi
 *
 * « Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse
 * depuis le dépôt officiel. » — Thot Secure ne demandera jamais de clé privée ni
 * de phrase de récupération.
 */
import { SupportPage as SupportContent } from '@/components/SupportPage';
import { PageHeader } from '@/components/ui';
import type { JSX } from 'react';

export function SupportPage(): JSX.Element {
  return (
    <div className="space-y-3">
      <PageHeader
        title="Soutenir le projet"
        description="Thot Secure est un logiciel libre (Apache-2.0) maintenu sur du temps bénévole. Les adresses ci-dessous sont les seules officielles ; elles sont identiques à celles publiées par GET /ui/support et docs/support.md."
      />

      <SupportContent />
    </div>
  );
}
