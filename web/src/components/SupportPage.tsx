/**
 * Page de soutien — **source unique de vérité des adresses de dons** dans
 * l'interface riche.
 *
 * Les mêmes valeurs existent côté serveur (`src/thotsecure/__init__.py`,
 * `FUNDING_ADDRESSES`) et sont exposées par `GET /ui/support` ainsi que par
 * `docs/support.md`. Elles sont reproduites ici à l'identique : toute
 * modification doit être appliquée aux deux endroits, et jamais depuis un canal
 * tiers.
 *
 * Précautions de fond :
 *  - les adresses sont affichées en **texte sélectionnable**, jamais transformées
 *    en lien : un lien de don peut être remplacé, pas une chaîne recopiée ;
 *  - aucun QR code ni image : rien ne doit pouvoir être substitué à l'insu de
 *    l'utilisateur ;
 *  - l'avertissement anti-arnaque est permanent et non repliable ;
 *  - la copie presse-papiers est facultative : si elle échoue (contexte non
 *    sécurisé), l'adresse reste lisible et recopiable à la main.
 */
import clsx from 'clsx';
import { useState } from 'react';
import type { JSX } from 'react';

import { Button, InlineNotice, Panel } from './ui';

export interface FundingAddress {
  /** Libellé exact attendu : symbole, nom et réseau. */
  label: string;
  symbol: 'BTC' | 'SOL';
  address: string;
}

/** Adresses de dons officielles — reprises à l'identique du dépôt. */
export const FUNDING_ADDRESSES: readonly FundingAddress[] = [
  {
    symbol: 'BTC',
    label: 'Bitcoin (BTC, réseau Bitcoin mainnet)',
    address: '33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR',
  },
  {
    symbol: 'SOL',
    label: 'Solana (SOL, réseau Solana mainnet)',
    address: '95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi',
  },
];

/** Phrase de cadrage des dons (identique à `FUNDING_DISCLAIMER` côté serveur). */
export const FUNDING_DISCLAIMER =
  "Dons volontaires, aucune contrepartie attendue. Vérifiez toujours l'adresse depuis le dépôt officiel.";

/** Avertissement anti-arnaque (identique à `FUNDING_ANTISCAM` côté serveur). */
export const FUNDING_ANTISCAM =
  "Seule la source officielle (dépôt Git et site du projet) fait foi. Thot Secure ne demandera jamais votre clé privée, votre phrase de récupération (seed) ni un accès à votre portefeuille, et n'accorde aucun avantage, support prioritaire ou fonctionnalité en échange d'un don.";

export interface SupportPageProps {
  className?: string;
}

export function SupportPage(props: SupportPageProps): JSX.Element {
  const { className } = props;
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);

  const copyAddress = async (address: string): Promise<void> => {
    try {
      if (typeof navigator === 'undefined' || navigator.clipboard === undefined) {
        throw new Error('presse-papiers indisponible');
      }
      await navigator.clipboard.writeText(address);
      setCopiedAddress(address);
      setCopyError(null);
    } catch {
      setCopyError(
        'Copie automatique indisponible (contexte non sécurisé ou permission refusée) : sélectionnez l’adresse et recopiez-la à la main.',
      );
    }
  };

  return (
    <div className={clsx('space-y-3', className)}>
      <Panel title="Soutenir Thot Secure">
        <p className="max-w-3xl text-xs leading-relaxed text-slate-200">
          Thot Secure est un logiciel libre sous licence Apache-2.0, développé et maintenu sur du temps bénévole. Les
          dons financent concrètement l’hébergement de la documentation et des miroirs, les certificats TLS, les
          audits de sécurité externes, la signature des binaires, les runners de CI/CD, la rédaction de la
          documentation et le temps de maintenance.
        </p>

        <InlineNotice tone="info" className="mt-2">
          <p className="font-semibold">{FUNDING_DISCLAIMER}</p>
        </InlineNotice>

        {copyError ? (
          <InlineNotice tone="warn" className="mt-2">
            {copyError}
          </InlineNotice>
        ) : null}

        <table className="soc-table mt-3">
          <caption>Adresses officielles de dons — aucune autre adresse n’est légitime.</caption>
          <thead>
            <tr>
              <th scope="col">Réseau</th>
              <th scope="col">Adresse</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {FUNDING_ADDRESSES.map((entry) => (
              <tr key={entry.symbol}>
                <td className="whitespace-nowrap text-xs">
                  <span className="font-semibold text-slate-100">{entry.label}</span>
                </td>
                <td>
                  <code className="soc-address">{entry.address}</code>
                  {copiedAddress === entry.address ? (
                    <p className="mt-0.5 text-2xs text-emerald-300">
                      Adresse copiée — vérifiez les premiers et derniers caractères avant tout envoi.
                    </p>
                  ) : null}
                </td>
                <td>
                  <Button size="sm" variant="secondary" onClick={() => void copyAddress(entry.address)}>
                    Copier
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <p className="mt-2 text-2xs text-slate-400">
          Aucun lien externe et aucun QR code ne sont proposés ici : une adresse affichée en texte ne peut pas être
          substituée par un lien modifié. Comparez toujours l’adresse avec celle publiée dans le dépôt officiel.
        </p>
      </Panel>

      <Panel title="⚠ Avertissement anti-arnaque">
        <InlineNotice tone="danger" title="Seule la source officielle fait foi">
          <p>{FUNDING_ANTISCAM}</p>
        </InlineNotice>

        <ul className="mt-2 list-inside list-disc space-y-1 text-2xs leading-relaxed text-slate-200">
          <li>
            Vérifiez toujours ces adresses depuis le <strong>dépôt officiel</strong> (dépôt Git et site du projet) :
            c’est la seule source qui fait autorité.
          </li>
          <li>
            Un message privé, un commentaire, un courriel ou une personne se présentant comme « mainteneur » ne sont{' '}
            <strong>jamais</strong> légitimes.
          </li>
          <li>
            Thot Secure ne demande <strong>jamais</strong> de clé privée, de phrase de récupération (seed) ni d’accès à
            un portefeuille — et aucune fonctionnalité, aucun support prioritaire et aucun avantage ne sont accordés en
            échange d’un don.
          </li>
          <li>
            En cas de doute, ne payez pas : ouvrez une <em>issue</em> publique sur le dépôt officiel pour faire
            vérifier l’adresse par la communauté.
          </li>
        </ul>

        <p className="mt-2 text-2xs text-slate-400">
          La même page est servie par l’API embarquée (<code className="soc-code-inline">GET /ui/support</code>) et
          documentée dans <code className="soc-code-inline">docs/support.md</code> : trois sources, une seule vérité.
        </p>
      </Panel>

      <Panel title="Autres façons de soutenir">
        <ul className="list-inside list-disc space-y-1 text-2xs text-slate-200">
          <li>
            <strong>GitHub Sponsors</strong> — financement récurrent et traçable.
          </li>
          <li>
            <strong>Open Collective</strong> — dépenses transparentes et publiées.
          </li>
          <li>
            <strong>Liberapay</strong> — dons récurrents sans commission de plateforme.
          </li>
        </ul>
        <p className="mt-2 text-2xs text-slate-400">
          Ces canaux sont déclarés dans <code className="soc-code-inline">.github/FUNDING.yml</code> du dépôt : si un
          canal n’y figure pas, il n’est pas officiel.
        </p>

        <h3 className="mt-3">Soutenir sans argent</h3>
        <ul className="mt-1 list-inside list-disc space-y-1 text-2xs text-slate-200">
          <li>Contribuer une règle de détection (voir CONTRIBUTING.md).</li>
          <li>Signaler un faux positif : c’est la contribution la plus utile à la qualité de la détection.</li>
          <li>Traduire la documentation ou signaler une imprécision.</li>
          <li>Dire simplement que vous utilisez l’outil dans une Discussion GitHub.</li>
        </ul>
      </Panel>

      <Panel title="Transparence">
        <p className="max-w-3xl text-xs leading-relaxed text-slate-200">
          Si le projet reçoit des dons, il publie un <strong>registre agrégé</strong> (montants totaux par période et
          par usage), jamais nominatif sans consentement explicite. L’objectif est de montrer où va l’argent, pas de
          mettre en avant les donateurs.
        </p>
        <p className="mt-2 text-2xs text-slate-400">
          Les dons ne créent aucune obligation contractuelle ni aucun engagement de support : le projet est fourni
          « en l’état », sans garantie, conformément à la licence Apache-2.0.
        </p>
      </Panel>
    </div>
  );
}
