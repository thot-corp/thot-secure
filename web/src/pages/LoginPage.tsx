/**
 * Écran de connexion : saisie de la clé API (`ao_…`, contrat §4).
 *
 * Sûreté :
 *  - la clé est le **seul** mécanisme d'authentification de l'API ; elle est
 *    transmise exclusivement par l'en-tête `X-API-Key` (`lib/api.ts`) et n'est
 *    **jamais** placée dans une URL, un journal ou un rendu ;
 *  - le champ est de type `password` et **sans** bouton « afficher » : la clé ne
 *    doit pas pouvoir être lue par-dessus une épaule ni capturée par une
 *    extension d'écran ;
 *  - le champ est vidé dès la soumission : la valeur ne reste pas dans l'état du
 *    composant après l'appel à `signIn` ;
 *  - la validation est faite par le serveur (`GET /api/v1/auth/whoami`) : le rôle,
 *    les capacités et le périmètre `tenant_id` ne viennent jamais du client.
 */
import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';

import { Button, InlineNotice, Panel, TextInput } from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { errorMessage } from '@/lib/api';

export function LoginPage(): JSX.Element {
  const { status, error, signIn, apiBaseUrl } = useAuth();
  const navigate = useNavigate();
  const [apiKeyDraft, setApiKeyDraft] = useState('');
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    // Une clé valide mène directement au tableau de bord ; aucune page
    // intermédiaire ne doit exposer l'état de connexion.
    if (status === 'authenticated') navigate('/', { replace: true });
  }, [navigate, status]);

  const loading = status === 'loading' && submitted;
  const failure = status === 'error' ? error : null;

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const trimmed = apiKeyDraft.trim();
    if (trimmed === '') return;
    setSubmitted(true);
    // Le champ est vidé immédiatement : la clé vit ensuite dans le stockage
    // local du navigateur, géré par `AuthProvider`.
    setApiKeyDraft('');
    signIn(trimmed);
  };

  return (
    <div className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-3 px-4 py-10">
      <header>
        <h1 className="text-lg">Thot Secure — Console SOC</h1>
        <p className="mt-1 text-xs text-slate-400">
          Interface riche optionnelle. La console embarquée servie par l’API (
          <code className="soc-code-inline">GET /</code>) reste la référence et fonctionne sans build Node.
        </p>
      </header>

      <Panel
        title="Connexion par clé API"
        description="La clé est créée par un administrateur du tenant et n’est affichée qu’une seule fois lors de sa création."
      >
        <form className="space-y-3" onSubmit={handleSubmit} autoComplete="off">
          <TextInput
            label="Clé API (ao_…)"
            type="password"
            name="thotsecure-api-key"
            value={apiKeyDraft}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            placeholder="ao_…"
            hint="Transmise uniquement dans l’en-tête X-API-Key. Elle n’apparaît jamais dans une URL, un journal ou cette page."
            onChange={(event) => setApiKeyDraft(event.target.value)}
            disabled={loading}
          />

          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" variant="primary" busy={loading} disabled={apiKeyDraft.trim() === ''}>
              Se connecter
            </Button>
            <span className="text-2xs text-slate-500">
              API ciblée : <code className="soc-code-inline">{apiBaseUrl}</code>
            </span>
          </div>
        </form>

        {loading ? (
          <InlineNotice tone="info" className="mt-3" title="Validation de la clé en cours">
            Interrogation de <code className="soc-code-inline">GET /api/v1/auth/whoami</code> : le rôle, les capacités
            et le périmètre tenant sont déterminés par le serveur.
          </InlineNotice>
        ) : null}

        {failure ? (
          <InlineNotice
            tone="danger"
            className="mt-3"
            title={failure.code === 'unauthenticated' || failure.status === 401 ? 'Clé refusée' : 'Connexion impossible'}
          >
            <p>{errorMessage(failure)}</p>
            <p>
              Vérifiez que la clé n’a pas été révoquée (<code className="soc-code-inline">DELETE /api/v1/keys/{'{key_id}'}</code>)
              et qu’elle appartient bien au tenant attendu. Les clés sont stockées hachées côté serveur : une clé
              perdue ne peut pas être réaffichée, il faut en créer une nouvelle.
            </p>
          </InlineNotice>
        ) : null}
      </Panel>

      <InlineNotice tone="info" title="Bonnes pratiques">
        <ul className="list-inside list-disc space-y-0.5">
          <li>
            Utilisez une clé dédiée à cette console, au rôle minimal nécessaire (un rôle <em>viewer</em> suffit pour
            consulter).
          </li>
          <li>
            Ne saisissez jamais une clé reçue par message privé, courriel ou commentaire : seule la distribution
            depuis le dépôt officiel et les procédures internes fait foi.
          </li>
          <li>
            La clé est conservée dans le stockage local de ce navigateur (poste d’astreinte dédié recommandé) et le
            cache de données est purgé à chaque changement de clé.
          </li>
          <li>
            Création côté serveur :{' '}
            <code className="soc-code-inline">thotsecure key create --tenant &lt;id&gt; --role analyst</code> (contrat §8).
          </li>
        </ul>
      </InlineNotice>
    </div>
  );
}
