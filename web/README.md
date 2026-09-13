# Thot Secure — dashboard web (React + TypeScript + Vite)

> **La console embarquée servie par l'API (`GET /`) reste la référence sans build Node.**
> Ce dashboard est l'**interface riche optionnelle** : il n'est pas nécessaire pour
> exploiter Thot Secure, il ne remplace aucune capacité de la console Jinja2/JS
> embarquée, et il n'expose rien que l'API n'expose déjà.

Interface SOC : flux temps réel (WebSocket), findings et preuves, cycle de vie des
actions SOAR (approbation / exécution / rollback), journal d'audit chaîné avec
vérification d'intégrité, règles de détection, politiques policy-as-code et
collecteurs. Tout est conforme au contrat d'interface gelé :
`docs/architecture/api-contract.md`.

---

## 1. Prérequis

| Outil | Version | Remarque |
|---|---|---|
| Node.js | ≥ 20.19.0 (`engines`) | testé sous Node 22 (image `node:22-alpine`) |
| npm | fourni avec Node | `npm ci` exige un accès au registre npm |
| API Thot Secure | 0.1.0 | `thotsecure serve` écoute par défaut sur `127.0.0.1:8080` |

Aucun secret n'est compilé dans l'artefact : **toutes les variables `VITE_*` sont
publiques** (elles finissent dans le bundle). La clé API est saisie par
l'utilisateur à l'exécution, jamais intégrée au build.

---

## 2. Démarrage

```powershell
# depuis le dossier web/
npm ci                 # installation reproductible (package-lock.json)
npm run dev            # http://127.0.0.1:5173 (proxy /api -> 127.0.0.1:8080)
npm run typecheck      # tsc --noEmit sur l'app ET sur les configs Node
npm run build          # typecheck + bundle de production dans dist/
npm run preview        # sert dist/ sur http://127.0.0.1:4173
npm test               # Vitest (client HTTP + flux WebSocket, sans réseau)
npm run lint           # ESLint (--max-warnings 0)
```

Le serveur de développement Vite proxifie `/api`, `/api/v1/ws`, `/healthz`,
`/readyz`, `/version` et `/openapi.json` vers `http://127.0.0.1:8080`
(`vite.config.ts`). `/ui` **n'est pas** proxifié en développement : pour ouvrir la
console embarquée, allez directement sur `http://127.0.0.1:8080/`.

### Connexion

1. L'API doit être joignable (voir `THOT_HOST` / `THOT_PORT`, contrat §9).
2. Créez une clé API côté serveur — elle n'est affichée **qu'une seule fois** :
   ```powershell
   thotsecure key create --tenant acme --role analyst --label dashboard
   ```
3. Ouvrez le dashboard, saisissez la clé (`ao_…`). Elle est validée par
   `GET /api/v1/auth/whoami`, qui est la **seule** source de vérité du rôle, des
   capacités, du mode d'autonomie et du périmètre `tenant_id`.

---

## 3. Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `VITE_THOT_API_URL` | `/api/v1` | URL de base de l'API. Laisser la valeur relative pour utiliser le proxy (Vite en dev, nginx en production). Une valeur **absolue** (`http://127.0.0.1:8080/api/v1`) fait pointer le dashboard directement sur l'API (CORS à configurer via `THOT_CORS_ORIGINS`) et rend la console embarquée accessible via le lien de la barre latérale. |

Copiez `.env.example` en `.env.local` pour surcharger localement. Aucune autre
variable n'est lue par le dashboard : il n'y a **pas** de clé API, de jeton ou de
secret dans la configuration de build.

---

## 4. Architecture des dossiers

```
web/
├── Dockerfile              # build multi-étapes node:22-alpine -> nginx:1.27-alpine
├── nginx.conf              # SPA + proxy /api (WebSocket) + en-têtes de sécurité
├── index.html              # coquille HTML (aucun script inline : CSP stricte)
├── vite.config.ts          # alias @, proxy d'API, découpage des lots
├── vitest.config.ts        # tests en environnement Node (fetch/WebSocket simulés)
├── tailwind.config.ts      # thème « SOC » (slate-950, accents cyan/ambre/rose)
├── tsconfig.json           # TypeScript strict (noUncheckedIndexedAccess, no any)
└── src/
    ├── main.tsx            # createRoot + QueryClient + BrowserRouter + AuthProvider + ErrorBoundary
    ├── App.tsx             # routes, garde d'authentification, masquage par capacité
    ├── index.css           # directives Tailwind + thème sombre et tableaux denses
    ├── lib/                # socle non visuel (déjà livré, réutilisé tel quel)
    │   ├── api.ts          # client HTTP typé couvrant TOUTES les routes du contrat §4
    │   ├── types.ts        # miroirs des schémas JSON du contrat §3
    │   ├── ws.ts           # client de flux (backoff, tampon borné) + hook React
    │   ├── auth.ts         # contexte d'authentification, capacités, périmètre tenant
    │   ├── capabilities.ts # RBAC côté client (masquage, jamais frontière de sécurité)
    │   ├── download.ts     # téléchargements (rapports, exports d'audit)
    │   └── format.ts       # formats de date/durée, couleurs de sévérité — jamais de HTML
    ├── components/
    │   ├── AppShell.tsx             # navigation, en-tête, période, indicateur de flux
    │   ├── ui.tsx                   # primitives (panneaux, boutons, ConfirmDialog…)
    │   ├── KpiCards.tsx             # indicateurs `stats/overview`
    │   ├── LiveStream.tsx           # flux WebSocket : pause/reprise, liste bornée
    │   ├── FindingsTable.tsx        # filtres, tri, pagination par curseur
    │   ├── FindingDetail.tsx        # preuves, score, décision, garde-fous, rapport
    │   ├── ActionsTable.tsx         # statuts, approbation, rejet, exécution, rollback
    │   ├── ActionApprovalDialog.tsx # double confirmation explicite + motif
    │   ├── AuditLog.tsx             # journal chaîné + « Vérifier l'intégrité »
    │   ├── RulesPanel.tsx           # règles YAML, validation, rechargement
    │   ├── PoliciesPanel.tsx        # politique-as-code, garde-fous d'exécution
    │   ├── SupportPage.tsx          # adresses de dons officielles (source unique)
    │   ├── AutonomyBanner.tsx       # bandeau permanent autonomie + dry_run
    │   ├── RiskGauge.tsx  SeverityBadge.tsx  EmptyState.tsx  ErrorBoundary.tsx
    ├── pages/              # une page par route (Dashboard, Findings, Actions, Audit,
    │                       # Rules, Collectors, Login, Support)
    └── tests/  (../tests/) # api.test.ts, ws.test.ts
```

---

## 5. Sûreté appliquée dans cette interface

Ces points ne sont pas des options de confort : ils sont exigés par le contrat et
vérifiables dans le code.

| Exigence | Mise en œuvre |
|---|---|
| **Masquage RBAC** | `capabilities.ts` + `CapabilityGate` (`App.tsx`) : une route, un bouton ou une colonne dont la capacité manque n'est pas affiché. Le serveur revérifie de toute façon (défense en profondeur). |
| **`dry_run` et autonomie toujours visibles** | `AutonomyBanner` en permanence dans l'en-tête de la coque, plus une variante complète sur le tableau de bord et la page Actions, plus la posture renvoyée par `stats/overview`. Un bandeau rouge apparaît dès que `dry_run=false`. |
| **Aucune action destructive sans double confirmation** | `ConfirmDialog` (engagement explicite + recopie manuelle d'un jeton) pour les findings ; `ActionApprovalDialog` en **deux étapes** (revue → confirmation finale avec recopie de la cible) pour approbation, rejet, exécution et rollback ; recopie du nom du collecteur pour un run manuel. |
| **Aucun `dangerouslySetInnerHTML`** | Interdit dans tout le projet. Les preuves de finding contiennent de vraies charges XSS : elles sont rendues en nœuds texte et en blocs `<pre>`. Le rapport HTML est **téléchargé** (Blob), jamais monté dans le document. |
| **Clé API jamais journalisée ni affichée** | Champ de type `password` sans bouton d'affichage, vidé dès la soumission, transmis uniquement par l'en-tête `X-API-Key`, absent de toute URL du dashboard. |
| **Périmètre tenant** | Le `tenant_id` provient de `whoami` et n'est jamais saisi : `lib/api.ts` refuse (`forbidden`) toute ligne reçue d'un autre tenant plutôt que d'afficher un résultat partiel. |
| **Erreurs lisibles** | Erreurs normalisées `{"error":{code,message,details}}`, jamais de HTML. |
| **URL de règle** | Seuls les schémas `http(s)` d'une `reference` deviennent un lien : toute autre valeur reste du texte inerte. |

### Nuance importante — jeton de flux

La console embarquée échange une session contre un **jeton court** via
`GET /ui/ws-token` (300 s), précisément pour que la clé API ne transite jamais
dans une URL. Le contrat d'interface §4 autorise par ailleurs, pour le WebSocket,
`?api_key=…`, ce que fait ce dashboard (`lib/ws.ts`), car l'authentification par
clé API n'ouvre pas de session de console.

Conséquences, à connaître avant de déployer :

* nginx écrit ses journaux avec `$uri` (sans chaîne de requête) — la clé du flux
  n'atterrit donc pas dans les journaux d'accès (`nginx.conf`) ;
* l'URL d'un WebSocket ne figure ni dans l'historique du navigateur ni dans
  l'en-tête `Referer` (celui-ci est en plus neutralisé par `Referrer-Policy:
  no-referrer`) ;
* si votre politique interdit toute clé en URL, utilisez la **console embarquée**
  (session + `/ui/ws-token`) ou un proxy qui échange le jeton, et n'ouvrez pas le
  flux temps réel de ce dashboard.

---

## 6. Docker

```powershell
# depuis web/ — l'image exige un accès npm pour `npm ci`
docker build -t thotsecure-web:0.1.0 .

# l'API doit être joignable sous le nom `thotsecure` sur le même réseau
docker run --rm -p 8081:8080 --network thotsecure_default thotsecure-web:0.1.0
# -> http://127.0.0.1:8081
```

* Étape de build : `node:22-alpine`, `npm ci` (repli `npm install` sans verrou)
  puis `npm run build` — donc **le typage est vérifié** : une erreur TypeScript
  fait échouer l'image.
* Étape d'exécution : `nginx:1.27-alpine`, utilisateur non privilégié `nginx`,
  écoute sur **8080** (port non privilégié, aucun `CAP_NET_BIND_SERVICE`).
* Proxy `/api`, `/ui`, `/healthz`, `/readyz`, `/version` et `/openapi.json` vers
  `http://thotsecure:8080`, avec les en-têtes d'upgrade WebSocket
  (`Upgrade` / `Connection`) et des délais de lecture longs.
* `/metrics` **n'est pas** exposé par ce proxy : Prometheus scrape l'API en
  interne (contrat §4.1).
* Résolution DNS : `resolver 127.0.0.11` (DNS Docker) + `proxy_pass` via variable,
  pour que nginx démarre même si l'API n'est pas encore résolue. Hors Docker,
  ajustez le resolver ou remplacez par un `proxy_pass` littéral.
* Sur Kubernetes avec `readOnlyRootFilesystem: true`, montez des volumes
  `emptyDir` sur `/tmp` et `/var/cache/nginx` (nginx y écrit son PID et ses
  tampons de proxy).

### En-têtes de sécurité servis par nginx

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
                         img-src 'self' data:; font-src 'self' data:; connect-src 'self';
                         frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: accelerometer=(), camera=(), display-capture=(), geolocation=(), …
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

`script-src` ne contient **aucun** `unsafe-inline` (le bundle Vite n'injecte pas
de script en ligne). `style-src` conserve `'unsafe-inline'` : React/Recharts
posent des attributs `style`, sans quoi les jauges de risque ne s'afficheraient
pas. Le flux WebSocket étant de même origine, `connect-src 'self'` le couvre.

---

## 7. Tests

```powershell
npm test
```

* `tests/api.test.ts` — client HTTP : en-tête `X-API-Key` (jamais dans l'URL),
  normalisation des erreurs, politique de réessai, garde de périmètre tenant,
  annulation, dépassement de délai, réponses `204` et JSON invalide.
* `tests/ws.test.ts` — flux : backoff plafonné, URL `ws(s)://`, analyse
  défensive des frames, projection d'affichage, tampon borné, pause/reprise,
  heartbeats, fermeture non autorisée (aucune reconnexion), reconnexion.

Aucun test ne touche le réseau : `fetch` est remplacé par une fonction locale et
`WebSocket` par une implémentation de test injectée via `socketFactory`.

---

## 8. Limites connues

* `npm ci` / `npm install` exigent un accès au registre npm ; hors ligne, seule la
  console embarquée (`GET /`) est disponible — c'est précisément pour cela qu'elle
  reste la référence.
* Les en-têtes de sécurité (CSP, `X-Frame-Options`, `Referrer-Policy`) sont posés
  par **nginx** en production ; le serveur de développement Vite ne les applique
  pas. Ne jugez pas la posture de sécurité depuis `npm run dev`.
* Les sourcemaps sont générées (`build.sourcemap: true`) pour le diagnostic ;
  `nginx.conf` refuse de les servir publiquement. Supprimez l'option ou le bloc
  `location` selon votre politique.
* L'interface n'expose volontairement pas l'administration des tenants et des clés
  API (`admin:tenants`, `admin:keys`), qui reste du ressort de la CLI
  (`thotsecure tenant …`, `thotsecure key …`) : afficher une clé dans un
  navigateur est un risque inutile pour un gain nul.
* Les pages sont monolingues (français), comme la console embarquée.
* Page de soutien : les adresses de dons sont celles du dépôt
  (`GET /ui/support`, `docs/support.md`) — **dons volontaires, aucune contrepartie
  attendue** ; vérifiez toujours l'adresse depuis le dépôt officiel.
