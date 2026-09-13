# Politiques de décision (policy-as-code)

*La politique transforme une détection en **intention** explicite, traçable et bornée — jamais en effet de bord.*

Cette page décrit le format des politiques de décision d'Thot Secure, leur sémantique d'évaluation, les garde-fous qui les encadrent et la manière d'auditer une décision a posteriori. Référence normative : [`docs/architecture/api-contract.md`](../architecture/api-contract.md) §3.3, §3.4, §4.5, §6 et §10. Le format des règles de détection qui produisent les findings est décrit dans [`../detection/rules.md`](../detection/rules.md).

---

## 1. Où se situe la décision dans le pipeline

```text
collecteur → Événement (§3.1) → moteur de règles → Finding (§3.2)
                                                        │
                                                        ▼
                                        politiques (§6) ──► Decision (§3.3)
                                                        │
                                                        ▼
                                            playbooks (§7) ──► Action (§3.4)
                                                        │
                                                        ▼
                                              connecteur (réel ou simulé)
```

| Étage | Rôle | Produit | Effet de bord |
|---|---|---|---|
| Détection | Repérer un comportement | `Finding` + `risk_score` | Aucun |
| **Décision** | **Qualifier l'intention** | `Decision` (`policy_id`, `reason`, `playbook`, `params`) | **Aucun** |
| Action | Exécuter une contre-mesure | `Action` + cycle de vie + audit | Oui, sur le connecteur |
| Audit | Prouver ce qui s'est passé | `AuditRecord` chaîné | Aucun |

!!! note "Séparation stricte décision / exécution"
    Une politique ne parle **jamais** directement à un connecteur. Elle nomme un playbook et des paramètres ; c'est le moteur d'actions qui planifie, fait approuver, exécute et journalise. Conséquence pratique : une politique erronée produit une mauvaise *intention* — elle ne peut pas, à elle seule, produire un effet réel non gardé.

Le pipeline complet (ingestion, scoring, décision, action, rollback) est détaillé dans [`../architecture/overview.md`](../architecture/overview.md) ; les tables de persistance sont décrites dans [`../architecture/data-model.md`](../architecture/data-model.md).

---

## 2. Format complet d'une politique

Une politique est un fichier YAML chargé depuis le répertoire `THOT_POLICIES_DIR` (défaut `./policies`, voir §9 du contrat).

```yaml
version: 1
id: auto-block-high-web
priority: 100
description: Blocage automatique des attaques web à fort score.
when:
  finding.severity: [critical, high]
  finding.risk_score: { gte: 70 }
  finding.tags_any: [web, exploit-attempt]
  tenant.mode: [auto]
  environment: [prod, staging]
then:
  decision: auto
  playbook: block-source-ip
  params:
    target: labels.src_ip
    duration_seconds: 3600
  dry_run: false
  cooldown_seconds: 300
  max_actions_per_hour: 10
rollback:
  playbook: unblock-source-ip
  auto_after_seconds: 3600
```

| Champ | Type | Défaut | Rôle |
|---|---|---|---|
| `version` | entier | — (à déclarer) | Version du schéma de politique. L'exemple du contrat utilise `1`. |
| `id` | chaîne | — (obligatoire) | Identifiant stable, unique, en kebab-case. Recopié dans `Decision.policy_id` et `Action.policy_id` : c'est la clé de corrélation décision ↔ action (§10 traçabilité). |
| `priority` | entier | non fixé par le §6 (toujours l'écrire) | Ordre d'évaluation : **plus grand = évalué d'abord**. |
| `description` | chaîne | vide | Documentation lisible par un humain ; n'influence pas l'évaluation. |
| `when` | mapping | — (obligatoire) | Conditions d'applicabilité. Voir §3. |
| `then` | mapping | — (obligatoire) | Intention produite si `when` correspond. Voir §7. |
| `rollback` | mapping | vide | Procédure de retour arrière associée à l'action, et son délai automatique. Voir §8. |

!!! tip "Un fichier = une politique"
    Le champ `id` est la seule identité de la politique. Éviter de dupliquer un même `id` dans deux fichiers : la résolution des doublons relève du chargeur et doit être vérifiée en préproduction avec `thotsecure policies validate`.

---

## 3. Sémantique de `when`

Trois règles, appliquées dans cet ordre :

1. **ET entre les clés** : toutes les clés de `when` doivent être satisfaites simultanément.
2. **Une liste = OU d'égalités** : `finding.severity: [critical, high]` est vrai si la sévérité vaut `critical` **ou** `high`.
3. **Un mapping = comparateurs** : `{ gte: 70 }`, `{ in: [...] }`, `{ matches: "..." }`.

| Comparateur | Sens | Exemple |
|---|---|---|
| `gt` | strictement supérieur | `finding.risk_score: { gt: 85 }` |
| `gte` | supérieur ou égal | `finding.risk_score: { gte: 70 }` |
| `lt` | strictement inférieur | `finding.confidence: { lt: 0.5 }` |
| `lte` | inférieur ou égal | `finding.risk_score: { lte: 69.9 }` |
| `in` | appartenance à une liste | `finding.severity: { in: [high, critical] }` |
| `not_in` | non-appartenance | `finding.status: { not_in: [suppressed, closed] }` |
| `matches` | expression régulière | `finding.title: { matches: "(?i)injection" }` |

### 3.1 Clés disponibles (liste exhaustive)

Le §6 du contrat ferme la liste : **aucune autre clé n'est définie** pour le MVP.

| Clé | Source | Type / valeurs | Exemple |
|---|---|---|---|
| `finding.severity` | Finding §3.2 | `info\|low\|medium\|high\|critical` | `[critical, high]` |
| `finding.risk_score` | Scoring | nombre dans `[0, 100]` | `{ gte: 70 }` |
| `finding.confidence` | Règle §5 | nombre dans `[0.0, 1.0]` | `{ gte: 0.8 }` |
| `finding.rule_id` | Règle §5 | chaîne, ex. `AO-WEB-001` | `[AO-WEB-001]` |
| `finding.tags` | Finding §3.2 | liste de tags complets du finding | `[owasp:a03]` |
| `finding.tags_any` | Finding §3.2 | vrai si **au moins un** des tags listés est présent | `[web, exploit-attempt]` |
| `finding.status` | Finding §3.2 | `open\|acked\|closed\|suppressed` | `[open]` |
| `finding.count` | Finding §3.2 | entier : nombre d'événements agrégés (seuils de la règle, §5) | `{ gte: 5 }` |
| `finding.title` | Finding §3.2 | chaîne libre | `{ matches: "(?i)injection" }` |
| `tenant.id` | Tenant §4.2 | chaîne, ex. `acme` | `[acme]` |
| `tenant.mode` | Tenant §4.2 | `manual\|supervised\|auto` | `[auto]` |
| `environment` | §9 `THOT_ENV` | `dev` (§9), `prod`, `staging` (exemple §6) | `[prod, staging]` |
| `time.hour_utc` | Horloge | entier `0`–`23` | `{ gte: 8, lt: 19 }` |
| `day.weekday` | Horloge | jour de la semaine | `[monday, tuesday]` |

!!! warning "Deux points à confirmer par le code"
    * La distinction exacte entre `finding.tags` (jeu de tags requis) et `finding.tags_any` (au moins un tag) suit l'exemple du §6 ; elle est vérifiée par `tests/test_decision.py`.
    * L'encodage de `day.weekday` (nom de jour ou entier `0`–`6`) **n'est pas figé par le contrat**. Valider vos politiques en préproduction avant de vous y appuyer.

!!! info "Ce qui n'est pas exposé à `when`"
    Les politiques ne voient ni les `payload` bruts des événements, ni les champs d'autres tenants, ni l'identité de l'appelant. Toute logique qui exige ces données appartient à la règle de détection (§5), pas à la politique.

---

## 4. Priorité et première correspondance gagnante

* `priority` : **la valeur la plus grande est évaluée en premier**.
* Le moteur s'arrête à la **première politique dont le `when` correspond** : les suivantes ne sont pas évaluées pour ce finding.
* Si **aucune** politique ne correspond → `decision = notify_only`. C'est le défaut sûr : le finding est notifié et journalisé, rien n'est exécuté silencieusement.
* Pour un **silence total** (bruit connu), il faut une politique `ignore` explicite, la plus spécifique possible, avec une `priority` élevée.

```yaml
# Le silence n'est jamais implicite : il doit être écrit, nommé et justifié.
version: 1
id: ignore-scanner-noise
priority: 900        # évaluée avant les politiques d'action
```

!!! warning "Piège classique de priorité"
    Une politique `ignore` large avec une `priority` trop élevée court-circuite toutes les politiques d'action. Réserver les fortes priorités aux règles d'exception **étroites** (`rule_id` + source + environnement).

---

## 5. Les quatre décisions

| `then.decision` | Ce que fait le moteur | Capacité / rôle minimum | Statut initial de l'`Action` |
|---|---|---|---|
| `auto` | Planifie et enchaîne l'exécution sans approbation humaine (à condition que le `mode` du tenant soit `auto`). | `execute:actions` → rôle `responder` ou `admin` (§4) | `planned`, puis `executing` sans passer par `pending_approval` |
| `require_approval` | Planifie l'action et l'immobilise jusqu'à décision humaine. | `approve:actions` → rôle `responder` ou `admin` (§4) | `pending_approval` |
| `notify_only` | Notifie et journalise ; **aucune contre-mesure** n'est planifiée. | `read:findings` suffit pour l'observation ; le playbook `notify` (§7) reste le moyen documenté d'émettre une notification explicite. | Aucune `Action` de contre-mesure |
| `ignore` | Ne fait rien, mais **journalise la décision** et le `policy_id` responsable. | Aucune capacité d'action requise. | Aucune |

!!! note "Rôles"
    `viewer` et `analyst` ne détiennent ni `execute:actions` ni `approve:actions` : ils ne peuvent pas déclencher d'exécution. Seuls `responder` et `admin` le peuvent (§4). Le détail des capacités figure dans [`../architecture/api-contract.md`](../architecture/api-contract.md) §4 et dans [`../api/usage.md`](../api/usage.md).

Lorsqu'une `Action` atteint `pending_approval`, personne ne peut l'exécuter avant approbation : `POST /api/v1/actions/{id}/execute` renvoie alors `409 conflict` (§4.6). Le cycle de vie complet est décrit dans [`../actions/playbooks.md`](../actions/playbooks.md).

---

## 6. Garde-fous non contournables

Ces cinq règles sont appliquées par le **moteur de décision**, en aval des politiques.

| Garde-fou | Comportement garanti | Ce qu'il empêche |
|---|---|---|
| `max_actions_per_hour` par tenant (défaut **20**) | Le nombre d'actions exécutées pour un tenant est plafonné par heure (défaut `20`, §6.1). | Une politique trop large qui viderait la plateforme sur un pic de bruit, ou un emballement en boucle. |
| `cooldown` par `(tenant, playbook, cible)` | Une même contre-mesure ne peut pas être réappliquée sur la même cible pendant la fenêtre de refroidissement (`then.cooldown_seconds`). | Les milliers d'actions redondantes sur une IP déjà bloquée. |
| Cibles de l'`autonomy_allowlist` protégées | **Aucune** action n'est appliquée à une cible appartenant à l'infra propre déclarée dans l'`autonomy_allowlist` du tenant (§4.2, §6.3). | L'auto-mise-hors-service de sa propre infrastructure — le scénario catastrophe du SOAR. |
| `dry_run` global | `THOT_DRY_RUN=true` (défaut, §9) est **prioritaire sur toute politique**, y compris `then.dry_run: false`. Aucune action réelle n'est exécutée. | Toute exécution réelle avant levée explicite et consciente. |
| Périmètre déclaré | Toute cible **hors du périmètre déclaré du tenant** (`THOT_TARGETS_FILE`, §9) force `require_approval`, quelle que soit la politique. | Les actions sur des cibles non possédées ou non déclarées. |

!!! danger "Une politique ne peut pas contourner un garde-fou"
    Aucune valeur de `then` — ni `dry_run: false`, ni `cooldown_seconds: 0`, ni `max_actions_per_hour: 100000` — ne désactive un garde-fou. Les garde-fous sont évalués **après** la politique et ont le dernier mot : la politique peut seulement être *plus prudente* que le plancher, jamais moins. Un plafond déclaré plus bas dans `then.max_actions_per_hour` restreint la politique ; il ne relève pas le plafond du tenant.

!!! note "Lacune assumée du contrat gelé"
    Le §6 ne précise pas la conséquence exacte d'un dépassement de `max_actions_per_hour` (rejet de l'action, report ou bascule en `require_approval`). Le comportement observé doit être confirmé par `tests/test_decision.py` et par un essai en préproduction : ne vous reposez pas sur une hypothèse pour dimensionner un plafond.

Ces garde-fous s'ajoutent à ceux de la plateforme décrits au §10 : isolation multi-tenant, RBAC, rate limit d'ingestion, `AUTONOMY=supervised` par défaut.

---

## 7. Le bloc `then`

| Champ | Type | Rôle |
|---|---|---|
| `decision` | énuméré | `auto` \| `require_approval` \| `notify_only` \| `ignore`. Voir §5. |
| `playbook` | chaîne | Nom du playbook à exécuter (`block-source-ip`, `rate-limit-source`, `notify`, `open-ticket`, …). La liste livrée est dans [`../actions/playbooks.md`](../actions/playbooks.md). |
| `params` | mapping | Paramètres transmis au playbook. Ils peuvent référencer un champ du finding : dans l'exemple §6, `target: labels.src_ip` est une **référence**, résolue en valeur réelle (`203.0.113.9`) au moment de la création de l'`Action` (§3.4). |
| `dry_run` | booléen | Demande de simulation pour cette politique. Ne peut pas rendre réel ce que le garde-fou global `THOT_DRY_RUN=true` interdit. |
| `cooldown_seconds` | entier | Fenêtre de refroidissement demandée pour `(tenant, playbook, cible)`. Exposée dans `Decision.cooldown_seconds`. |
| `max_actions_per_hour` | entier | Plafond **spécifique à cette politique**, nécessairement inférieur ou égal au plafond du tenant. |

!!! tip "Paramétrer un playbook"
    La liste des paramètres acceptés, leurs types, leurs valeurs par défaut et leurs bornes appartiennent au playbook, pas à la politique. Référez-vous à la table des playbooks livrés dans [`../actions/playbooks.md`](../actions/playbooks.md) et à `params_schema` exposé par `GET /api/v1/playbooks` (§4.5).

---

## 8. Le bloc `rollback`

```yaml
rollback:
  playbook: unblock-source-ip
  auto_after_seconds: 3600
```

| Champ | Type | Rôle |
|---|---|---|
| `playbook` | chaîne | Playbook de retour arrière. Pour un blocage réseau, c'est `unblock-source-ip` (§7). |
| `auto_after_seconds` | entier | Délai après lequel le retour arrière est déclenché automatiquement. Dans l'exemple §6, `3600` : une heure après le blocage. |

La matérialisation de ce bloc dans l'objet `Action` (§3.4) :

| Champ d'`Action` | Lien avec la politique |
|---|---|
| `rollback.available` | `true` tant que l'action peut encore être annulée (invariant §1.3 : le rollback doit réussir tant qu'il n'a pas expiré). |
| `rollback.token` | Jeton rendu par le connecteur (y compris en mode simulé), nécessaire au retour arrière. |
| `expires_at` | Fin de la fenêtre pendant laquelle l'action et son rollback sont valides ; cohérent avec `duration_seconds` demandé au playbook. |
| `rollback.performed_at` / `rollback.result` | Horodatage et résultat du retour arrière effectué. |

!!! warning "Un rollback ne s'invente pas"
    Déclarer `rollback.playbook` dans une politique ne crée pas la réversibilité : celle-ci vient du playbook lui-même (`reversible: true` + bloc `rollback`, §7). Si le playbook cible n'est pas réversible, l'action ne doit pas être planifiée — vérifier `GET /api/v1/playbooks` avant activation. Voir [`../actions/playbooks.md`](../actions/playbooks.md).

---

## 9. Politiques d'exemple

### 9.1 Blocage automatique d'une attaque web critique

```yaml
version: 1
id: auto-block-high-web
priority: 100
description: Blocage automatique des attaques web à fort score.
# POURQUOI : motif d'attaque applicatif avéré (injection, exploit), score élevé,
# tenant explicitement en autonomie, environnement de production.
when:
  finding.severity: [critical, high]
  finding.risk_score: { gte: 70 }
  finding.tags_any: [web, exploit-attempt]
  tenant.mode: [auto]
  environment: [prod, staging]
then:
  decision: auto
  playbook: block-source-ip
  params:
    target: labels.src_ip          # référence résolue depuis le finding
    duration_seconds: 3600         # 1 h : borné, donc sûr
    reason: "Thot Secure auto-mitigation (règle AO-WEB-001)"
  dry_run: false
  cooldown_seconds: 300            # 5 min : évite le spam d'actions sur la même IP
  max_actions_per_hour: 10         # plus strict que le plafond tenant (20)
rollback:
  playbook: unblock-source-ip
  auto_after_seconds: 3600         # déblocage automatique au bout d'une heure
```

**Risque si mal configurée**

* Un `finding.tags_any` trop large (par exemple un seul tag `web`) peut bloquer des IP légitimes de clients ou de partenaires.
* Retirer `tenant.mode: [auto]` ou passer `duration_seconds` à sa borne haute (604800) transforme une mitigation ponctuelle en blocage d'une semaine difficile à justifier.

### 9.2 Approbation obligatoire en production sur les actions sensibles

```yaml
version: 1
id: prod-require-approval-isolation
priority: 200                      # évaluée AVANT la politique de blocage automatique
description: Toute isolation d'hôte en production exige une approbation humaine.
# POURQUOI : isoler un hôte est une action à fort impact opérationnel ; en production,
# un humain doit valider avant exécution.
when:
  finding.tags_any: [lateral-movement, ransomware-behavior]
  finding.risk_score: { gte: 60 }
  environment: [prod]
then:
  decision: require_approval
  playbook: isolate-host
  params:
    target: labels.hostname
  dry_run: true                    # planification sans effet, en plus de l'approbation
  cooldown_seconds: 900
  max_actions_per_hour: 5
rollback:
  playbook: isolate-host           # retour arrière : réintégration de l'hôte
  auto_after_seconds: 7200
```

**Risque si mal configurée**

* Une `priority` trop basse laisse la politique d'exécution automatique gagner : l'action part sans approbation.
* Un `auto_after_seconds` très court (ou absent) fait durer l'isolement d'un hôte de production au-delà du nécessaire et dégrade le service.

### 9.3 Notification seule en staging

```yaml
version: 1
id: staging-notify-only
priority: 300
description: En staging, on observe et on notifie, on ne bloque pas automatiquement.
# POURQUOI : un environnement de recette contient du trafic de test qui déclenche
# légitimement des règles ; l'équipe veut le signal, pas la contre-mesure.
when:
  environment: [staging]
  finding.severity: [critical, high]
  tenant.mode: [supervised, manual]
then:
  decision: notify_only
  playbook: notify
  params:
    target: labels.src_ip
  cooldown_seconds: 600
  max_actions_per_hour: 3
rollback: {}                       # aucune contre-mesure : rien à annuler
```

**Risque si mal configurée**

* Un playbook de contre-mesure laissé dans `then.playbook` donnerait l'illusion d'une action alors que `notify_only` n'exécute aucune contre-mesure.
* Une politique `notify_only` en staging avec `priority` trop basse peut masquer une politique plus spécifique qui, elle, aurait dû exiger une approbation.

### 9.4 Ignorer le bruit d'un scanner autorisé (exception étroite)

```yaml
version: 1
id: ignore-authorized-scanner
priority: 900                      # très haute : elle court-circuite tout le reste…
description: Silence sur le scanner de conformité interne autorisé, hors production.
# POURQUOI : le scanner de conformité du tenant génère des findings récurrents
# (rule AO-WEB-001) depuis une IP connue, uniquement en dev/staging.
# GARDE-FOU ANTI-ABUS : l'exception est volontairement étroite — règle exacte,
# IP exacte, environnements non prod, score plafonné. Aucune autre détection
# de cette IP ni aucune détection de cette règle ailleurs n'est réduite au silence.
when:
  finding.rule_id: [AO-WEB-001]
  finding.risk_score: { lt: 40 }            # jamais les findings vraiment graves
  finding.tags_any: [scanner-known]         # tag posé par la règle interne
  environment: [dev, staging]               # jamais en production
  day.weekday: [monday, tuesday, wednesday, thursday, friday]
then:
  decision: ignore
  cooldown_seconds: 3600
rollback: {}
```

**Risque si mal configurée**

* Élargir `when` (retirer `finding.risk_score` ou `environment`) crée un angle mort : une vraie attaque menée depuis cette IP, ou la même règle en production, passerait totalement inaperçue.
* Une `priority: 900` couplée à des conditions larges annule de fait toutes les politiques d'action pour les findings concernés — d'où l'exigence de conditions étroites et d'une revue périodique des exceptions.

### 9.5 Limitation de débit progressive avant blocage

```yaml
version: 1
id: rate-limit-progressive
priority: 150                      # après l'approbation prod, avant le blocage automatique
description: Limitation de débit graduée sur les sources à score moyen ou répétitives.
# POURQUOI : une riposte graduée est proportionnée. On ralentit d'abord (réversible,
# à faible impact), on ne bloque que si la politique de blocage, plus prioritaire
# sur les cas graves, ne s'est pas déjà appliquée.
when:
  finding.tags_any: [web, brute-force-suspected, rate-abuse]
  finding.risk_score: { gte: 45, lt: 70 }
  finding.count: { gte: 20 }
  tenant.mode: [supervised, auto]
then:
  decision: auto
  playbook: rate-limit-source
  params:
    target: labels.src_ip
    duration_seconds: 900          # 15 min : fenêtre courte et réversible
    reason: "Thot Secure progressive rate limit"
  cooldown_seconds: 600
  max_actions_per_hour: 15
rollback:
  playbook: rate-limit-source     # retour arrière : retrait de la limitation
  auto_after_seconds: 900
```

**Risque si mal configurée**

* Un `finding.count` trop bas (ou absent) limite le débit de visiteurs légitimes sur un pic de charge normale.
* Une `duration_seconds` longue cumulée à un `auto_after_seconds` incohérent peut maintenir une limitation bien après la fin de l'incident ; aligner les deux valeurs.

!!! tip "Ordre de priorité de ces cinq exemples"
    `ignore-authorized-scanner` (900) → `staging-notify-only` (300) → `prod-require-approval-isolation` (200) → `rate-limit-progressive` (150) → `auto-block-high-web` (100). Les exceptions et les freins passent avant les automatismes : c'est le principe de conception attendu.

---

## 10. Comment auditer une décision

### 10.1 La `Decision` retournée

```json
{
  "decision": "auto",
  "policy_id": "auto-block-high-web",
  "playbook": "block-source-ip",
  "params": { "target": "labels.src_ip", "duration_seconds": 3600 },
  "reason": "severity=high risk=78.5 tags∈{web} tenant.mode=auto",
  "risk_score": 78.5,
  "expires_at": "2026-02-14T11:04:12Z",
  "cooldown_seconds": 300,
  "dry_run": false
}
```

| Champ | Ce qu'il prouve |
|---|---|
| `policy_id` | **Quelle** politique a produit la décision. Corrélé à `Action.policy_id` (§10 traçabilité). |
| `reason` | **Pourquoi** : le moteur restitue les faits qui ont satisfait le `when`. Ici : sévérité `high`, score `78.5`, au moins un tag de `{web, exploit-attempt}`, tenant en mode `auto`. |
| `risk_score` | Le score du finding au moment de la décision, pas un score recalculé après coup. |
| `expires_at` | Fin de validité de la décision ; au-delà, elle ne doit plus fonder d'exécution. |
| `cooldown_seconds` | Fenêtre de refroidissement appliquée à `(tenant, playbook, cible)` — celle réellement retenue par le moteur. |
| `dry_run` | Si l'exécution a été simulée, et pourquoi. `true` peut venir de la politique **ou** du garde-fou global (§6.4). |

!!! note "Lire le `reason`"
    Le format du `reason` n'est pas normatif, mais il doit rester **explicatif** : il reprend les clés du `when` satisfaites et leurs valeurs observées. C'est le premier élément à produire lors d'une revue post-incident : il permet de reconstituer le raisonnement sans relire le YAML au moment de l'incident.

### 10.2 Retrouver la politique et son rang

```bash
# Politiques chargées + ordre de priorité d'évaluation (capacité read:policies)
curl -s http://127.0.0.1:8080/api/v1/policies -H "X-API-Key: ao_…"

# Même information côté CLI, exploitable en script
thotsecure policies validate --json
```

`GET /api/v1/policies` expose les politiques **chargées** et leur **ordre de priorité** : c'est la vue de référence pour vérifier qu'une politique est bien prise en compte et qu'elle est évaluée au rang attendu.

### 10.3 Retrouver la trace de la décision

```bash
# Journal d'audit filtré sur l'action d'approbation, côté REST
curl -s "http://127.0.0.1:8080/api/v1/audit?action=action.approve&limit=50" -H "X-API-Key: ao_…"

# Côté CLI
thotsecure audit tail
thotsecure audit tail --json

# Vérification d'intégrité de la chaîne (capacité read:audit)
curl -s http://127.0.0.1:8080/api/v1/audit/verify -H "X-API-Key: ao_…"
# → {"valid": true, "records": 1287, "broken_at": null}

thotsecure audit verify      # code de sortie 0 si valide, 3 si la vérification échoue
```

### 10.4 Export SIEM

```bash
# Flux téléchargeable pour SIEM/SOAR : JSONL brut ou CEF
curl -s "http://127.0.0.1:8080/api/v1/audit/export?format=jsonl" -H "X-API-Key: ao_…" -o audit.jsonl
curl -s "http://127.0.0.1:8080/api/v1/audit/export?format=cef"   -H "X-API-Key: ao_…" -o audit.cef
```

### 10.5 Chaîne de traçabilité

Chaque décision référence `policy_id` ; chaque action porte `audit_seq` (§10). Le rapprochement se fait en trois sauts :

```text
Finding (rule_id) ──► Decision (policy_id) ──► Action (policy_id, audit_seq) ──► AuditRecord (seq)
```

Les transitions d'état sont visibles dans le journal grâce à `before` / `after` :

```json
{
  "seq": 42,
  "actor": "api-key:ci",
  "actor_role": "responder",
  "action": "action.approve",
  "target": { "type": "action", "id": "a91b…" },
  "before": { "status": "pending_approval" },
  "after": { "status": "approved" }
}
```

Le journal est **append-only** et chaîné par hash (§3.5) : toute modification d'un enregistrement passé casse la chaîne et est détectée par `GET /api/v1/audit/verify`. La procédure d'investigation complète figure dans [`../operations/runbook.md`](../operations/runbook.md) ; les exigences de journalisation côté conformité sont traitées dans [`../compliance/soc2-iso27001.md`](../compliance/soc2-iso27001.md).

---

## 11. Mode Rego / OPA (optionnel)

Le contrat prévoit une évaluation alternative en **Rego** via Open Policy Agent.

| Élément | Valeur |
|---|---|
| Activation | Variable `THOT_OPA_BIN` définie **et** binaire présent sur la machine (§9) |
| Fichier de politiques | `policies/rego/thotsecure.rego` |
| Portée | Évaluation des politiques de décision (`decision/` dans l'arborescence cible) |

!!! note "Mode dégradé : retour au YAML"
    Si `THOT_OPA_BIN` est vide, mal renseigné, ou si le binaire est absent, Thot Secure **retombe sur l'évaluation YAML** décrite dans cette page. Le service ne s'arrête pas : le mode Rego est une extension, jamais une dépendance. Vérifier le mode effectivement actif fait partie de la checklist de mise en service ([`../operations/deployment.md`](../operations/deployment.md)).

!!! warning "Deux moteurs, une seule politique"
    N'écrivez pas la même politique en YAML **et** en Rego en espérant un « OU » : le mode effectif est déterminé par la configuration. Une politique YAML qui n'est plus évaluée parce qu'OPA est actif est une cause classique d'écart entre l'intention documentée et le comportement observé.

---

## 12. Valider et activer une politique

```bash
# 1. Validation syntaxique et sémantique des politiques du répertoire THOT_POLICIES_DIR
thotsecure policies validate

# 2. Rechargement à chaud côté API (capacité admin:policies → rôle admin)
curl -s -X POST http://127.0.0.1:8080/api/v1/policies/reload -H "X-API-Key: ao_…"

# 3. Contrôle du résultat : politiques chargées + ordre de priorité
curl -s http://127.0.0.1:8080/api/v1/policies -H "X-API-Key: ao_…"
```

!!! warning "Tester en préproduction avant d'activer `auto`"
    Une politique `auto` n'est jamais activée directement. Séquence minimale :

    1. créer un **tenant de test** dédié ;
    2. rejouer un jeu d'événements représentatif (`thotsecure ingest --tenant <test> --file events.jsonl`) ;
    3. laisser `THOT_DRY_RUN=true` et comparer les `Decision.reason` obtenues à l'intention attendue ;
    4. vérifier le comportement des garde-fous (`cooldown`, plafond horaire, cibles de l'`autonomy_allowlist`, cibles hors périmètre) ;
    5. seulement ensuite activer la politique en production, idéalement en `require_approval`, puis en `auto`.

    Le contrat de test associé est `tests/test_decision.py` (§11) : `auto` vs `require_approval`, cooldown, plafond horaire, cibles protégées.

---

## 13. Roadmap

!!! info "Roadmap"
    Les éléments suivants **ne sont pas disponibles** en v0.1.0 (MVP) :

    * **éditeur de politiques dans la console** : les politiques s'écrivent dans des fichiers YAML versionnés, puis sont validées et rechargées par CLI ou API ;
    * **simulation « what-if »** : rejouer un finding donné contre l'ensemble des politiques pour afficher la décision qu'aurait produite chaque candidate n'est pas implémenté ; la comparaison se fait aujourd'hui en préproduction, en `dry_run`, via `Decision.reason` ;
    * **historisation des versions de politique** : le suivi des modifications repose sur le versionnement du dépôt de politiques, pas sur une fonctionnalité produit.

    Voir [`../roadmap.md`](../roadmap.md) pour l'ordre de livraison prévu.

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
