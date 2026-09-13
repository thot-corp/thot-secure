```yaml
canal: Blog du projet (Thot Secure) — série « devlog »
langue: fr
format: devlog court, ton personnel, avec captures de terminal
objectif: >
  Montrer l'avancement réel du sprint 1, assumer les erreurs, expliquer trois décisions
  difficiles (dry-run par défaut, chaîne de hash plutôt que blockchain, bus pluggable)
  et annoncer la suite sans promettre plus que ce qui est fait.
mot_cle_principal: devlog sprint 1
mots_cles_secondaires: [SOAR, dry-run, audit chaîné, dette technique, build in public]
longueur: 600–800 mots
public_cible: contributeurs, curieux techniques, futurs utilisateurs du MVP
date_de_publication_cible: S3 — jeudi, 08:30 CET
appel_a_action: lire le contrat d'interface et ouvrir une issue « bonne première contribution »
mention_de_dons: aucune dans ce billet (voir `content/funding/blocs-soutien.md` si nécessaire en fin de série)
```

# Devlog #1 — ce qui a tenu, ce qui a cassé, et trois décisions que je ne regrette pas

Premier sprint du MVP v0.1.0 d'Thot Secure terminé. Voici l'état réel, y compris les parties gênantes. Si vous cherchez une annonce triomphale, ce n'est pas ici.

## Ce qui est construit

Le contrat d'interface est gelé pour le sprint, et le code s'y conforme : normalisation d'événements, moteur de règles YAML (avec les opérateurs listés au §5 et une compatibilité partielle Sigma-lite), scoring de risque borné 0–100, moteur de décision *policy-as-code*, gate d'approbation, playbooks avec rollback, journal d'audit chaîné, API `/api/v1`, console embarquée sans build Node, et la CLI `thotsecure`.

Concrètement, le parcours complet fonctionne : je pose un fichier `events.jsonl`, j'ingère, un finding sort, une politique tranche, une action passe en `pending_approval`, je l'approuve, je l'exécute, je l'annule, et `thotsecure audit verify` me dit que la chaîne est intacte. C'est la démonstration que je voulais pouvoir faire avant d'écrire une ligne de communication.

## Ce qui a cassé

**La canonicalisation du hash, d'abord.** Premier bug trouvé par les tests d'audit : `verify()` déclarait la chaîne corrompue sur des journaux parfaitement sains. Cause : je sérialisais les dictionnaires `before` / `after` sans trier les clés. Un dictionnaire construit dans un ordre différent produit une empreinte différente. Deux heures perdues, et une leçon : quand un contrat spécifie `canonical()` — JSON trié, séparateurs compacts, UTF-8 — ce n'est pas un détail de style, c'est la condition de vérifiabilité. Le contrat est devenue ma référence, pas mon commentaire.

**Le cooldown, ensuite.** Je le calculais par `(tenant, playbook)` au lieu de `(tenant, playbook, cible)`. Résultat : bloquer une IP empêchait de bloquer une **autre** IP pendant cinq minutes. En test, c'était comique ; en production, c'est un angle mort exploitable. Corrigé, avec un test dédié.

**Et une décision que j'ai failli rater.** Ma première version faisait `ignore` par défaut quand aucune politique ne correspondait. Silencieux, élégant, faux. Le comportement correct est `notify_only` : si aucune politique ne matche, l'humain doit être averti. Le silence doit être **écrit explicitement** dans une politique `ignore`, jamais hérité d'un oubli.

## Trois décisions difficiles

**1. `dry_run` par défaut.** `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised` sont les défauts, et le `dry_run` global est prioritaire sur toute politique — une politique ne peut pas le contourner. La conséquence commerciale est désagréable : la première démo ne bloque rien. La conséquence opérationnelle est décisive : on peut brancher Thot Secure sur une infrastructure de production sans identifiants, en observation, et **tester le rollback** avant de donner à l'outil le droit d'agir.

**2. Une chaîne de hash, pas une blockchain.** Une blockchain résout le consensus entre parties qui ne se font pas confiance. Ici, l'autorité, c'est l'organisation qui exploite l'outil. Elle n'a pas besoin de mineurs : elle a besoin de prouver qu'un enregistrement n'a pas bougé. J'assume aussi la limite devant : avec un accès root, un attaquant réécrit la chaîne entière, et supprimer la **fin** du journal ne casse rien. Les contre-mesures sont l'export SIEM poussé et un ancrage horodaté de l'empreinte de tête — ce dernier n'est pas encore implémenté.

**3. Un bus pluggable.** `THOT_BUS` accepte `memory`, `sqlite` ou `nats`. J'ai hésité : trois implémentations à maintenir, c'est de la charge. Mais un bus imposé (NATS) aurait rendu le démarrage local pénible, et un bus unique `memory` aurait interdit la durabilité. Le compromis : `memory` par défaut pour le développement, `sqlite` pour la persistance locale, NATS quand on distribue — sans réécrire la logique de détection.

## Sortie de `thotsecure doctor`

*Forme indicative : la sortie exacte dépend de votre installation.*

```console
$ thotsecure doctor
Thot Secure 0.1.0 — diagnostic
[ok]   env=dev  dry_run=true  autonomy=supervised
[ok]   base: sqlite:///./data/thotsecure.db (schéma à jour)
[ok]   bus: memory
[ok]   règles: 42 chargées depuis ./rules (0 invalide)
[warn] politiques: 6 chargées — priorité max 100 (auto-block-high-web)
[warn] connecteurs: aucun configuré → playbooks en mode simulé (simulated: true)
[ok]   chaîne d'audit: 1284 enregistrements, valide
[warn] THOT_SECRET_KEY non défini (clé générée) — à fixer avant prod
[warn] THOT_BOOTSTRAP_API_KEY par défaut — à changer
[ok]   OPA absent → mode Rego désactivé
→ prêt, en mode simulation
```

```console
$ thotsecure findings list --tenant acme --severity high --min-risk 70
ID        SÉVÉRITÉ  RISQUE  RÈGLE        TITRE                                          STATUT
f1c2a9d0  high       78.5   AO-WEB-001   Tentative d'injection SQL depuis 203.0.113.9   open
f4b7e112  high       72.1   AO-WEB-004   User-Agent de scan offensif sur /wp-login    acked
2 findings (limite 100) — tenant acme
```

## Métriques du sprint

⚠️ **Les chiffres ci-dessous sont des ordres de grandeur destinés à montrer le format, pas des mesures.** Remplacez-les par vos valeurs réelles avant publication ; ne publiez jamais un chiffre que vous ne pouvez pas justifier.

| Indicateur | Valeur (à remplacer) |
|---|---|
| Fichiers de test (`unittest`, compatibles pytest) | 12 |
| Règles de détection livrées | ~40 |
| Politiques d'exemple | 6 |
| Playbooks livrés | 9 (+ inverses) |
| Endpoints `/api/v1` implémentés | ~30 |
| Bugs trouvés par les tests d'audit | 2 (canonicalisation, cooldown) |

## La suite

Priorités du prochain sprint : d'abord les tests manquants sur le rollback et l'idempotence (`idempotency_key`), ensuite un premier connecteur réel avec son inverse, puis l'ancrage horodaté de l'empreinte de tête d'audit. Le support PostgreSQL/TimescaleDB de première classe et les SDK TypeScript/Go restent **roadmap** : je préfère le dire maintenant plutôt que de le laisser deviner.

Si vous voulez aider : les issues « bonne première contribution » couvrent l'écriture de règles avec faux positifs documentés, un connecteur avec rollback, et la traduction. Le contrat d'interface fait foi — et si vous le trouvez faux ou incomplet, c'est exactement le genre de remarque que je veux recevoir avant d'avoir écrit dix mille lignes dessus.
