# Gouvernance

*Comment le projet Thot Secure est gouverné : licence, contributions, décisions, maintenance, sécurité et transparence — avec renvoi systématique aux fichiers qui font foi à la racine du dépôt.*

Les documents de référence de la gouvernance vivent **à la racine du dépôt**. Cette page les
résume et les relie ; en cas de divergence, ce sont les fichiers d'origine qui s'appliquent.

| Fichier (racine) | Objet |
|---|---|
| [`LICENSE`](../LICENSE) | Licence Apache-2.0 |
| [`NOTICE`](../NOTICE) | Mentions et attributions |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Guide de contribution de référence |
| [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Code de conduite et application |
| [`SECURITY.md`](../SECURITY.md) | Politique de sécurité et divulgation responsable |
| [`CHANGELOG.md`](../CHANGELOG.md) | Journal des modifications, source unique de vérité |
| [`README.md`](../README.md) | Point d'entrée du projet |
| [`GOVERNANCE.md`](../GOVERNANCE.md) | Gouvernance détaillée (rôles, votes, invariants) |
| [`MAINTAINERS.md`](../MAINTAINERS.md) | Registre des mainteneurs et des contacts |
| `.github/` | Modèles d'issues et de pull requests, financement (`FUNDING.yml`), workflows |

!!! note
    Certains de ces fichiers sont maintenus par d'autres lots que cette page de documentation. Ils
    sont cités ici, jamais dupliqués : une copie divergerait.

---

## 1. Licence Apache-2.0

Le projet est distribué sous **Apache License 2.0**. Ce que cela autorise :

* l'**usage commercial**, y compris interne à une entreprise ;
* la **modification** du code ;
* la **redistribution**, gratuite ou payante ;
* l'**intégration** dans un produit propriétaire, sous réserve des obligations ci-dessous ;
* l'usage de la licence de brevets associée, telle que rédigée dans le texte.

Obligations à respecter :

* conserver la **notice de licence**, les mentions de copyright et le fichier `NOTICE` ;
* **signaler les modifications** apportées aux fichiers ;
* inclure une copie de la licence dans toute redistribution ;
* ne pas utiliser les marques du projet pour suggérer une approbation non accordée.

!!! warning
    Apache-2.0 fournit le logiciel **sans garantie** d'aucune sorte. Cette section est une
    explication pratique : ce **n'est pas un avis juridique**. Pour un usage commercial ou
    réglementé, faites relire le texte de la licence par votre conseil.

## 2. Propriété intellectuelle et contributions

Le principe est **inbound = outbound** : ce qui entre dans le projet doit pouvoir en sortir sous la
même licence. Toute contribution est donc fournie sous Apache-2.0, sans condition supplémentaire.

Il n'y a **pas de CLA lourde** au MVP : vous conservez vos droits et vous accordez au projet le
droit de distribuer votre contribution sous Apache-2.0. En revanche, le projet exige un
**Developer Certificate of Origin** : le fichier [`CONTRIBUTING.md`](../CONTRIBUTING.md) à la racine
décrit la procédure de signature des commits. **Ce fichier réel fait foi** sur la mécanique exacte,
qui peut évoluer.

Deux règles pratiques :

* ne soumettez que du code que vous avez le droit de soumettre, et pas de code sous licence
  incompatible avec Apache-2.0 ;
* signalez explicitement toute dépendance tierce ajoutée, avec sa licence.

## 3. Processus de décision

| Type de changement | Processus |
|---|---|
| Correctif, documentation, règle de détection | Pull request + revue par les pairs ; consensus mou par défaut |
| Changement structurant (périmètre, API, dépendances du cœur) | Décision des mainteneurs, consensus recherché avant tout vote |
| Choix d'architecture | **ADR obligatoire** — voir [adr/0001-record-architecture-decisions.md](adr/0001-record-architecture-decisions.md) |
| Changement touchant la sécurité (`src/thotsecure/audit/`, `tenancy/`, `decision/`, `actions/`) | **Revue par les pairs obligatoire**, sans exception ni urgence qui l'annule |
| Modification des invariants | Hors de portée d'un vote : voir §6 |

Deux principes encadrent le reste :

1. **La sécurité prime sur la fonctionnalité.** Une fonctionnalité qui affaiblit un garde-fou est
   refusée, même si elle est utile et bien implémentée.
2. **Les défauts sûrs portent la charge de la preuve.** Une pull request qui assouplit
   `DRY_RUN`, `AUTONOMY` ou les garde-fous doit démontrer pourquoi, et non l'inverse.

## 4. Modèle de maintenance

* Les mainteneurs sont **bénévoles**. Il n'y a **aucun engagement de délai** sur les revues, les
  correctifs ou les versions.
* Les décisions se prennent **en public** : issues, discussions et pull requests du dépôt.
* Les branches et la mécanique de fusion sont décrites dans
  [`CONTRIBUTING.md`](../CONTRIBUTING.md) ; les modèles d'issues et de PR vivent dans `.github/`.
* **Politique de support : « au mieux ».** Aucun SLA n'est offert par le projet open source.
  Le fichier [`SECURITY.md`](../SECURITY.md) indique à ce jour que la ligne `0.1.x` est la seule
  supportée — à confirmer en le relisant, car c'est lui qui fait foi.
* Une offre de **support professionnel** peut exister le cas échéant, hors du dépôt ; elle
  n'affecte ni la licence, ni les correctifs de sécurité, ni la gouvernance.

## 5. Sécurité et divulgation responsable

La règle la plus importante : **ne jamais signaler une vulnérabilité dans un canal public** (issue,
pull request, discussion, réseau social). Un rapport public met en danger tous les déploiements
avant qu'un correctif n'existe.

Les canaux privés, le périmètre, les délais visés et la politique de crédit sont définis dans
[`SECURITY.md`](../SECURITY.md) à la racine. À ce jour, ce fichier documente :

* un **accusé de réception** sous 72 heures ;
* un **triage** sous 7 jours calendaires ;
* un **correctif** sous 30 jours pour les vulnérabilités critiques ;
* un **crédit par défaut** du rapporteur, sauf s'il demande l'anonymat.

Il n'y a **pas de récompense financière** (pas de programme de *bug bounty* rémunéré) au stade du
MVP. Le rapporteur est crédité s'il le souhaite, sous le nom ou le pseudonyme de son choix.

!!! tip
    En cas de doute sur la nature d'un problème : signalez-le en privé. Un faux positif coûte
    moins cher qu'une divulgation prématurée.

## 6. Invariants non négociables

Ces règles ne sont pas des préférences et ne se renversent pas par vote :

| # | Invariant | Portée |
|---|---|---|
| 1 | `DRY_RUN=true` par défaut, aucune action réelle sans levée explicite | Global |
| 2 | Toute action critique passe par `require_approval` ou un mode `auto` activé explicitement, et est journalisée | Décision |
| 3 | Toute action est **réversible** : le rollback doit réussir tant qu'il n'a pas expiré | Actions |
| 4 | Isolation stricte entre tenants, testée en CI | Données |
| 5 | Le core `thotsecure.core` ne dépend que de la stdlib + `pydantic`/`PyYAML` | Dépendances |
| 6 | **Zéro capacité offensive** : pas de scan agressif, pas de brute force, pas de « hack-back », pas de déni de service, pas d'exploitation de tiers | Constitutif (ADR 0006) |

Toute contribution contraire à l'un de ces invariants est refusée. Voir
[architecture/api-contract.md](architecture/api-contract.md) §1 et §10.

## 7. Conflits d'intérêts et transparence

* Les dons sont **volontaires et sans contrepartie** : ils financent l'infrastructure du projet
  (intégration continue, hébergement d'artefacts) et, le cas échéant, des audits externes.
  Voir [support.md](support.md).
* Le registre public des dons est **agrégé** : jamais nominatif sans consentement explicite.
* **Aucun avantage** — priorité de revue, influence sur la feuille de route, accès anticipé — n'est
  accordé en échange d'un don.
* **Aucun sponsor** n'obtient d'influence sur les décisions de sécurité, les invariants ou le
  contenu des garde-fous. Un sponsor qui le demanderait serait refusé.
* Les mainteneurs déclarent tout conflit d'intérêts susceptible d'affecter une revue et se
  retirent de la décision concernée.

## 8. Évolution de la gouvernance

!!! info "Roadmap"
    Si le projet grandit — plusieurs mainteneurs actifs, plusieurs organisations contributrices —,
    un **comité de mainteneurs** avec des règles de vote formalisées pourrait remplacer le
    consensus actuel. Rien n'est planifié à ce stade : toute évolution de ce type se déciderait en
    public et serait documentée dans `GOVERNANCE.md` avant d'entrer en vigueur.

## 9. Qui décide quoi

| Décision | Qui décide | Où c'est documenté |
|---|---|---|
| Correctif, règle, documentation | Auteur + relecteur | `CONTRIBUTING.md`, [detection/rules.md](detection/rules.md) |
| Ajout d'un connecteur ou d'un playbook | Relecteurs, avec exigence de rollback | [actions/playbooks.md](actions/playbooks.md) |
| Politique de décision livrée par défaut | Mainteneurs | [decision/policies.md](decision/policies.md) |
| Choix d'architecture | Mainteneurs, sur ADR | `adr/` |
| Changement du contrat d'interface | Mainteneurs, contrat gelé par défaut | [architecture/api-contract.md](architecture/api-contract.md) |
| Changement touchant `audit/`, `tenancy/`, `decision/`, `actions/` | Revue de sécurité obligatoire | `CODEOWNERS`, `.github/` |
| Modification des invariants | Personne : hors de portée d'un vote | `GOVERNANCE.md`, ADR 0006 |
| Vulnérabilité | Équipe sécurité, en privé | `SECURITY.md` |
| Licence | Processus dédié décrit dans `GOVERNANCE.md` | `LICENSE`, `NOTICE` |
| Adhésion ou retrait d'un mainteneur | Mainteneurs | `MAINTAINERS.md`, `GOVERNANCE.md` |

## Pour contribuer

Le point d'entrée pratique est [contributing.md](contributing.md) ; le texte de référence reste
[`CONTRIBUTING.md`](../CONTRIBUTING.md) à la racine. Pour les questions d'usage :
[support.md](support.md) et la [FAQ](faq.md).

<!-- Métadonnées: statut=stable, version=0.1.0 (MVP), dernière revue=2026-09-13 -->
