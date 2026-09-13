"""Interface explicite d'un magasin de persistance Thot Secure.

Ce module est le **contrat** que respectent les implémentations de stockage. Il existe pour
qu'une seconde implémentation (PostgreSQL/TimescaleDB, ``storage/postgres.py``) ne puisse pas
diverger silencieusement de la référence SQLite (``storage/store.py``) : la suite de conformité
``tests/test_storage_conformance.py`` exécute le **même** corpus de tests sur les deux, et
l'interface ci-dessous est la liste exhaustive de ce qu'elle a le droit d'appeler.

Invariants communs à toutes les implémentations
-----------------------------------------------

1. **Isolation multi-tenant** — toute lecture et toute écriture filtre ``tenant_id``. Aucune
   méthode ne retourne la ligne d'un autre tenant sans que l'appelant l'ait demandé
   explicitement (``iter_audit`` sans ``tenant_id`` est la seule exception, documentée).
2. **Idempotence** — ``event_id`` et ``idempotency_key`` sont uniques : rejouer une insertion
   ne duplique pas l'objet et ne lève pas. ``insert_event`` retourne ``False`` dans ce cas.
3. **Audit chaîné** — ``append_audit`` est transactionnel : deux processus concurrents ne
   peuvent pas produire deux maillons ayant le même ``prev_hash``. Une implémentation qui ne
   peut pas garantir cela doit le documenter explicitement.
4. **Erreurs typées** — une écriture impossible lève ``StorageError``, ``ConflictError``
   (unicité violée, idempotence) ou ``NotFoundError`` (mise à jour d'un objet absent).
   Aucune méthode ne laisse échapper l'exception brute du pilote de base de données.
5. **Curseurs opaques** — un curseur est une chaîne produite par le magasin ; sa forme interne
   n'est pas contractuelle, mais il doit rester exploitable par la **même** implémentation.
   La pagination est stable : aucun élément n'est ni dupliqué ni omis entre deux pages.

Capacités optionnelles
----------------------

``supports_backend_features()`` permet à la couche appelante (API, CLI, console) d'adapter son
comportement sans tester le type du magasin : compression de chunks, agrégats continus et
rétention native n'existent qu'avec TimescaleDB. Un appelant qui en dépend doit vérifier la
capacité **avant** de s'en servir ; aucune fonctionnalité listée n'est indispensable au
fonctionnement du produit.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator, Sequence
from typing import Any, ClassVar

from ..core.models import (
    Action,
    ApiKeyRecord,
    AuditRecord,
    CollectorStatus,
    Event,
    Finding,
    StatsOverview,
    Tenant,
)

# --------------------------------------------------------------------------------------
# Capacités de backend (``supports_backend_features``)
# --------------------------------------------------------------------------------------

#: Compression de chunks par le moteur (TimescaleDB) : les événements anciens sont stockés
#: compressés. Conséquence pour l'appelant : une plage compressée n'est plus modifiable, seule
#: la politique de rétention (``drop_chunks``) peut en supprimer le contenu.
FEATURE_COMPRESSION = "compression"

#: Agrégats continus (vues matérialisées rafraîchies automatiquement par le moteur) : la
#: volumétrie historique n'a plus besoin d'être recalculée par l'application.
FEATURE_CONTINUOUS_AGGREGATES = "continuous_aggregates"

#: Rétention appliquée par le moteur (``add_retention_policy``), en plus de ``purge()``.
FEATURE_NATIVE_RETENTION = "native_retention"

#: Réservation atomique d'un lot d'événements à rejouer par un seul processus
#: (``claim_pending_events``, verrou de bail). Sans cette capacité, ``pending_events`` peut
#: retourner le même lot à deux processus : ``mark_events_processed`` reste alors l'arbitre.
FEATURE_PENDING_CLAIM = "pending_claim"

#: ``SELECT ... FOR UPDATE SKIP LOCKED`` : deux lecteurs concurrents ne se bloquent pas et ne
#: se partagent pas les mêmes lignes.
FEATURE_SKIP_LOCKED = "for_update_skip_locked"

#: Index et opérateurs JSONB (``jsonb_path_ops``) pour interroger ``labels``/``payload``.
FEATURE_JSONB = "jsonb"

#: Resserrement de l'isolation au niveau du serveur (Row Level Security) — non implémenté.
FEATURE_ROW_LEVEL_SECURITY = "row_level_security"

__all__ = [
    "FEATURE_COMPRESSION",
    "FEATURE_CONTINUOUS_AGGREGATES",
    "FEATURE_JSONB",
    "FEATURE_NATIVE_RETENTION",
    "FEATURE_PENDING_CLAIM",
    "FEATURE_ROW_LEVEL_SECURITY",
    "FEATURE_SKIP_LOCKED",
    "StoreProtocol",
    "store_interface_methods",
]


class StoreProtocol(abc.ABC):
    """Contrat d'accès aux données d'Thot Secure.

    Les implémentations concrètes sont :

    * :class:`thotsecure.storage.store.Store` — SQLite (``sqlite3``, stdlib), enregistrée comme
      sous-classe virtuelle de cette ABC ;
    * :class:`thotsecure.storage.postgres.PostgresStore` — PostgreSQL/TimescaleDB
      (``psycopg``/``psycopg2``, extra optionnel ``postgres``).

    Toutes les méthodes sont synchrones et bloquantes : la couche appelante les exécute dans un
    thread de travail (``asyncio.to_thread`` côté API). Une instance est créée **une fois par
    processus** et reste utilisable depuis plusieurs threads.
    """

    #: Nom court du backend, utilisé par les journaux, ``/version`` et la documentation.
    backend_name: ClassVar[str] = "abstract"

    # ----------------------------------------------------------------------------------
    # Cycle de vie
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def init_schema(self) -> None:
        """Crée le schéma s'il n'existe pas (**idempotent**).

        Contrat : rappeler ``init_schema()`` sur une base à jour est sans effet et sans erreur ;
        c'est ce qui autorise la commande ``thotsecure init-db`` après chaque mise à jour.
        Certaines implémentations activent en outre des capacités optionnelles (hypertable,
        compression) : ``supports_backend_features()`` n'est fiable qu'**après** cet appel.

        Erreurs : ``StorageError`` si la base est injoignable, si le pilote est absent ou si le
        DDL ne peut pas être appliqué (droits insuffisants, extension indisponible).
        """

    @abc.abstractmethod
    def health(self) -> bool:
        """Vérifie réellement que la base répond.

        Contrat : exécute une requête triviale (``SELECT 1``) et retourne ``False`` — sans lever
        — si la base est injoignable, fermée ou en échec. Utilisé par ``/readyz`` et
        ``thotsecure doctor`` : cette méthode ne doit **jamais** faire tomber le service.
        """

    @abc.abstractmethod
    def close(self) -> None:
        """Libère les connexions. Idempotent.

        Après ``close()``, toute opération lève ``StorageError`` (« le stockage est fermé ») :
        c'est volontairement bruyant, un magasin fermé ne doit pas servir silencieusement des
        données périmées.
        """

    @abc.abstractmethod
    def transaction(self) -> Any:
        """Transaction d'écriture explicite, à utiliser comme gestionnaire de contexte.

        ``with store.transaction() as conn:`` — ``conn`` est la connexion du backend (objet
        spécifique au pilote : ``sqlite3.Connection``, ``psycopg.Connection``). Le bloc est
        validé (``COMMIT``) en sortie normale et annulé (``ROLLBACK``) sur exception.

        Cette méthode existe pour les appels qui doivent grouper plusieurs écritures ; elle
        n'est pas nécessaire pour les méthodes du contrat, qui sont déjà atomiques.
        """

    @abc.abstractmethod
    def supports_backend_features(self) -> frozenset[str]:
        """Capacités réellement disponibles sur ce backend (voir les constantes ``FEATURE_*``).

        Contrat : retourne un ensemble vide plutôt que ``None``. Pour un backend dont les
        capacités dépendent du serveur (TimescaleDB installé ou non), l'ensemble reflète l'état
        **constaté** au dernier ``init_schema()``, pas l'état souhaité.
        """

    # ----------------------------------------------------------------------------------
    # Tenants (frontière d'isolation)
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def upsert_tenant(self, tenant: Tenant, *, replace: bool = True) -> Tenant:
        """Crée ou remplace un tenant. Retourne le tenant **relu** depuis la base.

        Contrat : ``created_at`` n'est jamais écrasé par un upsert ; ``updated_at`` est
        repositionné. ``replace=False`` est accepté pour compatibilité et se comporte comme
        ``replace=True`` (aucune implémentation ne conserve de champs absents du modèle).
        ``autonomy_allowlist`` et ``protected_targets`` sont des listes de chaînes.

        Erreurs : ``StorageError`` si le tenant ne peut pas être relu après écriture (corruption).
        """

    @abc.abstractmethod
    def get_tenant(self, tenant_id: str) -> Tenant | None:
        """Retourne le tenant, ou ``None`` s'il n'existe pas. Ne lève jamais pour un identifiant
        inconnu — c'est ``require_tenant`` qui lève."""

    @abc.abstractmethod
    def require_tenant(self, tenant_id: str) -> Tenant:
        """Comme ``get_tenant`` mais lève ``NotFoundError`` si le tenant n'existe pas."""

    @abc.abstractmethod
    def list_tenants(self) -> list[Tenant]:
        """Tous les tenants, triés par ``tenant_id`` (uniquement les identifiants : jamais de
        secret)."""

    @abc.abstractmethod
    def update_tenant(self, tenant_id: str, **fields: Any) -> Tenant:
        """Met à jour les champs autorisés d'un tenant et retourne le tenant relu.

        Champs autorisés : ``name``, ``mode``, ``dry_run``, ``autonomy_allowlist``,
        ``protected_targets``, ``max_actions_per_hour``, ``cooldown_seconds``,
        ``asset_criticality``. Les autres clés et les valeurs ``None`` sont **ignorées** (pas
        d'erreur : la couche API valide déjà la charge utile). Un appel sans champ utile
        retourne le tenant inchangé.

        Erreurs : ``NotFoundError`` si le tenant n'existe pas.
        """

    # ----------------------------------------------------------------------------------
    # Clés API (toujours hachées, jamais en clair)
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def insert_api_key(self, record: ApiKeyRecord) -> ApiKeyRecord:
        """Insère une clé API hachée. ``key_hash`` est une empreinte ``scrypt`` : la clé en clair
        n'existe que dans la réponse de création, jamais en base.

        Erreurs : ``ConflictError`` si ``key_id`` ou ``key_hash`` existe déjà.
        """

    @abc.abstractmethod
    def get_api_key(self, key_id: str) -> ApiKeyRecord | None:
        """Retourne la clé par identifiant public (révoquée ou non), sinon ``None``."""

    @abc.abstractmethod
    def find_api_key_by_hash(self, key_hash: str) -> ApiKeyRecord | None:
        """Retourne la clé **non révoquée** correspondant à l'empreinte, sinon ``None``.

        Contrat : le filtre ``revoked_at IS NULL`` est indispensable — une clé révoquée ne doit
        jamais authentifier.
        """

    @abc.abstractmethod
    def list_api_keys(self, tenant_id: str) -> list[ApiKeyRecord]:
        """Clés d'un tenant, les plus récentes d'abord. Jamais de ``key_hash`` exploitable :
        l'objet est destiné à l'affichage."""

    @abc.abstractmethod
    def revoke_api_key(self, key_id: str, *, tenant_id: str | None = None) -> bool:
        """Révoque une clé active (renseigne ``revoked_at``, **ne supprime pas** la ligne).

        Retourne ``True`` si une clé active a été révoquée, ``False`` si elle était déjà
        révoquée ou inexistante. ``tenant_id`` restreint l'opération au tenant (défense contre
        une révocation croisée).
        """

    @abc.abstractmethod
    def touch_api_key(self, key_id: str) -> None:
        """Met à jour ``last_used_at`` (détection des clés dormantes). Sans effet si la clé
        n'existe pas — cet appel est sur le chemin chaud de l'authentification et ne doit
        jamais faire échouer une requête."""

    # ----------------------------------------------------------------------------------
    # Événements (immuables, purgés par rétention)
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def insert_event(self, event: Event) -> bool:
        """Insère un événement. Retourne ``False`` si ``event_id`` existe déjà (idempotence).

        Contrat : ne lève pas sur doublon. ``labels`` et ``payload`` sont des ``dict`` Python
        côté appelant ; la sérialisation est de la responsabilité du magasin.
        """

    @abc.abstractmethod
    def insert_events(self, events: Sequence[Event]) -> int:
        """Insertion par lots, en une seule transaction. Retourne le nombre de lignes
        **réellement insérées** (les doublons sont ignorés, pas comptés).

        Contrat : ``insert_events([]) == 0`` ; l'ordre d'entrée n'a pas d'importance ; un lot de
        *n* événements ne doit pas produire *n* allers-retours réseau si le backend permet mieux
        (l'implémentation découpe en tranches bornées, 1000 lignes par défaut).

        Erreurs : ``StorageError`` si la transaction échoue (aucune insertion partielle).
        """

    @abc.abstractmethod
    def get_event(self, tenant_id: str, event_id: str) -> Event | None:
        """Retourne l'événement du tenant, sinon ``None``. Un ``event_id`` existant mais
        appartenant à un autre tenant retourne ``None`` (isolation)."""

    @abc.abstractmethod
    def query_events(
        self,
        tenant_id: str,
        *,
        kinds: Sequence[str] | None = None,
        source_types: Sequence[str] | None = None,
        since: Any = None,
        until: Any = None,
        q: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[Event], str | None]:
        """Recherche paginée par curseur, du plus récent au plus ancien (``ts DESC``).

        * ``kinds`` / ``source_types`` : filtres ``IN`` (liste vide = pas de filtre) ;
        * ``since`` / ``until`` : bornes inclusives, acceptées en ``datetime`` ou en chaîne
          ISO-8601 ;
        * ``q`` : recherche textuelle dans ``labels`` **et** ``payload`` (insensible à la casse
          côté PostgreSQL, sensible côté SQLite : la sémantique exacte du contrat §4.3 n'est pas
          figée) ;
        * ``limit`` : borné à ``[1, MAX_PAGE_SIZE]`` (500) — jamais d'épuisement mémoire ;
        * ``cursor`` : curseur opaque rendu par l'appel précédent.

        Retourne ``(page, curseur_suivant)`` ; ``curseur_suivant`` vaut ``None`` sur la dernière
        page. Erreurs : ``StorageError`` si le curseur est invalide.
        """

    @abc.abstractmethod
    def pending_events(self, *, limit: int = 500) -> list[Event]:
        """Événements jamais traités par le pipeline, du plus ancien au plus récent.

        Utilisé au démarrage et par le rejeu après incident. Contrat : lecture **sans effet de
        bord** (elle ne marque rien) ; l'appelant doit appeler ``mark_events_processed``.
        Deux processus peuvent recevoir le même lot : ``mark_events_processed`` est l'arbitre,
        et un backend capable de réservation atomique expose ``claim_pending_events`` en plus
        (capacité ``FEATURE_PENDING_CLAIM``).
        """

    @abc.abstractmethod
    def mark_events_processed(self, event_ids: Sequence[str]) -> int:
        """Marque des événements comme traités. Retourne le nombre de lignes **transitions**
        (les événements déjà traités ne sont pas recomptés).

        Contrat : c'est cet ``UPDATE`` conditionnel (``... AND processed = FALSE``) qui garantit
        qu'un événement n'est marqué qu'une fois, même si deux processus l'ont lu.
        ``mark_events_processed([]) == 0``.
        """

    @abc.abstractmethod
    def count_events(self, tenant_id: str, *, since: Any = None) -> int:
        """Nombre d'événements du tenant, éventuellement depuis ``since`` (borne inclusive)."""

    @abc.abstractmethod
    def events_by_kind(self, tenant_id: str, *, since: Any = None) -> dict[str, int]:
        """Répartition des événements par ``kind``, du plus fréquent au moins fréquent."""

    # ----------------------------------------------------------------------------------
    # Findings (agrégats produits par la détection)
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def insert_finding(self, finding: Finding) -> Finding:
        """Insère un finding et retourne l'objet inséré.

        Erreurs : ``ConflictError`` si ``finding_id`` existe déjà.
        """

    @abc.abstractmethod
    def update_finding(self, tenant_id: str, finding_id: str, **fields: Any) -> Finding:
        """Met à jour les champs autorisés d'un finding et retourne l'objet relu.

        Champs autorisés : ``severity``, ``risk_score``, ``confidence``, ``status``, ``title``,
        ``description``, ``remediation``, ``tags``, ``mitre``, ``evidence``, ``last_seen``,
        ``count``, ``event_ids``, ``resolution``, ``comment``, ``dedup_key``. Les autres clés et
        les valeurs ``None`` sont ignorées ; ``updated_at`` est toujours repositionné.

        Erreurs : ``NotFoundError`` si le finding n'existe pas **pour ce tenant**.
        """

    @abc.abstractmethod
    def get_finding(self, tenant_id: str, finding_id: str) -> Finding | None:
        """Retourne le finding du tenant, sinon ``None`` (un finding d'un autre tenant est
        indiscernable d'un finding inexistant)."""

    @abc.abstractmethod
    def find_open_finding(self, tenant_id: str, rule_id: str, dedup_key: str) -> Finding | None:
        """Finding **ouvert ou acquitté** correspondant à la clé de déduplication, le plus
        récent d'abord — c'est la recherche qui décide si un événement crée un finding ou
        alimente l'agrégat existant. Un finding ``closed`` ou ``suppressed`` n'est pas retourné.
        """

    @abc.abstractmethod
    def list_findings(
        self,
        tenant_id: str,
        *,
        status: Sequence[str] | None = None,
        severity: Sequence[str] | None = None,
        rule_id: str | None = None,
        since: Any = None,
        until: Any = None,
        min_risk: float | None = None,
        q: str | None = None,
        sort: str = "risk_score",
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[Finding], str | None]:
        """Recherche paginée par curseur.

        ``sort`` : ``risk_score`` (défaut, décroissant) ou ``last_seen`` (décroissant) — toute
        autre valeur est traitée comme ``last_seen``. ``min_risk`` est une borne inclusive.
        ``q`` cherche dans ``title``, ``description`` et ``rule_id``. ``since``/``until``
        portent sur ``last_seen``. Retourne ``(page, curseur_suivant)``.

        Erreurs : ``StorageError`` si le curseur est invalide.
        """

    @abc.abstractmethod
    def count_findings(self, tenant_id: str, *, since: Any = None) -> dict[str, Any]:
        """Compteurs d'un tenant, sous la forme ``{"by_severity": {...}, "by_status": {...},
        "top_rules": [{"rule_id", "count", "max_risk"}]}``.

        ``since`` filtre sur ``last_seen``. ``top_rules`` est limité aux 10 règles les plus
        fréquentes. Les valeurs numériques sont des ``int``/``float`` (jamais ``Decimal``) :
        la couche API les sérialise directement.
        """

    # ----------------------------------------------------------------------------------
    # Actions (SOAR)
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def insert_action(self, action: Action) -> Action:
        """Insère une action et retourne l'objet inséré.

        Erreurs : ``ConflictError`` si ``idempotency_key`` existe déjà (rejeu d'une exécution) —
        ``details["action_id"]`` porte alors l'identifiant de l'action existante — ou si
        ``action_id`` est en doublon.
        """

    @abc.abstractmethod
    def update_action(self, action: Action) -> Action:
        """Persiste l'état d'une action (statut, approbation, exécution, résultat, rollback,
        ``audit_seq``) et retourne l'objet fourni.

        Contrat : la mise à jour est complète pour les champs de cycle de vie ; les champs
        immuables (``params``, ``target``, ``requested_by``, ``requested_at``) ne sont pas
        modifiés par cette méthode.

        Erreurs : ``NotFoundError`` si l'action n'existe pas pour ce tenant.
        """

    @abc.abstractmethod
    def get_action(self, tenant_id: str, action_id: str) -> Action | None:
        """Retourne l'action du tenant, sinon ``None``."""

    @abc.abstractmethod
    def find_action_by_idempotency(self, idempotency_key: str) -> Action | None:
        """Retourne l'action portant cette clé d'idempotence, quel que soit le tenant
        (la clé est unique globalement : ``acme:block-source-ip:203.0.113.9:1739527200``)."""

    @abc.abstractmethod
    def list_actions(
        self,
        tenant_id: str,
        *,
        status: Sequence[str] | None = None,
        playbook: str | None = None,
        finding_id: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[Action], str | None]:
        """Actions d'un tenant, les plus récentes d'abord (``requested_at DESC``), paginées par
        curseur. Retourne ``(page, curseur_suivant)``."""

    @abc.abstractmethod
    def count_actions_since(
        self,
        tenant_id: str,
        since: Any,
        *,
        playbook: str | None = None,
        exclude_failed: bool = True,
    ) -> int:
        """Compteur utilisé par le garde-fou ``max_actions_per_hour``.

        ``exclude_failed=True`` (défaut) exclut ``rejected`` et ``failed`` : une tentative
        refusée ne consomme pas le quota. ``playbook`` restreint le comptage à un playbook.
        """

    @abc.abstractmethod
    def last_action_for(self, tenant_id: str, playbook: str, target_value: str) -> Action | None:
        """Dernière action non terminale-négative sur une cible donnée — sert au calcul du
        cooldown par ``(tenant, playbook, cible)``.

        Contrat : la recherche porte sur la **valeur** de cible telle qu'elle a été persistée
        (``target.value``) ; les statuts considérés sont ``succeeded``, ``executing`` et
        ``approved``. Retourne ``None`` si aucune action ne correspond.
        """

    @abc.abstractmethod
    def actions_by_status(self, tenant_id: str, *, since: Any = None) -> dict[str, int]:
        """Répartition des actions par statut, éventuellement depuis ``since``.

        ``since`` porte sur ``requested_at``.
        """

    @abc.abstractmethod
    def actions_for_finding(self, tenant_id: str, finding_id: str) -> list[Action]:
        """Toutes les actions rattachées à un finding, les plus récentes d'abord. Sans
        pagination : un finding porte un nombre d'actions borné par la politique."""

    # ----------------------------------------------------------------------------------
    # Audit (append-only, chaîné par hash)
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def append_audit(
        self,
        *,
        tenant_id: str,
        actor: str,
        action: str,
        actor_role: str = "system",
        target: dict[str, Any] | None = None,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        ts: Any = None,
    ) -> AuditRecord:
        """Ajoute un maillon au journal d'audit et retourne l'enregistrement complet.

        Contrat **transactionnel** : la séquence (``seq``) et l'empreinte du maillon précédent
        (``prev_hash``) sont lues et écrites dans la **même** transaction, sous un verrou qui
        empêche deux écrivains concurrents de chaîner sur le même maillon. C'est l'invariant
        central du produit : deux processus qui appellent ``append_audit`` en parallèle ne
        peuvent pas produire une chaîne cassée.

        ``context`` n'entre pas dans l'empreinte mais est persisté (détail d'investigation).
        ``ts`` accepte un ``datetime`` ou une chaîne ISO-8601 ; par défaut, l'heure courante UTC.

        Erreurs : ``StorageError`` si le maillon ne peut pas être ajouté. Une erreur d'audit
        n'est jamais silencieuse : l'appelant doit considérer l'opération métier comme non
        journalisée et donc non fiable.
        """

    @abc.abstractmethod
    def list_audit(
        self,
        tenant_id: str,
        *,
        action: str | None = None,
        actor: str | None = None,
        since: Any = None,
        until: Any = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> tuple[list[AuditRecord], str | None]:
        """Journal d'un tenant, du plus récent au plus ancien (``seq DESC``), paginé par curseur.

        Le curseur d'audit est la représentation textuelle du dernier ``seq`` rendu. Retourne
        ``(page, curseur_suivant)``.
        """

    @abc.abstractmethod
    def iter_audit(self, *, tenant_id: str | None = None) -> Iterator[AuditRecord]:
        """Itère la chaîne **complète** dans l'ordre des ``seq`` croissants.

        C'est la lecture qui alimente la vérification d'intégrité (``/api/v1/audit/verify``).
        Sans ``tenant_id``, la chaîne globale est parcourue : les empreintes relient tous les
        tenants entre eux, filtrer par tenant laisserait passer une suppression ciblée.

        L'implémentation matérialise la page en mémoire : appelée sur un journal de plusieurs
        millions de lignes, elle doit être réservée aux outils de vérification hors ligne.
        """

    @abc.abstractmethod
    def count_audit(self, tenant_id: str, *, since: Any = None) -> int:
        """Nombre d'enregistrements d'audit d'un tenant, éventuellement depuis ``since``."""

    # ----------------------------------------------------------------------------------
    # Collecteurs et suppressions
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def record_collector_run(
        self,
        *,
        tenant_id: str,
        collector: str,
        status: str,
        started_at: Any,
        finished_at: Any = None,
        events: int = 0,
        findings: int = 0,
        errors: int = 0,
        detail: dict[str, Any] | None = None,
    ) -> str:
        """Enregistre une exécution de collecteur et retourne son ``run_id``.

        ``status`` ∈ ``running | ok | partial | error`` ; ``detail`` est un JSON libre
        (diagnostic, compteurs secondaires), jamais un secret.
        """

    @abc.abstractmethod
    def collector_stats(self, tenant_id: str) -> dict[str, dict[str, Any]]:
        """Statistiques par collecteur : ``runs``, ``last_run`` (ISO-8601, ou ``None``),
        ``last_status`` (``never`` si aucun run), ``events``, ``findings``, ``errors``,
        ``detail`` (JSON du dernier run)."""

    @abc.abstractmethod
    def add_suppression(
        self,
        *,
        tenant_id: str,
        rule_id: str,
        dedup_key: str,
        reason: str,
        expires_at: Any,
        created_by: str = "system",
    ) -> str:
        """Crée une exception de détection (silence temporaire) et retourne son identifiant.

        ``dedup_key`` vide signifie « toutes les cibles de cette règle ». ``expires_at`` est
        obligatoire : une suppression sans date de fin est un angle mort permanent. Une
        ``reason`` est exigée par le contrat (§4.4) pour la traçabilité du silence.
        """

    @abc.abstractmethod
    def is_suppressed(self, tenant_id: str, rule_id: str, dedup_key: str) -> bool:
        """Vrai si une suppression **non expirée** couvre ce couple règle/cible (une suppression
        à ``dedup_key`` vide couvre toutes les cibles)."""

    @abc.abstractmethod
    def list_suppressions(self, tenant_id: str) -> list[dict[str, Any]]:
        """Suppressions actives d'un tenant, triées par expiration croissante.

        Contrat de forme : les clés sont celles du schéma (``suppression_id``, ``tenant_id``,
        ``rule_id``, ``dedup_key``, ``reason``, ``created_by``, ``created_at``, ``expires_at``)
        et les horodatages sont des **chaînes ISO-8601 UTC**, identiques d'un backend à l'autre.
        """

    # ----------------------------------------------------------------------------------
    # Statistiques et rétention
    # ----------------------------------------------------------------------------------

    @abc.abstractmethod
    def stats_overview(
        self,
        tenant_id: str,
        *,
        window_hours: int = 24,
        collectors: Sequence[CollectorStatus] | None = None,
    ) -> StatsOverview:
        """Tableau de bord de ``GET /api/v1/stats/overview`` sur une fenêtre glissante.

        Contrat : les compteurs portent sur ``window_hours`` heures ; ``mttd_seconds`` (premier
        événement → création du finding) et ``mttr_seconds`` (création → clôture) valent ``None``
        quand aucun finding ne permet de les calculer — jamais ``0`` par défaut, qui serait
        indiscernable d'une performance parfaite.
        """

    @abc.abstractmethod
    def purge(self, *, retention_days: int = 30, audit_retention_days: int = 365) -> dict[str, int]:
        """Applique la rétention et retourne ``{"events": n, "suppressions": n, "audit": n}``.

        Règles (contrat §6, §9) :

        * ``events`` plus vieux que ``retention_days`` jours (sur ``ts``) sont supprimés ;
        * ``suppressions`` expirées sont supprimées ;
        * ``audit_log`` **n'est pas purgé** par défaut : ``audit_retention_days`` (365) est
          supérieur au seuil de 3650 jours en deçà duquel la purge d'audit est autorisée. Le
          journal d'audit est la preuve : sa suppression est un choix explicite de l'exploitant.

        Contrat d'implémentation : la purge procède **par lots bornés** (une transaction courte
        par lot) et ne prend jamais un verrou sur une table entière — une table d'événements de
        plusieurs milliards de lignes doit rester ingérable pendant la purge.
        """

    @abc.abstractmethod
    def vacuum(self) -> None:
        """Compacte / rafraîchit les statistiques du moteur (``VACUUM`` côté SQLite,
        ``VACUUM (ANALYZE)`` côté PostgreSQL). Opération d'exploitation, jamais sur le chemin
        d'une requête."""


def store_interface_methods() -> tuple[str, ...]:
    """Liste triée des noms de méthodes du contrat.

    Utilisée par la suite de conformité pour vérifier qu'une implémentation expose bien
    l'intégralité de l'interface — un magasin incomplet doit échouer **en test**, pas en
    production à la première requête de la console.
    """
    return tuple(sorted(StoreProtocol.__abstractmethods__))
