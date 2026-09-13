"""Socle commun des tests : construction d'une pile Thot Secure complète et isolée.

Les tests ne doivent jamais toucher au système de fichiers du dépôt ni au réseau : chaque
test reçoit un répertoire temporaire, un fichier SQLite dédié, une bibliothèque de règles,
des politiques et des playbooks écrits sur disque — de sorte que **le chemin de chargement
réel soit exercé**, et pas seulement les objets Python.
"""

from __future__ import annotations

import shutil
import tempfile
import textwrap
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from thotsecure.actions.engine import ActionEngine
from thotsecure.actions.executor import PlaybookExecutor
from thotsecure.actions.playbook_loader import load_playbooks_from_dir
from thotsecure.actions.registry import ConnectorRegistry
from thotsecure.audit.chain import AuditChain
from thotsecure.collectors.registry import default_registry
from thotsecure.collectors.runner import CollectorRunner
from thotsecure.core.config import Settings
from thotsecure.core.models import Event, EventSource, Tenant
from thotsecure.decision.engine import DecisionEngine
from thotsecure.decision.policy_loader import load_policies_from_dir
from thotsecure.detection.engine import DetectionEngine
from thotsecure.detection.rule_loader import load_rules_from_dir
from thotsecure.pipeline import Pipeline
from thotsecure.scope import TargetRegistry
from thotsecure.storage.store import Store
from thotsecure.tenancy.auth import ApiKeyService

# --------------------------------------------------------------------------------------
# Contenus de test (écrits en YAML pour exercer le chargeur réel)
# --------------------------------------------------------------------------------------

RULE_SQLI = """
id: AO-WEB-001
title: Tentative d'injection SQL dans un paramètre de requête
description: Détecte les motifs classiques d'injection SQL dans les requêtes HTTP.
status: stable
severity: high
confidence: 0.85
enabled: true
tags: [web, owasp:a03, mitre:T1190]
source_types: [web_probe, log_tail, webhook]
kinds: [http.request]
match:
  all:
    - field: labels.path
      op: regex
      value: "(?i)(union[\\\\s/*]+select|or\\\\s+1=1|sleep\\\\(\\\\d+\\\\)|benchmark\\\\()"
  threshold:
    count: 3
    window_seconds: 60
    group_by: [labels.src_ip]
dedup:
  key: [labels.src_ip]
  ttl_seconds: 900
risk:
  base: 60
false_positives:
  - Champ de recherche libre contenant le mot « union ».
remediation: Bloquer l'IP source au WAF pendant 1 h puis vérifier les journaux applicatifs.
references:
  - https://owasp.org/Top10/A03_2021-Injection/
"""

RULE_MISSING_HSTS = """
id: AO-WEB-050
title: En-tête HSTS absent
description: Le site n'impose pas HTTPS via l'en-tête Strict-Transport-Security.
status: stable
severity: medium
confidence: 0.9
enabled: true
tags: [web, hardening, owasp:a05]
source_types: [web_probe]
kinds: [http.response]
match:
  all:
    - field: labels.check
      op: eq
      value: missing_hsts
dedup:
  key: [labels.host]
  ttl_seconds: 86400
risk:
  base: 30
remediation: "Ajouter l'en-tête « Strict-Transport-Security: max-age=31536000; includeSubDomains »."
"""

RULE_DEPENDENCY = """
id: AO-DEP-001
title: Dépendance vulnérable détectée
description: Une dépendance déclarée correspond à une vulnérabilité connue.
status: test
severity: high
confidence: 0.8
enabled: true
tags: [supply-chain, owasp:a06, mitre:T1195]
source_types: [dependency]
kinds: [dependency]
match:
  all:
    - field: labels.cvss
      op: gte
      value: 7.0
dedup:
  key: [labels.package, labels.version]
  ttl_seconds: 604800
risk:
  base: 55
remediation: Mettre à jour vers la version corrigée indiquée par l'avis de sécurité.
"""

RULE_SSH_WEAK = """
id: AO-CFG-001
title: Configuration SSH permissive
description: La configuration SSH autorise la connexion directe de root.
status: stable
severity: high
confidence: 0.95
enabled: true
tags: [config, hardening, cis:5.2]
source_types: [config_audit]
kinds: [config.audit]
match:
  all:
    - field: labels.check
      op: eq
      value: ssh_permit_root_login
dedup:
  key: [labels.file]
  ttl_seconds: 86400
risk:
  base: 55
remediation: Positionner « PermitRootLogin no » puis recharger le service SSH.
"""

RULE_SIGMA = """
title: Connexion réussie après plusieurs échecs
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Motif Sigma minimal utilisé pour valider le traducteur.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    TargetUserName: admin
  filter:
    IpAddress: 127.0.0.1
  condition: selection and not filter
level: high
tags:
  - attack.t1078
falsepositives:
  - Administrateur légitime depuis la console locale.
"""

POLICY_AUTO_BLOCK = """
version: 1
id: auto-block-high-web
priority: 100
description: Blocage automatique des attaques web à score élevé, en mode autonome seulement.
when:
  finding.severity: [critical, high]
  finding.risk_score: { gte: 70 }
  finding.tags_any: [web, exploit-attempt]
then:
  decision: auto
  playbook: block-source-ip
  params:
    target: labels.src_ip
    duration_seconds: 3600
    reason: "Thot Secure — attaque web à fort score"
  cooldown_seconds: 300
rollback:
  playbook: unblock-source-ip
  auto_after_seconds: 3600
"""

POLICY_APPROVAL_SUPPLY_CHAIN = """
version: 1
id: approval-supply-chain
priority: 150
description: Toute vulnérabilité de dépendance exige une validation humaine avant action.
when:
  finding.tags_any: [supply-chain]
then:
  decision: require_approval
  playbook: patch-dependency
  params:
    target: labels.package
    version: labels.fixed_version
"""

POLICY_NOTIFY_HARDENING = """
version: 1
id: notify-only-hardening
priority: 50
description: Le durcissement est notifié, jamais appliqué automatiquement.
when:
  finding.tags_any: [hardening, config]
then:
  decision: notify_only
  playbook: harden-endpoint
"""

PLAYBOOK_BLOCK_IP = """
name: block-source-ip
description: Bloque une adresse source au niveau du connecteur WAF configuré.
reversible: true
dry_run_capable: true
connectors: [waf]
params:
  target:
    type: ip
    required: true
    description: Adresse IP ou plage CIDR à bloquer.
  duration_seconds:
    type: duration
    default: 3600
    min: 60
    max: 604800
    description: Durée du blocage, en secondes.
  reason:
    type: string
    default: "Thot Secure — contre-mesure automatique"
    description: Motif inscrit dans le journal du connecteur.
execute:
  - connector: waf
    call: block_ip
    with:
      ip: "${params.target}"
      ttl: "${params.duration_seconds}"
      note: "${params.reason}"
rollback:
  - connector: waf
    call: unblock_ip
    with:
      ip: "${params.target}"
audit:
  severity: high
  notify: [ticketing]
"""

PLAYBOOK_UNBLOCK_IP = """
name: unblock-source-ip
description: Retire un blocage précédemment appliqué.
reversible: true
dry_run_capable: true
connectors: [waf]
params:
  target:
    type: ip
    required: true
    description: Adresse IP à débloquer.
execute:
  - connector: waf
    call: unblock_ip
    with:
      ip: "${params.target}"
rollback:
  - connector: waf
    call: block_ip
    with:
      ip: "${params.target}"
"""

PLAYBOOK_PATCH_DEPENDENCY = """
name: patch-dependency
description: Ouvre une demande de mise à jour de dépendance (jamais de fusion automatique).
reversible: true
dry_run_capable: true
connectors: [ci, ticketing]
params:
  target:
    type: string
    required: true
    description: Nom du paquet concerné.
  version:
    type: string
    default: ""
    description: Version corrigée visée.
execute:
  - connector: ticketing
    call: open_ticket
    with:
      title: "Mise à jour de dépendance : ${params.target}"
      severity: high
      description: "Version visée : ${params.version}"
  - connector: ci
    call: patch_dependency
    with:
      package: "${params.target}"
      version: "${params.version}"
rollback:
  - connector: ticketing
    call: close_ticket
    with:
      rollback_token: "${params.rollback_token}"
      resolution: "annulé"
"""

PLAYBOOK_HARDEN_ENDPOINT = """
name: harden-endpoint
description: Applique un profil de durcissement à un actif déclaré.
reversible: true
dry_run_capable: true
connectors: [harden]
params:
  target:
    type: host
    required: true
    description: Hôte à durcir.
  profile:
    type: string
    default: baseline
    choices: [baseline, strict, web]
    description: Profil de durcissement.
execute:
  - connector: harden
    call: harden_endpoint
    with:
      host: "${params.target}"
      profile: "${params.profile}"
rollback:
  - connector: harden
    call: harden_endpoint
    with:
      host: "${params.target}"
      profile: rollback
"""

PLAYBOOK_REVOKE_SESSION = """
name: revoke-session
description: Révoque les sessions actives d'un utilisateur compromis (irréversible).
reversible: false
dry_run_capable: true
connectors: [iam]
params:
  target:
    type: string
    required: true
    description: Identifiant de l'utilisateur.
execute:
  - connector: iam
    call: revoke_session
    with:
      user: "${params.target}"
"""

TARGETS_YAML = """
tenants:
  acme:
    assets:
      - host: shop.acme.fr
        urls: ["https://shop.acme.fr"]
        criticality: 1.5
        tags: [production]
      - host: api.acme.fr
        urls: ["https://api.acme.fr"]
        criticality: 2.0
    owned_cidrs: ["198.51.100.0/24"]
    protected_targets: ["10.0.0.1", "10.0.0.0/24"]
    allow_probe: true
    log_sources:
      - path: ./logs/access.log
        format: nginx
    manifests:
      - ./app/requirements.txt
    config_files:
      - path: ./etc/sshd_config
        kind: ssh
  demo:
    assets:
      - host: demo.local
        urls: ["http://127.0.0.1:8000"]
    owned_cidrs: ["127.0.0.1/32"]
    allow_probe: true
"""

ACCESS_LOG = """203.0.113.7 - - [14/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
198.51.100.4 - - [14/Feb/2026:10:00:01 +0000] "POST /login HTTP/1.1" 403 512 "-" "curl/8.5.0"
203.0.113.9 - - [14/Feb/2026:10:00:02 +0000] "GET /product?id=1 UNION SELECT 1-- HTTP/1.1" 500 2048 "-" "sqlmap/1.7"
"""

REQUIREMENTS_TXT = """# Dépendances de test (épinglées volontairement vulnérables)
jinja2==3.1.2
requests==2.31.0
pyyaml==5.3.1
fastapi==0.110.0
"""

SSHD_CONFIG = """# Configuration SSH de test (volontairement permissive)
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
Protocol 2
"""

NGINX_CONF = """server {
    listen 80;
    server_name shop.acme.fr;
    server_tokens on;
    autoindex on;
    ssl_protocols TLSv1 TLSv1.2;
}
"""

CONNECTORS_YAML = """
version: 1
connectors:
  waf:
    driver: simulation
  ticketing:
    driver: local-ticket
    settings:
      directory: ./data/tickets
  ci:
    driver: simulation
  harden:
    driver: simulation
  iam:
    driver: simulation
  artifact:
    driver: local-quarantine
    settings:
      quarantine_dir: ./data/quarantine
"""


# --------------------------------------------------------------------------------------
# Pile de test
# --------------------------------------------------------------------------------------


@dataclass
class Stack:
    """Pile applicative complète, prête à l'emploi dans un test."""

    root: Path
    settings: Settings
    store: Store
    audit: AuditChain
    detection: DetectionEngine
    decision: DecisionEngine
    actions: ActionEngine
    pipeline: Pipeline
    keys: ApiKeyService
    connectors: ConnectorRegistry
    registry: TargetRegistry
    tenant: Tenant
    playbooks: dict[str, Any]
    collectors: Any = None

    def event(self, **overrides: Any) -> Event:
        """Construit un événement HTTP cohérent pour le tenant de la pile."""
        labels = {
            "src_ip": "203.0.113.9",
            "path": "/login",
            "method": "POST",
            "host": "shop.acme.fr",
            **overrides.pop("labels", {}),
        }
        payload = {"status": 403, "bytes": 512, **overrides.pop("payload", {})}
        kind = overrides.pop("kind", "http.request")
        source_type = overrides.pop("source_type", "log_tail")
        data: dict[str, Any] = {
            "tenant_id": overrides.pop("tenant_id", self.tenant.tenant_id),
            "kind": kind,
            "source": EventSource(
                type=source_type,
                name=overrides.pop("source_name", "nginx-prod"),
                host=overrides.pop("source_host", "shop.acme.fr"),
            ),
            "labels": labels,
            "payload": payload,
        }
        data.update(overrides)
        return Event(**data)

    def sqli_burst(self, *, count: int = 3, src_ip: str = "203.0.113.9") -> list[Event]:
        """Série de requêtes d'injection SQL : franchit le seuil de la règle AO-WEB-001."""
        return [
            self.event(
                labels={"src_ip": src_ip, "path": f"/product?id=1 UNION SELECT {index}--"},
                source_type="webhook",
            )
            for index in range(count)
        ]

    def close(self) -> None:
        self.store.close()


class StackTestCase(unittest.TestCase):
    """Base des tests : fournit ``self.stack`` dans un répertoire temporaire isolé."""

    #: Mode d'autonomie du tenant de test.
    tenant_mode: str = "supervised"
    #: Dry-run global.
    dry_run: bool = True
    #: Criticité d'actif du tenant.
    asset_criticality: float = 1.0
    #: Contenus YAML à écrire (surchargeables par les sous-classes).
    extra_rules: dict[str, str] = {}
    extra_policies: dict[str, str] = {}
    extra_playbooks: dict[str, str] = {}

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="thotsecure-test-"))
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        self.stack = build_stack(
            self._tmp,
            tenant_mode=self.tenant_mode,
            dry_run=self.dry_run,
            asset_criticality=self.asset_criticality,
            extra_rules=self.extra_rules,
            extra_policies=self.extra_policies,
            extra_playbooks=self.extra_playbooks,
        )
        self.addCleanup(self.stack.close)


def build_stack(
    root: Path,
    *,
    tenant_mode: str = "supervised",
    dry_run: bool = True,
    asset_criticality: float = 1.0,
    tenant_id: str = "acme",
    autonomy_allowlist: list[str] | None = None,
    protected_targets: list[str] | None = None,
    max_actions_per_hour: int = 20,
    cooldown_seconds: int = 300,
    env: str = "dev",
    extra_rules: dict[str, str] | None = None,
    extra_policies: dict[str, str] | None = None,
    extra_playbooks: dict[str, str] | None = None,
    connectors_dry_run: bool | None = None,
    targets_yaml: str | None = None,
    http_probe_delay_seconds: float = 0.0,
) -> Stack:
    """Construit une pile complète dans ``root`` (règles, politiques et playbooks sur disque)."""
    root = Path(root)
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "rules").mkdir(parents=True, exist_ok=True)
    (root / "policies").mkdir(parents=True, exist_ok=True)
    (root / "playbooks").mkdir(parents=True, exist_ok=True)
    (root / "config").mkdir(parents=True, exist_ok=True)

    rules = {
        "web-sqli.yaml": RULE_SQLI,
        "web-headers.yaml": RULE_MISSING_HSTS,
        "dependency.yaml": RULE_DEPENDENCY,
        "config-ssh.yaml": RULE_SSH_WEAK,
        "sigma-sample.yaml": RULE_SIGMA,
        **(extra_rules or {}),
    }
    policies = {
        "auto-block-high-web.yaml": POLICY_AUTO_BLOCK,
        "approval-supply-chain.yaml": POLICY_APPROVAL_SUPPLY_CHAIN,
        "notify-only-hardening.yaml": POLICY_NOTIFY_HARDENING,
        **(extra_policies or {}),
    }
    playbooks = {
        "block-source-ip.yaml": PLAYBOOK_BLOCK_IP,
        "unblock-source-ip.yaml": PLAYBOOK_UNBLOCK_IP,
        "patch-dependency.yaml": PLAYBOOK_PATCH_DEPENDENCY,
        "harden-endpoint.yaml": PLAYBOOK_HARDEN_ENDPOINT,
        "revoke-session.yaml": PLAYBOOK_REVOKE_SESSION,
        **(extra_playbooks or {}),
    }
    for filename, content in rules.items():
        (root / "rules" / filename).write_text(textwrap.dedent(content), encoding="utf-8")
    for filename, content in policies.items():
        (root / "policies" / filename).write_text(textwrap.dedent(content), encoding="utf-8")
    for filename, content in playbooks.items():
        (root / "playbooks" / filename).write_text(textwrap.dedent(content), encoding="utf-8")
    (root / "config" / "targets.yaml").write_text(
        targets_yaml or textwrap.dedent(TARGETS_YAML), encoding="utf-8"
    )
    (root / "config" / "connectors.yaml").write_text(
        textwrap.dedent(CONNECTORS_YAML), encoding="utf-8"
    )

    # Sources surveillées par les collecteurs (journaux, manifestes, configurations).
    (root / "logs").mkdir(parents=True, exist_ok=True)
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "logs" / "access.log").write_text(ACCESS_LOG, encoding="utf-8")
    (root / "app" / "requirements.txt").write_text(REQUIREMENTS_TXT, encoding="utf-8")
    (root / "etc" / "sshd_config").write_text(SSHD_CONFIG, encoding="utf-8")
    (root / "etc" / "nginx.conf").write_text(NGINX_CONF, encoding="utf-8")

    settings = Settings(
        root_dir=str(root),
        env=env,  # type: ignore[arg-type]
        db_url="sqlite:///./data/test.db",
        rules_dir="./rules",
        policies_dir="./policies",
        playbooks_dir="./playbooks",
        targets_file="./config/targets.yaml",
        connectors_file="./config/connectors.yaml",
        data_dir="./data",
        dry_run=dry_run,
        autonomy=tenant_mode,  # type: ignore[arg-type]
        secret_key="test-secret-key-not-for-production-use-only-0123456789",
        bootstrap_api_key="thot_BOOTSTRAP_changemebeforefirstuse",
        bus="memory",
        log_level="WARNING",
        log_format="console",
        http_probe_delay_seconds=http_probe_delay_seconds,
    )
    settings.ensure_directories()

    store = Store(settings.db_path)
    store.init_schema()
    audit = AuditChain(store)

    tenant = Tenant(
        tenant_id=tenant_id,
        name=f"Tenant {tenant_id}",
        mode=tenant_mode,  # type: ignore[arg-type]
        dry_run=dry_run,
        autonomy_allowlist=autonomy_allowlist or [],
        protected_targets=protected_targets or ["10.0.0.1", "10.0.0.0/24"],
        max_actions_per_hour=max_actions_per_hour,
        cooldown_seconds=cooldown_seconds,
        asset_criticality=asset_criticality,
    )
    store.upsert_tenant(tenant)

    rules_loaded, rule_diagnostics = load_rules_from_dir(settings.rules_path)
    playbooks_loaded, playbook_diagnostics = load_playbooks_from_dir(settings.playbooks_path)
    connectors = ConnectorRegistry.from_file(
        settings.connectors_path,
        dry_run=dry_run if connectors_dry_run is None else connectors_dry_run,
        root_dir=settings.root_path,
    )
    registry = TargetRegistry.from_file(settings.targets_path)
    policies_loaded, policy_diagnostics = load_policies_from_dir(
        settings.policies_path, known_playbooks=set(playbooks_loaded)
    )

    detection = DetectionEngine(rules_loaded)
    decision = DecisionEngine(store, policies_loaded, settings=settings, registry=registry)
    executor = PlaybookExecutor(connectors, dry_run=dry_run)
    actions = ActionEngine(
        store,
        audit,
        playbooks_loaded,
        executor,
        settings=settings,
        registry=registry,
        connectors=connectors,
    )
    keys = ApiKeyService(store, settings, audit)
    pipeline = Pipeline(store, audit, detection, decision, actions, settings=settings, bus=None)
    collector_runner = CollectorRunner(
        default_registry(), pipeline, store, audit, registry, settings=settings
    )

    stack = Stack(
        root=root,
        settings=settings,
        store=store,
        audit=audit,
        detection=detection,
        decision=decision,
        actions=actions,
        pipeline=pipeline,
        keys=keys,
        connectors=connectors,
        registry=registry,
        tenant=tenant,
        playbooks=playbooks_loaded,
        collectors=collector_runner,
    )
    stack.rule_diagnostics = rule_diagnostics  # type: ignore[attr-defined]
    stack.policy_diagnostics = policy_diagnostics  # type: ignore[attr-defined]
    stack.playbook_diagnostics = playbook_diagnostics  # type: ignore[attr-defined]
    return stack


__all__ = [
    "CONNECTORS_YAML",
    "PLAYBOOK_BLOCK_IP",
    "POLICY_AUTO_BLOCK",
    "RULE_SQLI",
    "TARGETS_YAML",
    "Stack",
    "StackTestCase",
    "build_stack",
]
