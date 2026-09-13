"""CLI Thot Secure (contrat §8).

La CLI est la surface « professionnelle » : scriptable, prévisible, sortie exploitable en CI.
Trois principes :

* **codes de sortie stables** — ``0`` succès, ``1`` erreur, ``2`` erreur d'usage, ``3``
  vérification négative (audit corrompu, règle invalide). Un pipeline CI doit pouvoir
  distinguer « l'outil a échoué » de « la vérification a échoué » ;
* **``--json`` partout** — pour être consommé par un script, un job, ou un autre outil ;
* **aucune action implicite** — la CLI n'exécute jamais une contre-mesure sans commande
  explicite, et affiche systématiquement l'état de simulation et d'autonomie.

Aucune capacité offensive n'est exposée : ``probe`` audite **vos** actifs déclarés, rien
d'autre.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

from . import (
    FUNDING_ADDRESSES,
    FUNDING_ANTISCAM,
    FUNDING_DISCLAIMER,
    FUNDING_NETWORKS,
    __license__,
    __version__,
)
from .core.config import Settings, get_settings, set_settings
from .core.errors import ThotSecureError, NotFoundError, ValidationError
from .core.logging_setup import get_logger
from .core.models import Event, EventSource, Finding, Tenant
from .core.util import iso_z
from .reports import render as render_report
from .scoring.risk import risk_band
from .service import Service, build_service
from .storage import store_location

log = get_logger("cli")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NEGATIVE = 3

#: Largeur d'affichage des tableaux texte.
WIDTH = 100

#: Symboles Unicode et leur repli ASCII. Un terminal Windows en page de code cp1252 ne peut
#: PAS encoder « ─ », « ✔ » ou « ⚠ » : sans repli, `thotsecure doctor` — la toute première
#: commande recommandée — se terminerait par une trace UnicodeEncodeError. On ne veut jamais
#: qu'un problème cosmétique empêche un diagnostic de sécurité de s'afficher.
SYMBOLS: dict[str, tuple[str, str]] = {
    "rule": ("─", "-"),
    "bullet": ("•", "*"),
    "ok": ("✔", "OK"),
    "warn": ("⚠", "!"),
    "error": ("✖", "x"),
    "arrow": ("→", "->"),
    "ellipsis": ("…", "..."),
}


def configure_output_encoding() -> None:
    """Force UTF-8 sur les flux standard, quand c'est possible.

    Sur un terminal moderne (Windows Terminal, PowerShell 7), cela suffit à afficher
    correctement les tableaux. Sur une console ancienne, l'écriture réussit malgré tout (les
    glyphes peuvent apparaître approximatifs) : c'est toujours préférable à un plantage.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(Exception):
            reconfigure(encoding="utf-8", errors="replace")


def _supports(stream: Any, sample: str) -> bool:
    """Vrai si le flux peut encoder l'échantillon donné."""
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        # Flux en mémoire (tests, redirection) : l'Unicode passe toujours.
        return True
    try:
        sample.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


# --------------------------------------------------------------------------------------
# Sortie
# --------------------------------------------------------------------------------------


class Output:
    """Sortie unifiée : texte lisible ou JSON, jamais les deux."""

    def __init__(self, *, as_json: bool = False, quiet: bool = False, color: bool | None = None) -> None:
        self.as_json = as_json
        self.quiet = quiet
        self.color = sys.stdout.isatty() if color is None else color
        self.unicode_ok = _supports(sys.stdout, "─✔⚠✖→…")

    # -- symboles ----------------------------------------------------------------------

    def sym(self, kind: str) -> str:
        """Symbole adapté aux capacités du terminal (repli ASCII si nécessaire)."""
        unicode_form, ascii_form = SYMBOLS.get(kind, ("?", "?"))
        return unicode_form if self.unicode_ok else ascii_form

    # -- sortie ------------------------------------------------------------------------

    def emit(self, payload: Any, *, text: str | None = None) -> None:
        if self.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            return
        if text is not None:
            if not self.quiet:
                print(text)
            return
        if isinstance(payload, str):
            if not self.quiet:
                print(payload)
        elif not self.quiet:
            print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))

    def title(self, text: str) -> None:
        if self.quiet or self.as_json:
            return
        print()
        print(text)
        print(self.sym("rule") * min(len(text), WIDTH))

    def success(self, text: str) -> None:
        if not self.quiet and not self.as_json:
            print(f"{self.sym('ok')} {text}")

    def warn(self, text: str) -> None:
        print(f"{self.sym('warn')} {text}", file=sys.stderr)

    def error(self, text: str) -> None:
        print(f"{self.sym('error')} {text}", file=sys.stderr)

    def table(self, rows: list[list[str]], headers: list[str]) -> None:
        if self.quiet or self.as_json:
            return
        if not rows:
            print("  (aucun résultat)")
            return
        widths = [
            min(max(len(str(header)), *(len(str(row[index])) for row in rows)), 48)
            for index, header in enumerate(headers)
        ]
        header_line = "  ".join(str(header).ljust(widths[i]) for i, header in enumerate(headers))
        print(header_line)
        print("  ".join(self.sym("rule") * widths[i] for i in range(len(headers))))
        for row in rows:
            cells = []
            for index, cell in enumerate(row):
                text = str(cell)
                if len(text) > widths[index]:
                    text = text[: widths[index] - 1] + self.sym("ellipsis")
                cells.append(text.ljust(widths[index]))
            print("  ".join(cells))


def safety_banner(service: Service, out: Output) -> None:
    """Rappelle l'état de sûreté : indispensable avant toute commande d'action."""
    if out.quiet or out.as_json:
        return
    if service.settings.dry_run:
        print(
            "mode simulation actif (THOT_DRY_RUN=true) : aucune action n'aura d'effet réel",
            file=sys.stderr,
        )
    for warning in service.settings.safety_warnings():
        print(f"{out.sym('warn')} {warning}", file=sys.stderr)


# --------------------------------------------------------------------------------------
# Parseur
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thotsecure",
        description=(
            "Thot Secure — SOAR/CSPM strictement défensif : détection, décision "
            "policy-as-code, contre-mesures réversibles et audit chaîné."
        ),
        epilog=(
            "Codes de sortie : 0 succès · 1 erreur · 2 usage · 3 vérification négative "
            "(audit corrompu, validation échouée)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"Thot Secure {__version__} ({__license__})")
    parser.add_argument("--json", action="store_true", help="sortie JSON (pour l'automatisation)")
    parser.add_argument("--quiet", "-q", action="store_true", help="sortie minimale")
    parser.add_argument("--no-color", action="store_true", help="désactiver la couleur")
    parser.add_argument(
        "--root",
        default=None,
        help="racine du projet (règles, politiques, base) — par défaut le répertoire courant",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMANDE")

    # -- serve -------------------------------------------------------------------------
    serve = sub.add_parser("serve", help="démarrer le service (API + console)")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true", help="rechargement automatique (développement)")
    serve.add_argument("--log-level", default=None)

    # -- init-db / doctor --------------------------------------------------------------
    sub.add_parser("init-db", help="initialiser la base de données")
    sub.add_parser("doctor", help="auto-diagnostic de l'installation et des défauts de sûreté")
    sub.add_parser("funding", help="afficher les adresses de dons officielles")

    # -- tenants -----------------------------------------------------------------------
    tenant = sub.add_parser("tenant", help="gérer les tenants")
    tenant_sub = tenant.add_subparsers(dest="tenant_command", metavar="SOUS-COMMANDE")
    tenant_create = tenant_sub.add_parser("create", help="créer ou mettre à jour un tenant")
    tenant_create.add_argument("--id", required=True, dest="tenant_id")
    tenant_create.add_argument("--name", default="")
    tenant_create.add_argument(
        "--mode", choices=["manual", "supervised", "auto"], default="supervised"
    )
    tenant_create.add_argument(
        "--no-dry-run",
        action="store_true",
        help="désactiver la simulation pour ce tenant (déconseillé avant validation)",
    )
    tenant_create.add_argument(
        "--allowlist", nargs="*", default=[], help="plages CIDR où l'automatisation est permise"
    )
    tenant_create.add_argument(
        "--protected", nargs="*", default=[], help="plages ou hôtes JAMAIS modifiés automatiquement"
    )
    tenant_create.add_argument("--max-actions-per-hour", type=int, default=20)
    tenant_create.add_argument("--asset-criticality", type=float, default=1.0)
    tenant_sub.add_parser("list", help="lister les tenants")

    # -- keys --------------------------------------------------------------------------
    key = sub.add_parser("key", help="gérer les clés API")
    key_sub = key.add_subparsers(dest="key_command", metavar="SOUS-COMMANDE")
    key_create = key_sub.add_parser("create", help="créer une clé API")
    key_create.add_argument("--tenant", required=True)
    key_create.add_argument("--role", choices=["viewer", "analyst", "responder", "admin"], default="viewer")
    key_create.add_argument("--label", default="")
    key_sub.add_parser("list", help="lister les clés (sans secret)").add_argument("--tenant", required=True)
    key_revoke = key_sub.add_parser("revoke", help="révoquer une clé")
    key_revoke.add_argument("--key-id", required=True)

    # -- rules / policies / playbooks --------------------------------------------------
    rules = sub.add_parser("rules", help="bibliothèque de détection")
    rules_sub = rules.add_subparsers(dest="rules_command", metavar="SOUS-COMMANDE")
    rules_sub.add_parser("list", help="lister les règles chargées")
    rules_validate = rules_sub.add_parser("validate", help="valider les règles d'un répertoire")
    rules_validate.add_argument("--path", default=None)
    rules_validate.add_argument("--file", default=None, help="valider un fichier unique")
    rules_show = rules_sub.add_parser("show", help="afficher la source YAML d'une règle")
    rules_show.add_argument("rule_id")

    policies = sub.add_parser("policies", help="politiques de décision")
    policies_sub = policies.add_subparsers(dest="policies_command", metavar="SOUS-COMMANDE")
    policies_sub.add_parser("list", help="lister les politiques (ordre d'évaluation)")
    policies_validate = policies_sub.add_parser("validate", help="valider les politiques")
    policies_validate.add_argument("--path", default=None)

    playbooks = sub.add_parser("playbooks", help="playbooks d'action")
    playbooks_sub = playbooks.add_subparsers(dest="playbooks_command", metavar="SOUS-COMMANDE")
    playbooks_sub.add_parser("list", help="lister les playbooks et leurs paramètres")

    # -- ingest ------------------------------------------------------------------------
    ingest = sub.add_parser("ingest", help="ingérer des événements (JSONL)")
    ingest.add_argument("--tenant", required=True)
    ingest.add_argument("--file", default=None, help="fichier JSONL (sinon entrée standard)")
    ingest.add_argument("--source-type", default="webhook")

    # -- findings ----------------------------------------------------------------------
    findings = sub.add_parser("findings", help="consulter et qualifier les findings")
    findings_sub = findings.add_subparsers(dest="findings_command", metavar="SOUS-COMMANDE")
    findings_list = findings_sub.add_parser("list", help="lister les findings")
    findings_list.add_argument("--tenant", required=True)
    findings_list.add_argument("--severity", action="append", default=None)
    findings_list.add_argument("--status", action="append", default=None)
    findings_list.add_argument("--min-risk", type=float, default=None)
    findings_list.add_argument("--limit", type=int, default=50)
    findings_show = findings_sub.add_parser("show", help="afficher un finding")
    findings_show.add_argument("finding_id")
    findings_show.add_argument("--tenant", required=True)
    findings_ack = findings_sub.add_parser("ack", help="acquitter un finding")
    findings_ack.add_argument("finding_id")
    findings_ack.add_argument("--tenant", required=True)
    findings_ack.add_argument("--comment", default="")
    findings_close = findings_sub.add_parser("close", help="clôturer un finding")
    findings_close.add_argument("finding_id")
    findings_close.add_argument("--tenant", required=True)
    findings_close.add_argument(
        "--resolution",
        choices=["true_positive", "false_positive", "mitigated", "duplicate", "benign"],
        default="true_positive",
    )
    findings_close.add_argument("--comment", default="")

    # -- actions -----------------------------------------------------------------------
    actions = sub.add_parser("actions", help="planifier, approuver, exécuter, annuler")
    actions_sub = actions.add_subparsers(dest="actions_command", metavar="SOUS-COMMANDE")
    actions_list = actions_sub.add_parser("list", help="lister les actions")
    actions_list.add_argument("--tenant", required=True)
    actions_list.add_argument("--status", action="append", default=None)
    actions_plan = actions_sub.add_parser("plan", help="planifier une action (sans effet)")
    actions_plan.add_argument("--tenant", required=True)
    actions_plan.add_argument("--playbook", required=True)
    actions_plan.add_argument("--finding", default=None)
    actions_plan.add_argument("--target", default=None, help="IP, hôte, chemin ou chemin de champ")
    actions_plan.add_argument("--duration", type=int, default=None)
    actions_plan.add_argument("--param", action="append", default=[], metavar="CLÉ=VALEUR")
    actions_plan.add_argument(
        "--live",
        action="store_true",
        help="autoriser un effet réel si THOT_DRY_RUN=false (sinon simulation)",
    )
    for name, help_text in (
        ("approve", "approuver une action"),
        ("reject", "rejeter une action"),
        ("execute", "exécuter une action approuvée"),
        ("rollback", "annuler une action (rollback)"),
    ):
        node = actions_sub.add_parser(name, help=help_text)
        node.add_argument("action_id")
        node.add_argument("--tenant", required=True)
        node.add_argument("--by", default="cli", help="identité inscrite dans l'audit")
        if name in {"approve", "reject", "rollback"}:
            node.add_argument("--comment", default="")

    # -- audit -------------------------------------------------------------------------
    audit = sub.add_parser("audit", help="journal d'audit chaîné")
    audit_sub = audit.add_subparsers(dest="audit_command", metavar="SOUS-COMMANDE")
    audit_verify = audit_sub.add_parser("verify", help="vérifier l'intégrité de la chaîne")
    audit_verify.add_argument("--tenant", default=None)
    audit_tail = audit_sub.add_parser("tail", help="afficher les derniers enregistrements")
    audit_tail.add_argument("--tenant", required=True)
    audit_tail.add_argument("--limit", type=int, default=20)
    audit_export = audit_sub.add_parser("export", help="exporter pour un SIEM (cef/jsonl)")
    audit_export.add_argument("--tenant", required=True)
    audit_export.add_argument("--format", choices=["cef", "jsonl"], default="jsonl")
    audit_export.add_argument("--output", "-o", default=None)

    # -- report ------------------------------------------------------------------------
    report = sub.add_parser("report", help="générer un rapport de finding")
    report.add_argument("finding_id")
    report.add_argument("--tenant", required=True)
    report.add_argument("--format", choices=["md", "html", "json", "sarif", "cef"], default="md")
    report.add_argument("--output", "-o", default=None)

    # -- probe / collect ---------------------------------------------------------------
    probe = sub.add_parser("probe", help="audit défensif de VOS actifs déclarés")
    probe.add_argument("--tenant", required=True)
    probe.add_argument("--target", default=None, help="URL à auditer (doit être déclarée)")

    collect = sub.add_parser("collect", help="collecteurs")
    collect_sub = collect.add_subparsers(dest="collect_command", metavar="SOUS-COMMANDE")
    collect_sub.add_parser("list", help="état des collecteurs").add_argument("--tenant", required=True)
    collect_run = collect_sub.add_parser("run", help="exécuter un collecteur")
    collect_run.add_argument("collector")
    collect_run.add_argument("--tenant", required=True)
    collect_run.add_argument("--all", action="store_true", help="exécuter tous les collecteurs")

    # -- demo --------------------------------------------------------------------------
    demo = sub.add_parser("demo", help="créer un jeu de démonstration (findings + action)")
    demo.add_argument("--tenant", default="demo")
    demo.add_argument("--scenario", choices=["web-attack", "supply-chain", "hardening"], default="web-attack")

    return parser


# --------------------------------------------------------------------------------------
# Entrée principale
# --------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    configure_output_encoding()
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Output(as_json=args.json, quiet=args.quiet, color=not args.no_color)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    try:
        return _dispatch(args, out)
    except ThotSecureError as exc:
        out.error(f"{exc.code}: {exc.message}")
        if exc.details:
            print(json.dumps(exc.details, ensure_ascii=False, indent=2), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover - interaction utilisateur
        out.warn("interrompu par l'utilisateur")
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - sortie redirigée fermée
        return EXIT_OK


def _settings_from_args(args: argparse.Namespace) -> Settings:
    settings = get_settings(refresh=True)
    if getattr(args, "root", None):
        overrides = settings.model_dump()
        overrides["root_dir"] = args.root
        settings = Settings(**overrides)
    set_settings(settings)
    return settings


def _dispatch(args: argparse.Namespace, out: Output) -> int:
    command = args.command
    settings = _settings_from_args(args)

    if command == "serve":
        return _cmd_serve(args, settings, out)
    if command == "funding":
        return _cmd_funding(out)

    # Toutes les autres commandes ont besoin du service applicatif.
    service = build_service(settings)

    try:
        handler = {
            "init-db": _cmd_init_db,
            "doctor": _cmd_doctor,
            "tenant": _cmd_tenant,
            "key": _cmd_key,
            "rules": _cmd_rules,
            "policies": _cmd_policies,
            "playbooks": _cmd_playbooks,
            "ingest": _cmd_ingest,
            "findings": _cmd_findings,
            "actions": _cmd_actions,
            "audit": _cmd_audit,
            "report": _cmd_report,
            "probe": _cmd_probe,
            "collect": _cmd_collect,
            "demo": _cmd_demo,
        }.get(command)
        if handler is None:  # pragma: no cover - argparse empêche ce cas
            raise ValidationError(f"commande inconnue: {command}")
        return handler(args, service, out)
    finally:
        service.close()


# --------------------------------------------------------------------------------------
# Commandes
# --------------------------------------------------------------------------------------


def _cmd_serve(args: argparse.Namespace, settings: Settings, out: Output | None = None) -> int:
    import uvicorn

    out = out or Output()
    host = args.host or settings.host
    port = args.port or settings.port
    level = (args.log_level or settings.log_level).lower()
    print(f"Thot Secure {__version__} — API et console sur http://{host}:{port}/")
    print(f"documentation interactive : http://{host}:{port}/docs")
    if settings.dry_run:
        print("mode simulation actif : aucune contre-mesure n'aura d'effet réel")
    for warning in settings.safety_warnings():
        print(f"{out.sym('warn')} {warning}", file=sys.stderr)
    if not settings.tls_enabled:
        print(
            f"{out.sym('warn')} TLS non activé en direct : placez le service derrière un "
            "reverse-proxy HTTPS (les clés API circulent dans un en-tête)",
            file=sys.stderr,
        )
    uvicorn.run(
        "thotsecure.main:app" if args.reload else _app_factory(settings),
        host=host,
        port=port,
        reload=args.reload,
        log_level=level,
    )
    return EXIT_OK


def _app_factory(settings: Settings):  # pragma: no cover - utilisé par uvicorn
    from .main import create_app

    return create_app(settings)


def _cmd_funding(out: Output) -> int:
    payload = {
        "addresses": FUNDING_ADDRESSES,
        "networks": FUNDING_NETWORKS,
        "disclaimer": FUNDING_DISCLAIMER,
        "antiscam": FUNDING_ANTISCAM,
    }
    text = "\n".join(
        [
            "Soutenir Thot Secure — dons volontaires, aucune contrepartie attendue.",
            "",
            *(
                f"  {symbol:4s} ({FUNDING_NETWORKS[symbol]}) : {address}"
                for symbol, address in FUNDING_ADDRESSES.items()
            ),
            "",
            f"  {FUNDING_DISCLAIMER}",
            "",
            textwrap.fill(FUNDING_ANTISCAM, width=WIDTH, initial_indent="  ", subsequent_indent="  "),
            "",
            "  Source officielle : dépôt Git et site du projet. Page complète : /ui/support",
        ]
    )
    out.emit(payload, text=text)
    return EXIT_OK


def _cmd_init_db(args: argparse.Namespace, service: Service, out: Output) -> int:
    tenant = service.keys.bootstrap()
    payload = {
        "database": store_location(service.store),
        "initialized": True,
        "bootstrap_tenant": tenant.tenant_id if tenant else None,
        "bootstrap_key_hint": (
            "clé d'amorçage créée depuis THOT_BOOTSTRAP_API_KEY"
            if tenant
            else "base déjà initialisée : aucun tenant d'amorçage créé"
        ),
    }
    out.emit(payload, text=f"base initialisée : {store_location(service.store)}")
    if tenant and not out.as_json:
        out.warn(
            "la clé d'amorçage est publique : créez une clé dédiée puis révoquez-la "
            "(thotsecure key create --tenant <id> --role admin)"
        )
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace, service: Service, out: Output) -> int:
    """Auto-diagnostic : c'est la première commande à lancer après installation."""
    settings = service.settings
    checks: list[dict[str, Any]] = []
    critical_failures = 0

    def add(name: str, ok: bool, detail: str, *, critical: bool = False) -> None:
        nonlocal critical_failures
        checks.append({"check": name, "ok": ok, "detail": detail, "critical": critical})
        if not ok and critical:
            critical_failures += 1

    add("python", sys.version_info >= (3, 11), f"Python {sys.version.split()[0]} (≥ 3.11 requis)", critical=True)
    add("base de données", service.store.health(), store_location(service.store), critical=True)
    # Le contrôle « fichier présent » n'a de sens qu'en SQLite : sur PostgreSQL, la base est
    # distante et `settings.db_path` lève une erreur. On décrit donc ce que l'on sait vraiment.
    if service.store.backend_name == "sqlite":
        present = Path(str(store_location(service.store))).exists()
        add("schéma", present, "fichier de base présent" if present else "absent (lancez init-db)")
    else:
        add(
            "schéma",
            service.store.health(),
            f"base distante ({service.store.backend_name}) : schéma appliqué par init-db",
        )

    rules = len(service.rules)
    add("règles de détection", rules > 0, f"{rules} règle(s) chargée(s), {len(service.rule_diagnostics)} rejetée(s)", critical=rules == 0)
    add("politiques", len(service.policies) > 0, f"{len(service.policies)} politique(s), {len(service.policy_diagnostics)} rejetée(s)")
    add("playbooks", len(service.playbooks) > 0, f"{len(service.playbooks)} playbook(s), {len(service.playbook_diagnostics)} rejetée(s)")
    add("périmètre déclaré", bool(service.targets.tenants()), f"{len(service.targets.tenants())} tenant(s) déclaré(s) dans {settings.targets_path}")

    reversible = sum(1 for playbook in service.playbooks.values() if playbook.reversible)
    add(
        "réversibilité des playbooks",
        reversible == len(service.playbooks) or reversible > 0,
        f"{reversible}/{len(service.playbooks)} playbooks réversibles",
    )
    add(
        "cibles protégées",
        True,
        "configurables par tenant (protected_targets) : à renseigner pour votre infra critique",
    )

    verdict = service.audit.verify()
    add("intégrité de l'audit", verdict.valid, verdict.reason or f"{verdict.records} enregistrement(s)", critical=not verdict.valid)
    add("mode simulation", settings.dry_run, "actif (sûr par défaut)" if settings.dry_run else "DÉSACTIVÉ : les actions auront un effet réel")
    add("autonomie", True, f"globale : {settings.autonomy}")
    add(
        "connecteurs réels",
        not service.connectors.stats().get("simulated_only", True),
        "tous les connecteurs sont en simulation (aucun effet réel possible)",
    )
    add("clé de signature", not settings.secret_key_is_ephemeral, "THOT_SECRET_KEY définie" if not settings.secret_key_is_ephemeral else "éphémère : les sessions et clés API seront invalidées au redémarrage")
    add("clé d'amorçage", not settings.bootstrap_key_is_dev, "THOT_BOOTSTRAP_API_KEY personnalisée" if not settings.bootstrap_key_is_dev else "valeur de développement publique : à remplacer")
    add("bus d'événements", True, f"{settings.bus} (sqlite/nats recommandés en production)")
    add("TLS", settings.tls_enabled, "actif" if settings.tls_enabled else "désactivé en direct : utilisez un reverse-proxy HTTPS")

    payload = {
        "version": __version__,
        "environment": settings.env,
        "checks": checks,
        "critical_failures": critical_failures,
        "warnings": settings.safety_warnings(),
        "database": store_location(service.store),
        "root": str(settings.root_path),
    }
    if out.as_json:
        out.emit(payload)
    else:
        out.title(f"Thot Secure {__version__} — diagnostic")
        out.table(
            [
                [
                    out.sym("ok") if check["ok"] else (out.sym("error") if check["critical"] else out.sym("warn")),
                    check["check"],
                    check["detail"],
                ]
                for check in checks
            ],
            ["", "contrôle", "détail"],
        )
        if settings.safety_warnings():
            out.title("Avertissements")
            for warning in settings.safety_warnings():
                print(f"  {out.sym('warn')} {warning}")
        out.title("Prochaines étapes")
        print("  1. déclarer vos actifs dans config/targets.yaml")
        print("  2. créer un tenant : thotsecure tenant create --id <id> --name \"<nom>\"")
        print("  3. créer une clé :   thotsecure key create --tenant <id> --role responder")
        print("  4. observer :        thotsecure collect run config_audit --tenant <id>")
        print("  5. n'activer le mode réel QU'APRÈS avoir validé les décisions en simulation")
    return EXIT_NEGATIVE if critical_failures else EXIT_OK


def _cmd_tenant(args: argparse.Namespace, service: Service, out: Output) -> int:
    if args.tenant_command == "create":
        tenant = Tenant(
            tenant_id=args.tenant_id,
            name=args.name or args.tenant_id,
            mode=args.mode,
            dry_run=not args.no_dry_run and service.settings.dry_run,
            autonomy_allowlist=args.allowlist or [],
            protected_targets=args.protected or [],
            max_actions_per_hour=args.max_actions_per_hour,
            asset_criticality=args.asset_criticality,
        )
        stored = service.store.upsert_tenant(tenant)
        service.audit.record(
            tenant_id=stored.tenant_id,
            actor="cli",
            actor_role="admin",
            action="tenant.create",
            target={"type": "tenant", "id": stored.tenant_id},
            after=stored.model_dump(mode="json"),
            context={"channel": "cli"},
        )
        out.emit(stored.model_dump(mode="json"), text=f"tenant '{stored.tenant_id}' enregistré (mode {stored.mode}, dry-run {stored.dry_run})")
        if args.no_dry_run:
            out.warn(
                "dry-run désactivé pour ce tenant : les actions pourront avoir un effet réel. "
                "Vérifiez vos playbooks et vos connecteurs avant de passer en mode 'auto'."
            )
        return EXIT_OK

    tenants = service.store.list_tenants()
    payload = [
        {
            **tenant.model_dump(mode="json"),
            "keys": len(service.keys.list_keys(tenant.tenant_id)),
            "open_findings": service.store.count_findings(tenant.tenant_id)["by_status"].get("open", 0),
        }
        for tenant in tenants
    ]
    out.emit({"items": payload, "count": len(payload)})
    out.title(f"Tenants ({len(tenants)})")
    out.table(
        [
            [
                tenant["tenant_id"],
                tenant["name"],
                tenant["mode"],
                "oui" if tenant["dry_run"] else "NON",
                str(tenant["keys"]),
                str(tenant["open_findings"]),
            ]
            for tenant in payload
        ],
        ["id", "nom", "mode", "dry-run", "clés", "findings ouverts"],
    )
    return EXIT_OK


def _cmd_key(args: argparse.Namespace, service: Service, out: Output) -> int:
    if args.key_command == "create":
        info, api_key = service.keys.create(
            tenant_id=args.tenant, role=args.role, label=args.label, actor="cli", actor_role="admin"
        )
        payload = {**info.model_dump(mode="json"), "api_key": api_key}
        if out.as_json:
            out.emit(payload)
        else:
            out.title(f"Clé API créée pour '{info.tenant_id}' (rôle {info.role})")
            print(f"  identifiant : {info.key_id}")
            print(f"  clé         : {api_key}")
            out.warn("cette clé ne sera plus jamais affichée : conservez-la dans un coffre de secrets")
        return EXIT_OK

    if args.key_command == "list":
        keys = service.keys.list_keys(args.tenant)
        out.emit({"items": [key.model_dump(mode="json") for key in keys], "count": len(keys)})
        out.title(f"Clés de '{args.tenant}'")
        out.table(
            [
                [
                    key.key_id,
                    key.label,
                    key.role,
                    "active" if key.active else "révoquée",
                    iso_z(key.created_at)[:16],
                    iso_z(key.last_used_at)[:16] if key.last_used_at else "jamais",
                ]
                for key in keys
            ],
            ["identifiant", "libellé", "rôle", "état", "créée", "dernier usage"],
        )
        return EXIT_OK

    if args.key_command == "revoke":
        service.keys.revoke(key_id=args.key_id, actor="cli")
        out.emit({"revoked": args.key_id}, text=f"clé {args.key_id} révoquée")
        return EXIT_OK

    raise ValidationError("sous-commande 'key' manquante (create, list, revoke)")


def _cmd_rules(args: argparse.Namespace, service: Service, out: Output) -> int:
    if args.rules_command == "list":
        summaries = service.detection.summaries()
        out.emit(
            {
                "items": summaries,
                "count": len(summaries),
                "diagnostics": [item.model_dump() for item in service.rule_diagnostics],
            }
        )
        out.title(f"Règles de détection ({len(summaries)})")
        out.table(
            [
                [
                    rule["rule_id"],
                    rule["severity"],
                    rule["title"],
                    ",".join(rule["tags"][:3]),
                    rule["path"].split("\\")[-1].split("/")[-1] if rule["path"] else "",
                ]
                for rule in summaries
            ],
            ["id", "sévérité", "titre", "étiquettes", "fichier"],
        )
        return EXIT_OK

    if args.rules_command == "validate":
        from .detection.rule_loader import load_rule_text, load_rules_from_dir

        if args.file:
            text = Path(args.file).read_text(encoding="utf-8")
            rule = load_rule_text(text, path=args.file)
            out.emit(rule.summary(), text=f"✔ règle valide : {rule.id} ({rule.severity})")
            return EXIT_OK
        path = Path(args.path) if args.path else service.settings.rules_path
        rules, diagnostics = load_rules_from_dir(path)
        payload = {
            "path": str(path),
            "valid": len(rules),
            "rejected": len(diagnostics),
            "diagnostics": [item.model_dump() for item in diagnostics],
        }
        if out.as_json:
            out.emit(payload)
        else:
            out.title(f"Validation des règles ({path})")
            print(f"  {out.sym('ok')} {len(rules)} règle(s) valide(s)")
            for item in diagnostics:
                print(f"  {out.sym('error')} {item.path}: {item.error}")
        return EXIT_NEGATIVE if diagnostics else EXIT_OK

    if args.rules_command == "show":
        from .detection.rule_loader import dump_rule

        rule = service.detection.get_rule(args.rule_id)
        if rule is None:
            raise NotFoundError(f"règle introuvable: {args.rule_id}")
        out.emit(rule.summary(), text=dump_rule(rule))
        return EXIT_OK

    raise ValidationError("sous-commande 'rules' manquante (list, validate, show)")


def _cmd_policies(args: argparse.Namespace, service: Service, out: Output) -> int:
    if args.policies_command == "validate":
        from .decision.policy_loader import load_policies_from_dir

        path = Path(args.path) if args.path else service.settings.policies_path
        policies, diagnostics = load_policies_from_dir(path, known_playbooks=set(service.playbooks))
        payload = {
            "path": str(path),
            "valid": len(policies),
            "rejected": len(diagnostics),
            "diagnostics": [item.model_dump() for item in diagnostics],
        }
        if out.as_json:
            out.emit(payload)
        else:
            out.title(f"Validation des politiques ({path})")
            print(f"  {out.sym('ok')} {len(policies)} politique(s) valide(s)")
            for item in diagnostics:
                print(f"  {out.sym('error')} {item.path}: {item.error}")
        return EXIT_NEGATIVE if diagnostics else EXIT_OK

    summaries = [policy.summary() for policy in service.decision.policies]
    out.emit({"items": summaries, "count": len(summaries)})
    out.title(f"Politiques de décision ({len(summaries)}) — par priorité")
    out.table(
        [
            [
                str(policy["priority"]),
                policy["policy_id"],
                policy["decision"],
                policy["playbook"] or "—",
                "oui" if policy["enabled"] else "non",
            ]
            for policy in summaries
        ],
        ["priorité", "politique", "décision", "playbook", "active"],
    )
    return EXIT_OK


def _cmd_playbooks(args: argparse.Namespace, service: Service, out: Output) -> int:
    summaries = [playbook.summary() for _, playbook in sorted(service.playbooks.items())]
    out.emit(
        {
            "items": summaries,
            "count": len(summaries),
            "connectors": {
                name: service.connectors.get(name).driver
                for name in sorted(service.connectors.configuration)
            },
        }
    )
    out.title(f"Playbooks ({len(summaries)})")
    out.table(
        [
            [
                playbook["name"],
                "oui" if playbook["reversible"] else "NON",
                ",".join(playbook["connectors"]),
                ",".join(playbook["params_schema"]),
                str(playbook["steps"]),
            ]
            for playbook in summaries
        ],
        ["playbook", "réversible", "connecteurs", "paramètres", "étapes"],
    )
    if not out.as_json:
        print()
        print("  Connecteurs configurés :")
        for name in sorted(service.connectors.configuration):
            connector = service.connectors.get(name)
            marker = "simulation" if connector.driver == "simulation" else connector.driver
            print(f"    {name:14s} → {marker}")
    return EXIT_OK


def _cmd_ingest(args: argparse.Namespace, service: Service, out: Output) -> int:
    lines: list[str] = []
    if args.file:
        lines = Path(args.file).read_text(encoding="utf-8").splitlines()
    else:
        lines = [line for line in sys.stdin.read().splitlines() if line.strip()]

    events: list[Event] = []
    errors: list[str] = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            document = json.loads(line)
        except ValueError as exc:
            errors.append(f"ligne {index}: JSON invalide ({exc})")
            continue
        document.setdefault("tenant_id", args.tenant)
        document["tenant_id"] = args.tenant  # le tenant est imposé par la commande
        document.setdefault("source", {"type": args.source_type})
        try:
            events.append(Event(**document))
        except Exception as exc:  # noqa: BLE001 - on collecte les erreurs ligne par ligne
            errors.append(f"ligne {index}: {exc}")

    if not events and errors:
        raise ValidationError("aucun événement valide", details={"errors": errors[:20]})

    outcome = service.pipeline.ingest(events, actor="cli", actor_role="analyst")
    payload = {
        **outcome.result.model_dump(mode="json"),
        "errors": errors[:50],
        "findings_detail": [finding.model_dump(mode="json") for finding in outcome.findings],
        "actions": [action.model_dump(mode="json") for action in outcome.actions],
    }
    if out.as_json:
        out.emit(payload)
    else:
        out.title("Ingestion")
        print(f"  acceptés : {outcome.result.accepted}   refusés : {outcome.result.rejected}")
        print(f"  findings : {len(outcome.findings)}   actions : {len(outcome.actions)}")
        for finding in outcome.findings:
            print(
                f"    [{finding.severity}] {finding.risk_score:.1f} "
                f"{finding.rule_id} — {finding.title}"
            )
        for error in errors[:10]:
            print(f"  {out.sym('warn')} {error}")
    return EXIT_OK


def _cmd_findings(args: argparse.Namespace, service: Service, out: Output) -> int:
    if args.findings_command == "list":
        findings, _ = service.store.list_findings(
            args.tenant,
            severity=args.severity,
            status=args.status,
            min_risk=args.min_risk,
            limit=args.limit,
        )
        out.emit({"items": [finding.model_dump(mode="json") for finding in findings], "count": len(findings)})
        out.title(f"Findings de '{args.tenant}' ({len(findings)})")
        out.table(
            [
                [
                    finding.finding_id[:14],
                    finding.severity,
                    f"{finding.risk_score:.1f}",
                    finding.status,
                    str(finding.count),
                    finding.rule_id,
                    finding.title[:44],
                ]
                for finding in findings
            ],
            ["finding", "sévérité", "risque", "statut", "occ.", "règle", "titre"],
        )
        return EXIT_OK

    if args.findings_command == "show":
        finding = service.store.get_finding(args.tenant, args.finding_id)
        if finding is None:
            raise NotFoundError(f"finding introuvable: {args.finding_id}")
        actions = service.store.actions_for_finding(args.tenant, args.finding_id)
        tenant = service.store.require_tenant(args.tenant)
        decision = service.decision.decide_for_finding(finding, tenant, environment=service.settings.env)
        payload = {
            **finding.model_dump(mode="json"),
            "actions": [action.model_dump(mode="json") for action in actions],
            "decision": decision.model_dump(mode="json"),
        }
        if out.as_json:
            out.emit(payload)
        else:
            out.title(f"{finding.title}")
            print(f"  identifiant : {finding.finding_id}")
            print(f"  règle       : {finding.rule_id} — {finding.rule_name}")
            print(f"  sévérité    : {finding.severity}   score : {finding.risk_score:.1f}/100 ({risk_band(finding.risk_score)})")
            print(f"  statut      : {finding.status}   occurrences : {finding.count}")
            print(f"  période     : {iso_z(finding.first_seen)} → {iso_z(finding.last_seen)}")
            print()
            print(f"  remédiation : {finding.remediation}")
            print()
            print(f"  décision    : {decision.decision} (politique {decision.policy_id or 'aucune'})")
            if decision.guards:
                print(f"  garde-fous  : {', '.join(decision.guards)}")
            if actions:
                print()
                print("  actions :")
                for action in actions:
                    print(f"    {action.action_id} {action.playbook} → {action.status} (dry-run {action.dry_run})")
        return EXIT_OK

    if args.findings_command in {"ack", "close"}:
        finding = service.store.get_finding(args.tenant, args.finding_id)
        if finding is None:
            raise NotFoundError(f"finding introuvable: {args.finding_id}")
        status = "acked" if args.findings_command == "ack" else "closed"
        updated = service.store.update_finding(
            args.tenant,
            args.finding_id,
            status=status,
            comment=args.comment or None,
            resolution=getattr(args, "resolution", None),
        )
        service.audit.record_state_change(
            tenant_id=args.tenant,
            actor="cli",
            actor_role="analyst",
            action=f"finding.{'ack' if status == 'acked' else 'close'}",
            target={"type": "finding", "id": args.finding_id},
            before={"status": finding.status},
            after={"status": updated.status, "resolution": updated.resolution},
            context={"comment": args.comment[:300], "channel": "cli"},
        )
        out.emit(updated.model_dump(mode="json"), text=f"finding {args.finding_id} → {updated.status}")
        return EXIT_OK

    raise ValidationError("sous-commande 'findings' manquante (list, show, ack, close)")


def _cmd_actions(args: argparse.Namespace, service: Service, out: Output) -> int:
    tenant = service.store.require_tenant(args.tenant)
    command = args.actions_command

    if command == "list":
        actions, _ = service.actions.list(args.tenant, status=args.status, limit=100)
        out.emit({"items": [action.model_dump(mode="json") for action in actions], "count": len(actions)})
        out.title(f"Actions de '{args.tenant}' ({len(actions)})")
        out.table(
            [
                [
                    action.action_id[:14],
                    action.playbook,
                    str(action.target),
                    action.status,
                    action.mode,
                    "oui" if action.dry_run else "NON",
                    "dispo" if action.rollback.available else "—",
                ]
                for action in actions
            ],
            ["action", "playbook", "cible", "statut", "mode", "simulation", "rollback"],
        )
        return EXIT_OK

    if command == "plan":
        params: dict[str, Any] = {}
        for item in args.param:
            if "=" not in item:
                raise ValidationError(f"paramètre invalide (attendu CLÉ=VALEUR) : {item}")
            key, _, value = item.partition("=")
            params[key.strip()] = value.strip()
        if args.target:
            params.setdefault("target", args.target)
        if args.duration:
            params["duration_seconds"] = args.duration

        finding: Finding | None = None
        if args.finding:
            finding = service.store.get_finding(args.tenant, args.finding)
            if finding is None:
                raise NotFoundError(f"finding introuvable: {args.finding}")

        safety_banner(service, out)
        action = service.actions.plan(
            tenant=tenant,
            playbook_name=args.playbook,
            actor=args.by if hasattr(args, "by") else "cli",
            actor_role="responder",
            finding=finding,
            params=params,
            mode="manual",
            dry_run=None if args.live else True,
            reason="planification via CLI",
        )
        out.emit(action.model_dump(mode="json"))
        out.title("Action planifiée")
        print(f"  identifiant : {action.action_id}")
        print(f"  playbook    : {action.playbook}")
        print(f"  cible       : {action.target}")
        print(f"  paramètres  : {json.dumps(action.params, ensure_ascii=False)}")
        print(f"  simulation  : {'oui' if action.dry_run else 'NON (effet réel possible après approbation)'}")
        print(f"  rév. dispo. : {'oui' if action.rollback.available else 'non'}")
        print()
        print("  Aucun effet n'a été appliqué. Étapes suivantes :")
        print(f"    thotsecure actions approve {action.action_id} --tenant {args.tenant}")
        print(f"    thotsecure actions execute {action.action_id} --tenant {args.tenant}")
        return EXIT_OK

    if command in {"approve", "reject", "execute", "rollback"}:
        safety_banner(service, out)
        actor = args.by
        if command == "approve":
            action = service.actions.approve(
                tenant=tenant, action_id=args.action_id, actor=actor, actor_role="responder",
                comment=args.comment,
            )
        elif command == "reject":
            action = service.actions.reject(
                tenant=tenant, action_id=args.action_id, actor=actor, actor_role="responder",
                reason=args.comment,
            )
        elif command == "execute":
            action = service.actions.execute(
                tenant=tenant, action_id=args.action_id, actor=actor, actor_role="responder"
            )
        else:
            action = service.actions.rollback(
                tenant=tenant, action_id=args.action_id, actor=actor, actor_role="responder",
                reason=args.comment or "annulation via CLI",
            )
        out.emit(action.model_dump(mode="json"))
        if not out.as_json:
            out.title(f"Action {args.action_id} → {action.status}")
            print(f"  playbook : {action.playbook}   cible : {action.target}")
            if action.result:
                steps = action.result.get("steps") or []
                print(f"  étapes   : {len(steps)}")
                for step in steps:
                    marker = "simulé" if step.get("simulated") else ("ok" if step.get("ok") else "ÉCHEC")
                    print(f"    [{marker}] {step.get('connector')}.{step.get('call')} — {step.get('detail') or step.get('error')}")
            if action.status == "succeeded" and action.rollback.available:
                print()
                print(f"  annulation possible : thotsecure actions rollback {action.action_id} --tenant {args.tenant}")
            if action.status == "failed":
                out.warn(f"échec : {action.reason}")
        return EXIT_NEGATIVE if action.status == "failed" else EXIT_OK

    raise ValidationError("sous-commande 'actions' manquante (list, plan, approve, reject, execute, rollback)")


def _cmd_audit(args: argparse.Namespace, service: Service, out: Output) -> int:
    if args.audit_command == "verify":
        verdict = service.audit.verify(tenant_id=args.tenant)
        payload = {**verdict.model_dump(mode="json"), "scope": "chaîne globale"}
        if out.as_json:
            out.emit(payload)
        elif verdict.valid:
            out.success(f"chaîne d'audit intègre ({verdict.records} enregistrement(s))")
        else:
            out.error(f"CHAÎNE D'AUDIT ROMPUE au seq {verdict.broken_at} : {verdict.reason}")
            out.error("incident de sécurité : la piste d'audit a été modifiée ou tronquée")
        return EXIT_OK if verdict.valid else EXIT_NEGATIVE

    if args.audit_command == "tail":
        records, _ = service.store.list_audit(args.tenant, limit=args.limit)
        out.emit({"items": [record.model_dump(mode="json") for record in records], "count": len(records)})
        out.title(f"Journal d'audit de '{args.tenant}' ({len(records)} derniers)")
        out.table(
            [
                [
                    str(record.seq),
                    iso_z(record.ts)[:19],
                    record.actor,
                    record.action,
                    f"{record.target.get('type', '')}:{record.target.get('id', '')}"[:30],
                ]
                for record in records
            ],
            ["seq", "horodatage", "acteur", "action", "cible"],
        )
        return EXIT_OK

    if args.audit_command == "export":
        lines = list(service.audit.export(args.tenant, fmt=args.format, limit=10000))
        content = "\n".join(lines) + ("\n" if lines else "")
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            out.emit({"output": args.output, "records": len(lines), "format": args.format},
                     text=f"{len(lines)} enregistrement(s) exportés vers {args.output}")
        else:
            out.emit({"records": len(lines), "format": args.format}, text=content)
        service.audit.record(
            tenant_id=args.tenant,
            actor="cli",
            actor_role="analyst",
            action="audit.export",
            target={"type": "audit", "id": args.output or "stdout"},
            after={"format": args.format, "records": len(lines)},
        )
        return EXIT_OK

    raise ValidationError("sous-commande 'audit' manquante (verify, tail, export)")


def _cmd_report(args: argparse.Namespace, service: Service, out: Output) -> int:
    finding = service.store.get_finding(args.tenant, args.finding_id)
    if finding is None:
        raise NotFoundError(f"finding introuvable: {args.finding_id}")
    tenant = service.store.require_tenant(args.tenant)
    actions = service.store.actions_for_finding(args.tenant, args.finding_id)
    audit = [
        record
        for record in service.audit.tail(args.tenant, limit=300)
        if record.target.get("id") in {args.finding_id, *[action.action_id for action in actions]}
    ][:30]
    content, _media_type = render_report(finding, args.format, tenant=tenant, actions=actions, audit=audit)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
        out.emit({"output": args.output, "format": args.format, "bytes": len(content)},
                 text=f"rapport {args.format} écrit dans {args.output}")
    else:
        out.emit({"finding_id": args.finding_id, "format": args.format}, text=content)
    return EXIT_OK


def _cmd_probe(args: argparse.Namespace, service: Service, out: Output) -> int:
    """Audit de surface **de ses propres actifs déclarés**."""
    scope = service.targets.for_tenant(args.tenant)
    verdict = service.targets.check_probe(args.tenant)
    if args.target:
        if not any(args.target in asset.urls or args.target == asset.host for asset in scope.assets):
            from .core.errors import TargetNotAllowedError

            raise TargetNotAllowedError(
                f"la cible '{args.target}' n'est pas déclarée pour le tenant '{args.tenant}'",
                details={"declared": [url for asset in scope.assets for url in asset.urls]},
            )
    if not verdict.allowed:
        out.error(verdict.reason)
        out.error("Thot Secure n'audite que les actifs que vous avez explicitement déclarés")
        return EXIT_NEGATIVE

    result = service.collectors.run("web_probe", args.tenant, actor="cli")
    payload = result.to_dict()
    if out.as_json:
        out.emit(payload)
    else:
        out.title(f"Audit de surface de '{args.tenant}'")
        print(f"  cibles : {', '.join(result.detail.get('targets', []))}")
        print(f"  événements : {result.event_count}   erreurs : {len(result.errors)}")
        checks: dict[str, int] = {}
        for event in result.events:
            check = str(event.labels.get("check", "?"))
            checks[check] = checks.get(check, 0) + 1
        if checks:
            print()
            out.table([[check, str(count)] for check, count in sorted(checks.items())], ["contrôle", "occurrences"])
        for error in result.errors[:10]:
            print(f"  {out.sym('warn')} {error}")
    return EXIT_OK


def _cmd_collect(args: argparse.Namespace, service: Service, out: Output) -> int:
    if args.collect_command == "list":
        statuses = service.collectors.status(args.tenant)
        out.emit({"items": [status.model_dump(mode="json") for status in statuses], "count": len(statuses)})
        out.title(f"Collecteurs de '{args.tenant}'")
        out.table(
            [
                [
                    status.name,
                    "oui" if status.enabled else "non",
                    status.last_status,
                    iso_z(status.last_run)[:19] if status.last_run else "jamais",
                    str(status.runs),
                    str(status.events_emitted),
                ]
                for status in statuses
            ],
            ["collecteur", "autorisé", "dernier état", "dernière exécution", "runs", "événements"],
        )
        return EXIT_OK

    if args.collect_command == "run":
        results: dict[str, Any] = {}
        if args.all:
            for name, result in service.collectors.run_all(args.tenant, actor="cli").items():
                results[name] = result.to_dict()
        else:
            results[args.collector] = service.collectors.run(args.collector, args.tenant, actor="cli").to_dict()
        if out.as_json:
            out.emit(results)
        else:
            out.title("Collecte")
            out.table(
                [
                    [name, payload["status"], str(payload["events"]), str(payload["error_count"]), payload.get("detail", {}).get("reason", "")[:40]]
                    for name, payload in results.items()
                ],
                ["collecteur", "état", "événements", "erreurs", "note"],
            )
        failed = [name for name, payload in results.items() if payload["status"] == "error"]
        return EXIT_NEGATIVE if failed else EXIT_OK

    raise ValidationError("sous-commande 'collect' manquante (list, run)")


def _cmd_demo(args: argparse.Namespace, service: Service, out: Output) -> int:
    """Jeu de démonstration : tout le pipeline, sans rien casser.

    La démonstration est conçue pour être **sûre** : elle crée un tenant en mode simulation,
    injecte des événements qui déclenchent des détections réelles, et n'exécute que des
    connecteurs de simulation.
    """
    tenant_id = args.tenant
    tenant = service.store.get_tenant(tenant_id) or service.store.upsert_tenant(
        Tenant(
            tenant_id=tenant_id,
            name=f"Démonstration ({tenant_id})",
            mode="supervised",
            dry_run=True,
            protected_targets=["10.0.0.1", "10.0.0.0/24"],
            max_actions_per_hour=20,
        )
    )

    scenarios: dict[str, list[Event]] = {
        "web-attack": [
            Event(
                tenant_id=tenant_id,
                kind="http.request",
                source=EventSource(type="webhook", name="demo", host="shop.demo.local"),
                labels={
                    "src_ip": "203.0.113.9",
                    "method": "GET",
                    "path": f"/product?id=1 UNION SELECT {index}--",
                    "host": "shop.demo.local",
                    "user_agent": "sqlmap/1.7",
                },
                payload={"status": 403, "bytes": 512},
            )
            for index in range(3)
        ],
        "supply-chain": [
            Event(
                tenant_id=tenant_id,
                kind="dependency",
                source=EventSource(type="dependency", name="demo", host="requirements.txt"),
                labels={
                    "check": "vulnerable_dependency",
                    "package": "pyyaml",
                    "version": "5.3.1",
                    "cvss": 9.8,
                    "cve": "CVE-2020-14343",
                    "fixed_version": "5.4",
                    "ecosystem": "pypi",
                },
                payload={"summary": "Désérialisation arbitraire via full_load."},
                severity_hint="critical",
            )
        ],
        "hardening": [
            Event(
                tenant_id=tenant_id,
                kind="config.audit",
                source=EventSource(type="config_audit", name="demo", host="sshd_config"),
                labels={"check": "ssh_permit_root_login", "file": "/etc/ssh/sshd_config", "kind": "ssh"},
                payload={"message": "PermitRootLogin yes"},
                severity_hint="high",
            )
        ],
    }

    events = scenarios[args.scenario]
    outcome = service.pipeline.ingest(events, actor="cli:demo", actor_role="admin")
    payload = {
        "tenant": tenant.model_dump(mode="json"),
        "scenario": args.scenario,
        "accepted": outcome.result.accepted,
        "findings": [finding.model_dump(mode="json") for finding in outcome.findings],
        "decisions": [decision.model_dump(mode="json") for decision in outcome.decisions],
        "actions": [action.model_dump(mode="json") for action in outcome.actions],
    }
    if out.as_json:
        out.emit(payload)
    else:
        out.title(f"Démonstration « {args.scenario} » — tenant '{tenant_id}'")
        print(f"  {outcome.result.accepted} événement(s) ingéré(s), {len(outcome.findings)} finding(s)")
        for index, finding in enumerate(outcome.findings):
            decision = outcome.decisions[index] if index < len(outcome.decisions) else None
            print()
            print(f"  [{finding.severity}] {finding.risk_score:.1f}/100  {finding.rule_id}")
            print(f"    {finding.title}")
            print(f"    remédiation : {finding.remediation[:80]}")
            if decision is not None:
                print(f"    décision    : {decision.decision} (politique {decision.policy_id or 'aucune'})")
                if decision.guards:
                    print(f"    garde-fous  : {', '.join(decision.guards)}")
        for action in outcome.actions:
            print()
            print(f"  action {action.action_id} : {action.playbook} → {action.status}")
        print()
        out.success("démonstration terminée — aucune action réelle n'a été appliquée")
        print("  console : thotsecure serve  puis  http://127.0.0.1:8080/")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
