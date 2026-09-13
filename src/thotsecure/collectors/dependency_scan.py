"""Analyse des dépendances déclarées face à un instantané d'avis de sécurité **hors ligne**.

Le collecteur lit les manifestes explicitement déclarés par le tenant (``requirements.txt``,
``package.json``, ``go.mod``, ``pom.xml``) et les confronte à un instantané local d'avis
(``thotsecure/data/advisories.json``). Aucune requête réseau n'est effectuée : un outil de
sécurité qui interroge un service tiers à chaque exécution crée une dépendance
d'approvisionnement (et une fuite d'information sur son parc).

L'instantané livré est un **jeu de départ volontairement restreint** de vulnérabilités
publiques notoires. Il doit être rafraîchi depuis une source faisant autorité (OSV, NVD,
GitHub Advisory) — procédure décrite dans ``docs/operations/runbook.md``.

Ce collecteur **ne modifie rien** : il émet des événements. La mise à jour d'une dépendance
passe par un playbook, donc par une décision, donc par une trace.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.models import Severity
from .base import Collector, CollectorContext, CollectorResult

#: Nombre maximal de paquets signalés par manifeste (protection contre l'avalanche).
MAX_FINDINGS_PER_MANIFEST = 100


@dataclass(slots=True)
class Dependency:
    """Dépendance déclarée dans un manifeste."""

    name: str
    version: str
    ecosystem: str
    raw: str = ""


@dataclass(slots=True)
class Advisory:
    """Avis de sécurité local."""

    cve: str
    package: str
    ecosystem: str
    affected: str
    fixed_version: str
    cvss: float
    severity: str
    summary: str
    references: list[str]

    def affects(self, version: str) -> bool:
        """Vrai si ``version`` est concernée par ``affected`` (ex. ``<4.17.21``)."""
        spec = self.affected.strip()
        match = re.match(r"^(<=|>=|<|>|==)\s*(.+)$", spec)
        if not match:
            return False
        operator, bound = match.group(1), match.group(2).strip()
        comparison = compare_versions(version, bound)
        if comparison is None:
            return False
        return {
            "<": comparison < 0,
            "<=": comparison <= 0,
            ">": comparison > 0,
            ">=": comparison >= 0,
            "==": comparison == 0,
        }[operator]


class DependencyScanCollector(Collector):
    """Confronte les dépendances déclarées aux avis de sécurité locaux."""

    name = "dependency_scan"
    source_type = "dependency"
    description = "Détecte les dépendances vulnérables connues d'après un instantané d'avis local."
    default_interval_seconds = 3600
    requires_probe_optin = False

    def __init__(self, advisories_path: Path | None = None) -> None:
        self._advisories_path = advisories_path
        self._cache: list[Advisory] | None = None

    # ----------------------------------------------------------------------------------

    @property
    def advisories_path(self) -> Path:
        if self._advisories_path is not None:
            return Path(self._advisories_path)
        return Path(__file__).resolve().parent.parent / "data" / "advisories.json"

    def load_advisories(self) -> list[Advisory]:
        """Charge l'instantané local (mis en cache après le premier chargement)."""
        if self._cache is not None:
            return self._cache
        path = self.advisories_path
        if not path.exists():
            self._cache = []
            return self._cache
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._cache = []
            return self._cache
        advisories: list[Advisory] = []
        for item in document.get("advisories") or []:
            try:
                advisories.append(
                    Advisory(
                        cve=str(item["cve"]),
                        package=str(item["package"]).lower(),
                        ecosystem=str(item.get("ecosystem") or "pypi").lower(),
                        affected=str(item.get("affected") or "<0"),
                        fixed_version=str(item.get("fixed_version") or ""),
                        cvss=float(item.get("cvss") or 0.0),
                        severity=str(item.get("severity") or "medium"),
                        summary=str(item.get("summary") or ""),
                        references=[str(ref) for ref in item.get("references") or []],
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        self._cache = advisories
        return advisories

    # ----------------------------------------------------------------------------------

    def collect(self, context: CollectorContext) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        scope = context.scope
        manifests = [str(item) for item in scope.manifests]
        if not manifests:
            return self._skip(
                f"aucun manifeste déclaré pour le tenant '{scope.tenant_id}' "
                "(renseignez 'manifests' dans config/targets.yaml)"
            )

        advisories = self.load_advisories()
        if not advisories:
            result.add_error(
                "instantané d'avis vide ou illisible : aucune comparaison possible "
                f"({self.advisories_path})"
            )
            return result

        result.detail["manifests"] = manifests
        result.detail["advisories_loaded"] = len(advisories)
        total_dependencies = 0
        total_matches = 0

        for manifest in manifests:
            path = Path(manifest).expanduser()
            if not path.is_absolute():
                path = context.settings.root_path / path
            if not path.exists():
                result.add_error(f"manifeste introuvable: {path}")
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                result.add_error(f"{path}: {exc}")
                continue

            dependencies = parse_manifest(path.name, text)
            total_dependencies += len(dependencies)
            matches = 0
            for dependency in dependencies:
                for advisory in advisories:
                    if advisory.package != dependency.name.lower():
                        continue
                    if advisory.ecosystem and advisory.ecosystem != dependency.ecosystem:
                        continue
                    if not advisory.affects(dependency.version):
                        continue
                    matches += 1
                    result.events.append(
                        context.make_event(
                            kind="dependency",
                            source_type=self.source_type,
                            source_name=self.name,
                            source_host=path.name,
                            labels={
                                "package": dependency.name,
                                "version": dependency.version,
                                "ecosystem": dependency.ecosystem,
                                "cve": advisory.cve,
                                "cvss": advisory.cvss,
                                "fixed_version": advisory.fixed_version,
                                "manifest": str(path),
                                "check": "vulnerable_dependency",
                            },
                            payload={
                                "summary": advisory.summary,
                                "severity": advisory.severity,
                                "references": advisory.references,
                                "declared_in": dependency.raw[:300],
                            },
                            severity_hint=_severity_from_cvss(advisory.cvss),  # type: ignore[arg-type]
                        )
                    )
                    if matches >= MAX_FINDINGS_PER_MANIFEST:
                        result.add_error(
                            f"{path.name}: limité à {MAX_FINDINGS_PER_MANIFEST} avis signalés"
                        )
                        break
                if matches >= MAX_FINDINGS_PER_MANIFEST:
                    break
            total_matches += matches
            result.detail.setdefault("per_manifest", {})[path.name] = {
                "dependencies": len(dependencies),
                "matches": matches,
            }

        result.detail["dependencies_analyzed"] = total_dependencies
        result.detail["vulnerable_matches"] = total_matches
        result.finished_at = _now()
        return result


# --------------------------------------------------------------------------------------
# Analyse des manifestes
# --------------------------------------------------------------------------------------


def parse_manifest(filename: str, text: str) -> list[Dependency]:
    """Détecte le format d'après le nom du fichier et délègue à l'analyseur adapté."""
    lower = filename.lower()
    if lower.startswith("requirements") or (lower.endswith(".txt") and "requirements" in lower):
        return parse_requirements(text)
    if lower == "package.json":
        return parse_package_json(text)
    if lower == "go.mod":
        return parse_go_mod(text)
    if lower == "pom.xml":
        return parse_pom_xml(text)
    # Repli : format requirements, le plus répandu.
    return parse_requirements(text)


_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?P<op>==|>=|<=|~=|>|<)?\s*(?P<version>[0-9][^\s;#]*)"
)


def parse_requirements(text: str) -> list[Dependency]:
    """Analyse un ``requirements.txt`` (épinglage ``==`` privilégié)."""
    dependencies: list[Dependency] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", "git+", "http")):
            continue
        match = _REQUIREMENT.match(stripped)
        if not match:
            continue
        version = match.group("version") or "0"
        # Une contrainte >= n'épingle pas : on ne peut pas conclure, on ne signale rien.
        if match.group("op") not in {"==", "~="}:
            continue
        dependencies.append(
            Dependency(
                name=match.group("name").lower(),
                version=version.strip(),
                ecosystem="pypi",
                raw=stripped,
            )
        )
    return dependencies


def parse_package_json(text: str) -> list[Dependency]:
    """Analyse un ``package.json`` (dépendances et dépendances de développement)."""
    try:
        document = json.loads(text)
    except ValueError:
        return []
    dependencies: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (document.get(section) or {}).items():
            version = str(spec).lstrip("^~>=< ").split(" ")[0]
            if not version or not version[0].isdigit():
                # Plages (``*``, ``latest``, ``workspace:*``) : indéterminable.
                continue
            dependencies.append(
                Dependency(
                    name=str(name).lower(),
                    version=version,
                    ecosystem="npm",
                    raw=f"{name}: {spec}",
                )
            )
    return dependencies


def parse_go_mod(text: str) -> list[Dependency]:
    """Analyse un ``go.mod`` (bloc ``require`` et lignes simples)."""
    dependencies: list[Dependency] = []
    in_require_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and stripped == ")":
            in_require_block = False
            continue
        if not in_require_block and not stripped.startswith("require "):
            continue
        candidate = (
            stripped[len("require ") :].strip() if stripped.startswith("require ") else stripped
        )
        parts = candidate.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1].lstrip("v")
        if not version or not version[0].isdigit():
            continue
        dependencies.append(
            Dependency(name=module.lower(), version=version, ecosystem="go", raw=stripped)
        )
    return dependencies


_POM_DEPENDENCY = re.compile(
    r"<dependency>\s*<groupId>(?P<group>[^<]+)</groupId>\s*<artifactId>(?P<artifact>[^<]+)</artifactId>"
    r"\s*<version>(?P<version>[^<]+)</version>",
    re.DOTALL,
)


def parse_pom_xml(text: str) -> list[Dependency]:
    """Analyse les dépendances d'un ``pom.xml`` Maven (sans parseur XML complet)."""
    dependencies: list[Dependency] = []
    for match in _POM_DEPENDENCY.finditer(text):
        version = match.group("version").strip()
        if "${" in version or not version or not version[0].isdigit():
            continue
        dependencies.append(
            Dependency(
                name=f"{match.group('group').strip()}:{match.group('artifact').strip()}".lower(),
                version=version,
                ecosystem="maven",
                raw=match.group(0)[:200],
            )
        )
    return dependencies


# --------------------------------------------------------------------------------------
# Comparaison de versions
# --------------------------------------------------------------------------------------


def version_key(version: str) -> tuple[int, ...]:
    """Convertit une version en tuple comparable.

    Les suffixes de pré-version (``rc1``, ``b2``) sont traduits en entiers *négatifs* pour
    qu'ils se comparent **avant** la version finale (``1.0rc1`` < ``1.0``), ce qui est le
    comportement attendu en sécurité.
    """
    cleaned = version.strip().lstrip("v").split("+")[0]
    parts = re.split(r"[.\-]", cleaned)
    key: list[int] = []
    for part in parts:
        match = re.match(r"^(\d+)", part)
        if match:
            key.append(int(match.group(1)))
            suffix = part[match.end() :]
            if suffix:
                key.append(-1)
        else:
            key.append(-1)
    while len(key) < 4:
        key.append(0)
    return tuple(key[:6])


def compare_versions(left: str, right: str) -> int | None:
    """Compare deux versions. ``None`` si la comparaison n'a pas de sens."""
    try:
        left_key, right_key = version_key(left), version_key(right)
    except (ValueError, AttributeError):
        return None
    return (left_key > right_key) - (left_key < right_key)


def _severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _now() -> Any:
    from ..core.util import utcnow

    return utcnow()


__all__ = [
    "MAX_FINDINGS_PER_MANIFEST",
    "Advisory",
    "Dependency",
    "DependencyScanCollector",
    "compare_versions",
    "parse_go_mod",
    "parse_manifest",
    "parse_package_json",
    "parse_pom_xml",
    "parse_requirements",
    "version_key",
]
