"""Adaptateur OPA/Rego (optionnel).

Thot Secure évalue ses politiques avec un moteur YAML embarqué, sans dépendance. Pour les
organisations qui ont déjà standardisé leur *policy-as-code* sur Open Policy Agent, un
adaptateur est fourni : si le binaire ``opa`` est présent (``THOT_OPA_BIN``), les
politiques Rego sont évaluées par OPA et le résultat est converti en ``Decision``.

L'échec d'OPA ne fait **jamais** tomber la décision : on retombe sur le moteur YAML et on
journalise. Un SOAR qui ne sait plus décider parce qu'un binaire annexe manque est un SOAR
qui laisse passer les attaques.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.logging_setup import get_logger

log = get_logger("decision.opa")

#: Requête par défaut : la politique Rego doit exposer ``decision``.
DEFAULT_QUERY = "data.thotsecure.decision"

#: Délai maximal accordé à OPA. Au-delà, on considère la décision comme indisponible :
#: le pipeline ne doit pas être bloqué par un sous-processus.
OPA_TIMEOUT_SECONDS = 2.0

#: Taille maximale du document d'entrée (protection anti-épuisement).
MAX_INPUT_BYTES = 256 * 1024


@dataclass(slots=True)
class OpaResult:
    ok: bool
    payload: dict[str, Any] | None = None
    error: str | None = None


class OpaEvaluator:
    """Évalue des politiques Rego via le binaire ``opa``."""

    def __init__(
        self,
        binary: str | None = None,
        *,
        query: str = DEFAULT_QUERY,
        rego_dir: str | Path | None = None,
        timeout: float = OPA_TIMEOUT_SECONDS,
    ) -> None:
        self.binary = binary
        self.query = query
        self.rego_dir = Path(rego_dir) if rego_dir else None
        self.timeout = timeout
        self._resolved: str | None = None
        self.evaluations = 0
        self.failures = 0

    # ----------------------------------------------------------------------------------

    def available(self) -> bool:
        """Vrai si un binaire OPA utilisable est présent."""
        if self._resolved is not None:
            return bool(self._resolved)
        candidate = self.binary or shutil.which("opa") or ""
        if not candidate:
            self._resolved = ""
            return False
        resolved = shutil.which(candidate) or (candidate if Path(candidate).exists() else "")
        self._resolved = resolved
        return bool(resolved)

    def evaluate(self, input_document: dict[str, Any]) -> OpaResult:
        """Évalue ``input`` et retourne le dictionnaire ``decision`` produit par Rego."""
        self.evaluations += 1
        if not self.available():
            return OpaResult(ok=False, error="binaire OPA indisponible")

        serialized = json.dumps(input_document, ensure_ascii=False, default=str)
        if len(serialized.encode("utf-8")) > MAX_INPUT_BYTES:
            return OpaResult(ok=False, error="document d'entrée trop volumineux pour OPA")

        command = [self._resolved or "opa", "eval", "--format=json", "--stdin-input", self.query]
        if self.rego_dir and self.rego_dir.exists():
            command.insert(-1, str(self.rego_dir))

        try:
            completed = subprocess.run(  # noqa: S603 - binaire résolu explicitement
                command,
                input=serialized.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.failures += 1
            log.error("échec d'exécution d'OPA", extra={"error": str(exc)})
            return OpaResult(ok=False, error=str(exc))

        if completed.returncode != 0:
            self.failures += 1
            stderr = completed.stderr.decode("utf-8", "replace")[:500]
            log.error("OPA a retourné une erreur", extra={"stderr": stderr})
            return OpaResult(ok=False, error=stderr)

        try:
            document = json.loads(completed.stdout.decode("utf-8", "replace"))
            result = document["result"][0]["expressions"][0]["value"]
        except (ValueError, KeyError, IndexError) as exc:
            self.failures += 1
            log.error("réponse d'OPA illisible", extra={"error": str(exc)})
            return OpaResult(ok=False, error="réponse OPA illisible")

        if not isinstance(result, dict):
            return OpaResult(ok=False, error="la politique Rego doit retourner un objet")
        return OpaResult(ok=True, payload=result)

    def stats(self) -> dict[str, Any]:
        return {
            "available": self.available(),
            "query": self.query,
            "evaluations": self.evaluations,
            "failures": self.failures,
        }


def decision_from_rego(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise la sortie Rego vers les champs de ``Decision``.

    On accepte les clés françaises et anglaises pour ne pas imposer un format d'écriture
    Rego, mais tout champ inconnu est ignoré : une politique Rego ne peut pas injecter de
    garde-fou contourné, le moteur Python réapplique les siens.
    """
    allowed = {
        "decision",
        "playbook",
        "params",
        "reason",
        "cooldown_seconds",
        "max_actions_per_hour",
        "dry_run",
    }
    normalized: dict[str, Any] = {}
    for key in allowed:
        if key in payload:
            normalized[key] = payload[key]

    decision = normalized.get("decision")
    if decision not in {"auto", "require_approval", "notify_only", "ignore"}:
        normalized["decision"] = "notify_only"
        normalized["reason"] = (
            f"OPA a retourné une décision inconnue ({decision!r}) : repli sur 'notify_only'"
        )
    if not isinstance(normalized.get("params"), dict):
        normalized["params"] = {}
    return normalized


__all__ = [
    "DEFAULT_QUERY",
    "MAX_INPUT_BYTES",
    "OPA_TIMEOUT_SECONDS",
    "OpaEvaluator",
    "OpaResult",
    "decision_from_rego",
]
