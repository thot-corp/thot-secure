# Exemple de politique OPA/Rego pour Thot Secure.
#
# Utilisation (facultative) : définissez THOT_OPA_BIN vers le binaire `opa` et placez ce
# fichier dans policies/rego/. Le moteur YAML reste actif en repli : l'indisponibilité d'OPA
# ne doit jamais empêcher une décision (voir thotsecure/decision/opa.py).
#
# Requête évaluée par défaut : data.thotsecure.decision
#
# IMPORTANT : une politique Rego ne peut PAS désactiver les garde-fous du moteur Python
# (cible protégée, périmètre déclaré, plafond horaire, cooldown, dry-run). Ceux-ci sont
# appliqués après, quel que soit le résultat renvoyé ici.

package thotsecure

import future.keywords.if
import future.keywords.in

# Décision par défaut : notification seule. Le silence n'est jamais un défaut.
default decision := {
    "decision": "notify_only",
    "reason": "aucune politique Rego correspondante (défaut sûr)",
}

# Blocage automatique des attaques web critiques, uniquement si le tenant est en mode autonome
# et que le score dépasse 80.
decision := result if {
    input.finding.severity == "critical"
    input.finding.risk_score >= 80
    input.tenant.mode == "auto"
    some tag in input.finding.tags
    tag in {"exploit-attempt", "exposure"}
    result := {
        "decision": "auto",
        "playbook": "block-source-ip",
        "params": {
            "target": "labels.src_ip",
            "duration_seconds": 3600,
            "reason": "OPA — attaque critique (blocage réversible)",
        },
        "reason": sprintf("Rego: severity=%s risk=%.1f tenant=%s", [input.finding.severity, input.finding.risk_score, input.tenant.id]),
    }
}

# Toute vulnérabilité de dépendance exige une validation humaine.
decision := result if {
    input.finding.severity in {"high", "critical"}
    "supply-chain" in input.finding.tags
    result := {
        "decision": "require_approval",
        "playbook": "patch-dependency",
        "params": {
            "target": "labels.package",
            "version": "labels.fixed_version",
        },
        "reason": "Rego: vulnérabilité de chaîne d'approvisionnement à valider",
    }
}

# Le durcissement n'est jamais appliqué automatiquement.
decision := result if {
    input.finding.severity in {"medium", "high"}
    some tag in input.finding.tags
    tag in {"hardening", "config"}
    result := {
        "decision": "notify_only",
        "playbook": "harden-endpoint",
        "params": {"target": "labels.host", "profile": "baseline"},
        "reason": "Rego: durcissement notifié, jamais appliqué d'office",
    }
}
