"""Thot Secure — SOAR/CSPM défensif open source.

Thot Secure collecte des signaux de sécurité, détecte les menaces, score le risque, décide
selon une politique *policy-as-code* puis applique des contre-mesures **réversibles** et
**auditées**.

Invariant de conception : **100 % défensif**. Aucune capacité offensive (pas de scan
agressif, pas d'exploitation, pas de déni de service, pas de hack-back) n'existe dans ce
paquet, et toute contribution de ce type sera refusée.
"""

from __future__ import annotations

__version__ = "0.1.0"
__license__ = "Apache-2.0"
__title__ = "Thot Secure"
__description__ = (
    "SOAR/CSPM défensif : détection, décision policy-as-code et contre-mesures réversibles."
)

#: Adresses de dons officielles — source unique de vérité.
#: Elles sont rappelées par ``thotsecure funding`` et par la page ``/ui/support``.
#: Vérifiez-les toujours depuis le dépôt officiel : aucun autre canal n'est légitime.
FUNDING_ADDRESSES: dict[str, str] = {
    "BTC": "33cDzgvVe7m9P4X58pW3rsMKuxrRXFmPBR",
    "SOL": "95s8JxNzLbre9nopbdxakkc4dtNCzkzA2JUTDFQnM7Hi",
}
FUNDING_NETWORKS: dict[str, str] = {
    "BTC": "Bitcoin mainnet",
    "SOL": "Solana mainnet",
}
FUNDING_DISCLAIMER = (
    "Dons volontaires, aucune contrepartie attendue. "
    "Vérifiez toujours l'adresse depuis le dépôt officiel."
)
FUNDING_ANTISCAM = (
    "Seule la source officielle (dépôt Git et site du projet) fait foi. "
    "Thot Secure ne demandera jamais votre clé privée, votre phrase de récupération "
    "ni un accès à votre wallet, et n'accorde aucun avantage, support prioritaire "
    "ou fonctionnalité en échange d'un don."
)

__all__ = [
    "FUNDING_ADDRESSES",
    "FUNDING_ANTISCAM",
    "FUNDING_DISCLAIMER",
    "FUNDING_NETWORKS",
    "__version__",
]
