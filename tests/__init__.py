"""Rend ``src/`` importable sans installation préalable du paquet.

C'est ce qui permet à ``python -m unittest discover -s tests -t .`` de fonctionner sur une
machine sans accès réseau (pas de ``pip install -e .``). En CI, le paquet est installé et ce
chemin n'a simplement aucun effet.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
