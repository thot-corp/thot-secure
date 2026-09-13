# Scripts d'exploitation — Thot Secure

Ce répertoire contient les scripts qui **installent, sauvegardent, restaurent, durcissent et
exportent** une installation Thot Secure. Ils sont écrits pour être lus avant d'être exécutés :
un script d'exploitation qui agit sur `/etc`, `/var/lib` et un service systemd mérite cinq minutes
de lecture, surtout lancé en `root`.

> **Lisez un script avant de l'exécuter en root.** Un `curl … | sudo bash` exécute du code
> distant avec vos privilèges : téléchargez, lisez, vérifiez l'origine, puis lancez. Aucun de ces
> scripts n'a besoin d'être piped pour fonctionner : ils acceptent tous `--help`.

Thot Secure est un outil **strictement défensif**. Aucun script de ce répertoire ne scanne, ne
force, n'exploite ou n'attaque quoi que ce soit, et aucun ne désactive un garde-fou.

## Tableau récapitulatif

| Script | Rôle | Prérequis | Exemple d'usage | Risque |
|---|---|---|---|---|
| `install.sh` | Installation Linux/macOS en une commande, depuis une release **vérifiée** (signature Sigstore + condensé SHA-256), création du compte système, des répertoires et de l'unité systemd | `root`, Python ≥ 3.11, `cosign`, `curl` ou `wget`, `systemd` | `sudo ./scripts/install.sh --dry-run --version v0.1.0` | **Élevé** — écrit dans `/etc`, `/var/lib`, `/opt`, `/usr/local` et installe un service |
| `install.ps1` | Installation Windows : contrôle **obligatoire** du condensé SHA-256, environnement virtuel, lanceur `thotsecure.cmd`, répertoires de données protégés | PowerShell 5.1+, Python ≥ 3.11, droits d'administration pour `%ProgramData%` | `.\scripts\install.ps1 -Archive .\thotsecure-0.1.0-py3-none-any.whl -Sha256 <hex>` | **Élevé** — crée des répertoires machine et des ACL |
| `uninstall.sh` | Désinstallation réversible : arrêt du service, sauvegarde proposée, binaires retirés ; **les données sont conservées** sauf `--purge` (confirmation exigée) | `root`, `systemd` si installé | `sudo ./scripts/uninstall.sh --backup` | **Élevé** — arrête le service et supprime des fichiers |
| `backup.sh` | Sauvegarde **cohérente** (API `.backup()` de SQLite, jamais un `cp` brut), contrôle `PRAGMA integrity_check`, vérification de la chaîne d'audit, scellés SHA-256, chiffrement `age`/`gpg`, rotation `--keep` | Python ≥ 3.11, `sha256sum`/`shasum`/`openssl`, accès en lecture à la base | `sudo ./scripts/backup.sh --keep 30 --encrypt age --recipient age1…` | **Moyen** — lit les données, écrit des archives sensibles ; la rotation supprime (confirmation) |
| `restore.sh` | Restauration : **condensé vérifié**, déchiffrement si nécessaire, arrêt du service, **sauvegarde de sécurité de la base courante**, bascule atomique, puis `doctor` et `audit verify` | `root`, Python ≥ 3.11, `sha256sum`/`shasum`/`openssl` | `sudo ./scripts/restore.sh --archive /var/backups/thotsecure/thotsecure-backup-*.db --dry-run` | **Critique** — **remplace la base de production** |
| `audit-export.sh` | Export périodique du journal d'audit (`format=cef|jsonl`) vers un SIEM ou un disque hors ligne, avec **vérification préalable de la chaîne**, horodatage, scellés et rotation | Python ≥ 3.11, accès à l'API locale, clé API en fichier `0600` ou `THOT_API_KEY` | `sudo ./scripts/audit-export.sh --tenant acme --format cef --out /mnt/coffre/audit --sync` | **Moyen** — lit l'audit et écrit un fichier sensible (acteurs, cibles, décisions) |
| `hardening-check.sh` | Contrôle du **durcissement de l'hôte** : permissions des données et de la base, fichier d'environnement et secrets, compte de service non-root, exposition réseau, unité systemd durcie, absence de secret dans les journaux | Python non requis ; `root` recommandé pour tout voir | `sudo ./scripts/hardening-check.sh --json` | **Faible** — lecture seule, aucune correction appliquée (code 3 si un contrôle critique échoue) |
| `thotsecure.service` | Unité systemd **durcie**, commentée directive par directive : utilisateur dédié, `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `ReadWritePaths=/var/lib/thotsecure`, `Restart=on-failure` | `systemd` ≥ 245 | `sudo install -o root -g root -m 0644 scripts/thotsecure.service /etc/systemd/system/` | **Élevé** — définit un processus exécuté en continu |
| `dev-setup.sh` | Environnement de **développement** POSIX : venv, `pip install -e ".[dev]"` avec repli `--no-deps`, `.env` local sûr, `init-db`, tenant de démonstration, `demo`, `doctor` | Python ≥ 3.11, clone du dépôt | `./scripts/dev-setup.sh --offline` | **Faible** — n'agit que dans le dépôt (`.venv/`, `.env`, `config/targets.yaml`, `data/`) |
| `dev-setup.ps1` | Équivalent Windows de `dev-setup.sh` (mêmes étapes, mêmes garde-fous) | PowerShell 5.1+, Python ≥ 3.11 | `.\scripts\dev-setup.ps1 -Offline -NoDemo` | **Faible** — n'agit que dans le dépôt |

## Conventions communes

Tous les scripts partagent les mêmes conventions : les connaître une fois suffit pour tous.

* **Codes de sortie** (contrat d'interface §8) : `0` succès, `1` erreur, `2` erreur d'usage,
  `3` **vérification négative** (condensé invalide, base corrompue, chaîne d'audit rompue). Un
  `3` n'est pas un plantage : c'est un résultat qu'il faut traiter.
* **Options** : chaque script accepte `--help`. Les scripts destructifs acceptent `--dry-run`
  (tout est vérifié, rien n'est modifié) et `--yes` (automatisation, à réserver aux tâches
  planifiées que vous avez validées).
* **Secrets** : ils ne vivent que dans `/etc/thotsecure/thotsecure.env` (`0600`,
  `root:thotsecure`). Aucun script n'accepte un secret en argument de ligne de commande (il
  apparaîtrait dans `ps` et dans l'historique) : `audit-export.sh` lit la clé API dans un fichier
  `0600` ou dans la variable d'environnement `THOT_API_KEY`.
* **Chemins** : compte système `thotsecure`, `/etc/thotsecure`, `/var/lib/thotsecure`,
  `/var/log/thotsecure`, `/var/backups/thotsecure`, `/opt/thotsecure/venv`.
* **Variables** : préfixe `THOT_` (`THOT_DRY_RUN`, `THOT_AUTONOMY`, `THOT_DB_URL`,
  `THOT_SECRET_KEY`, `THOT_TLS_ENABLED`…). Le fichier d'environnement est la seule source des
  secrets ; les scripts n'écrivent jamais `THOT_DRY_RUN=false` ni `THOT_AUTONOMY=auto`.
  Les variables de **réglage des scripts** (et non du produit) sont documentées dans le `--help`
  de chaque script : `THOT_BACKUP_DIR`, `THOT_BACKUP_KEEP`, `THOT_BACKUP_RECIPIENT`,
  `THOT_AUDIT_EXPORT_DIR`, `THOT_AUDIT_EXPORT_KEEP`, `THOT_API_URL`, `THOT_API_KEY`,
  `THOT_HEALTH_URL`, `THOT_DEV_PYTHON`. Le contrat d'interface §9 reste la référence pour les
  variables lues par l'application elle-même.
* **Vérification avant action** : les scripts qui manipulent des données vérifient d'abord
  (`PRAGMA integrity_check`, `thotsecure audit verify`, condensé SHA-256) et **refusent** de
  poursuivre sur une donnée douteuse. Il n'existe volontairement aucune option de contournement
  silencieuse.

## Ordre recommandé pour une mise en production

1. **Lire les scripts** que vous allez lancer, et lire `SECURITY.md` ainsi que
   `docs/operations/deployment.md`.
2. **Installer** : `sudo ./scripts/install.sh` (ou, sous Windows,
   `.\scripts\install.ps1 -Archive … -Sha256 …`). L'installation refuse un artefact non vérifié :
   c'est voulu, ne cherchez pas à contourner ce point.
3. **Diagnostiquer** : `thotsecure doctor`. Corrigez tout contrôle marqué critique avant d'aller
   plus loin (périmètre déclaré, base initialisée, clé de signature persistée).
4. **Contrôler l'hôte** : `sudo ./scripts/hardening-check.sh`. Aucun échec critique ne doit
   subsister, et chaque avertissement doit être une décision assumée par écrit.
5. **Déclarer votre périmètre** dans `/etc/thotsecure/targets.yaml` : c'est la **seule** source de
   vérité sur ce que Thot Secure a le droit d'observer et de modifier. Aucune cible n'est devinée.
6. **Observer en simulation** : gardez `THOT_DRY_RUN=true` et `THOT_AUTONOMY=supervised`, laissez
   tourner les collecteurs, relisez les findings, les décisions proposées et les actions
   planifiées. Vérifiez que les playbooks produiraient bien l'effet attendu, et que leurs
   rollbacks sont utilisables.
7. **Mettre en place les sauvegardes et l'export d'audit** : planifiez `backup.sh` et
   `audit-export.sh` (voir la section suivante), puis **testez une restauration** avec
   `restore.sh --dry-run` sur un hôte de recette. Une sauvegarde jamais restaurée n'est pas une
   sauvegarde.
8. **N'activer le mode réel qu'après validation** : le passage à `THOT_DRY_RUN=false` ou
   `THOT_AUTONOMY=auto` doit être une décision écrite, datée et approuvée, limitée aux cibles
   déclarées, avec des cibles protégées renseignées et une revue périodique des actions et des
   rollbacks. Commencez par un seul playbook, sur un seul périmètre, en heures ouvrées.

## Planification

Les tâches récurrentes se planifient avec un timer systemd ou une entrée cron, jamais avec un
`&` oublié dans une session. Exemple de timer pour la sauvegarde quotidienne :

```ini
# /etc/systemd/system/thotsecure-backup.service
[Unit]
Description=Thot Secure — sauvegarde cohérente de la base et du journal d'audit

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/thotsecure-backup
# Le script refuse d'écraser une archive existante et confirme la rotation :
# --yes est réservé à une tâche planifiée que vous avez validée une première fois.
```

```ini
# /etc/systemd/system/thotsecure-backup.timer
[Unit]
Description=Thot Secure — sauvegarde quotidienne

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

Le rôle Ansible `deploy/ansible/roles/thotsecure` fournit déjà une sauvegarde planifiée
(`thotsecure_backup_dir`, `thotsecure_backup_on_calendar`) : préférez-le si vous gérez
l'infrastructure de cette façon.

## Ce que ces scripts ne feront jamais

* Ils ne modifient pas `THOT_DRY_RUN` ni `THOT_AUTONOMY` : au contraire, ils **avertissent**
  lorsqu'ils constatent que ces garde-fous ont été inversés.
* Ils n'exécutent aucune action offensive et ne contactent que des cibles que vous avez
  déclarées.
* Ils ne suppriment ni ne remplacent une donnée sans confirmation explicite (`read -r -p`) ou
  `--yes` assumé ; `uninstall.sh` conserve les données par défaut, y compris le journal d'audit.
* Ils n'écrivent de secret ni dans un journal, ni dans un argument de commande, ni dans un
  fichier lisible par tous.
* Ils ne « réparent » jamais une chaîne d'audit rompue : une rupture est une **information**, et
  la reconstruire effacerait la preuve. Elle se traite comme un incident (`SECURITY.md`).
