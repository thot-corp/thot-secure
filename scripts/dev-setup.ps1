<#
.SYNOPSIS
    Thot Secure (nom technique du paquet : « thotsecure ») — scripts/dev-setup.ps1

.DESCRIPTION
    Prépare un environnement de DÉVELOPPEMENT complet sous Windows, sans privilège
    d'administration, en miroir de scripts/dev-setup.sh :

      1. vérifie qu'on est bien à la racine du dépôt et que Python >= 3.11 est là ;
      2. crée (ou RÉUTILISE) l'environnement virtuel .venv ;
      3. installe le paquet en mode éditable avec les outils de développement
         (pip install -e ".[dev]") et, SI LE RÉSEAU EST INDISPONIBLE, se replie
         automatiquement sur « pip install -e . --no-deps --no-build-isolation »
         en annonçant clairement ce que l'on perd (pytest, ruff, mypy, httpx) ;
      4. crée un fichier .env local avec les valeurs de DÉVELOPPEMENT sûres
         (jamais écrasé s'il existe) et copie config\targets.example.yaml vers
         config\targets.yaml si le périmètre n'est pas encore déclaré ;
      5. initialise la base locale       : thotsecure init-db ;
      6. crée le tenant de démonstration : thotsecure tenant create --id demo ... ;
      7. injecte le jeu de démonstration : thotsecure demo --tenant demo ;
      8. termine par le diagnostic       : thotsecure doctor.

    IDEMPOTENT : relançable sans rien casser. L'environnement virtuel existant est
    conservé, la base est mise à jour et non recréée, le .env n'est jamais écrasé,
    la démonstration est rejouable. Seul -Recreate (avec confirmation) supprime
    quelque chose.

    SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
      * Ce script pose THOT_DRY_RUN=true et THOT_AUTONOMY=supervised pour TOUTES
        les commandes qu'il exécute, et il ne les inverse JAMAIS ;
      * s'il constate que vous les avez modifiés (environnement ou .env), il le
        dit très explicitement : passer en réel est une décision, pas un
        raccourci de développement ;
      * aucun secret n'est écrit en dur : le .env de développement ne contient
        que des réglages locaux, et il est ignoré par Git (.gitignore) ;
      * aucune expression n'est évaluée dynamiquement (pas d'Invoke-Expression).

    Codes de sortie : 0 succès, 1 erreur, 2 usage, 3 vérification négative
    (code renvoyé par « thotsecure doctor » lorsqu'un contrôle critique échoue).

.EXAMPLE
    .\scripts\dev-setup.ps1
    .\scripts\dev-setup.ps1 -Offline -NoDemo
    .\scripts\dev-setup.ps1 -Recreate -Yes

.NOTES
    Lisez ce script avant de l'exécuter : il modifie le dépôt (venv, .env, base
    locale). Licence Apache-2.0.
#>

[CmdletBinding()]
param(
    # Répertoire de l'environnement virtuel (relatif à la racine du dépôt).
    [string]$VenvDir = '.venv',

    # Interpréteur Python à utiliser. Vide = détection automatique
    # (py -3.11, py -3, python, puis $env:THOT_DEV_PYTHON s'il est défini).
    [string]$Python = '',

    # Identifiant du tenant de démonstration.
    [string]$Tenant = 'demo',

    # Ne pas tenter d'accéder au réseau : installation directe avec --no-deps.
    [switch]$Offline,

    # Ne pas injecter le jeu de démonstration.
    [switch]$NoDemo,

    # Ne pas créer de fichier .env local.
    [switch]$NoEnvFile,

    # Supprimer puis recréer l'environnement virtuel (destructif : confirmation).
    [switch]$Recreate,

    # Ne poser aucune question (automatisation).
    [switch]$Yes,

    # Afficher les opérations sans rien modifier.
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptName = 'dev-setup.ps1'
$ScriptVersion = '0.1.0'
$ExitUsage = 2
$ExitVerify = 3
$MinPythonMajor = 3
$MinPythonMinor = 11

# -----------------------------------------------------------------------------
# Journalisation (mêmes codes couleur que scripts/install.sh et dev-setup.sh)
# -----------------------------------------------------------------------------
function Write-Info  { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Message) Write-Host "  ok $Message" -ForegroundColor Green }
function Write-Warn  { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err   { param([string]$Message) Write-Host "[x] $Message" -ForegroundColor Red }
function Write-Step  { param([string]$Message) Write-Host "    $Message" -ForegroundColor DarkGray }

function Stop-Script {
    <# Termine le script avec un message d'erreur et un code de sortie explicite. #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [int]$Code = 1
    )
    Write-Err $Message
    exit $Code
}

function Invoke-Mutation {
    <#
        Exécute une opération qui MODIFIE le dépôt, ou l'affiche seulement en
        mode -DryRun. Aucune opération destructive ne passe ailleurs.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    if ($DryRun) {
        Write-Host "    [dry-run] $Description" -ForegroundColor DarkGray
        return
    }
    & $Action
}

function Read-Confirmation {
    <# Confirmation explicite. -Yes ou réponse « oui » exigée ; jamais par défaut. #>
    param([Parameter(Mandatory = $true)][string]$Prompt)
    if ($Yes) {
        Write-Warn "$Prompt → confirmé par -Yes."
        return $true
    }
    if (-not [Environment]::UserInteractive) {
        Write-Err "$Prompt : aucune confirmation possible (session non interactive)."
        Write-Step "Relancez avec -Yes si l'opération est réellement voulue."
        return $false
    }
    $answer = Read-Host "$Prompt [oui/non]"
    return ($answer -match '^(oui|o|yes|y)$')
}

# -----------------------------------------------------------------------------
# 1. Racine du dépôt et interpréteur
# -----------------------------------------------------------------------------
function Resolve-RepoRoot {
    $candidate = Split-Path -Parent $PSScriptRoot
    if (-not (Test-Path -LiteralPath (Join-Path $candidate 'pyproject.toml'))) {
        Stop-Script "pyproject.toml introuvable dans $candidate : lancez ce script depuis un clone du dépôt." 1
    }
    if (-not (Test-Path -LiteralPath (Join-Path $candidate 'src\thotsecure'))) {
        Stop-Script "src\thotsecure introuvable dans $candidate : dépôt incomplet." 1
    }
    Set-Location -LiteralPath $candidate
    Write-Step "Racine du dépôt : $candidate"
    return $candidate
}

function Resolve-PythonExe {
    <# Retourne la ligne de commande complète (tableau) de l'interpréteur retenu. #>
    $candidates = @()
    if ($Python) { $candidates += ,@($Python) }
    if ($env:THOT_DEV_PYTHON) { $candidates += ,@($env:THOT_DEV_PYTHON) }
    $candidates += ,@('py', '-3.11')
    $candidates += ,@('py', '-3')
    $candidates += ,@('python')

    foreach ($candidate in $candidates) {
        $exe = $candidate[0]
        $command = Get-Command $exe -ErrorAction SilentlyContinue
        if (-not $command) { continue }

        $probeArgs = @()
        if ($candidate.Count -gt 1) { $probeArgs = $candidate[1..($candidate.Count - 1)] }
        $probeArgs += @('-c', 'import sys; print("%d.%d" % sys.version_info[:2])')

        try {
            $version = (& $command.Source @probeArgs 2>$null | Select-Object -First 1)
        }
        catch {
            continue
        }
        if (-not $version) { continue }
        if ($version -notmatch '^\d+\.\d+$') { continue }

        $parts = $version.Split('.')
        $major = [int]$parts[0]
        $minor = [int]$parts[1]
        if ($major -lt $MinPythonMajor -or ($major -eq $MinPythonMajor -and $minor -lt $MinPythonMinor)) {
            Write-Warn "Python $version est trop ancien (>= $MinPythonMajor.$MinPythonMinor requis par pyproject.toml) : candidat ignoré."
            continue
        }

        return @{ Exe = $candidate; Display = ($candidate -join ' '); Version = $version }
    }

    Stop-Script "Aucun interpréteur Python >= $MinPythonMajor.$MinPythonMinor trouvé. Installez Python (python.org) ou passez -Python <chemin>." 1
}

# -----------------------------------------------------------------------------
# 2. Sûreté : garde-fous imposés, avertissement si l'utilisateur les a modifiés
# -----------------------------------------------------------------------------
function Write-SafetyWarnings {
    $dryRun = if ($env:THOT_DRY_RUN) { $env:THOT_DRY_RUN } else { 'true' }
    $autonomy = if ($env:THOT_AUTONOMY) { $env:THOT_AUTONOMY } else { 'supervised' }

    if ($dryRun -ne 'true') {
        Write-Warn "AVERTISSEMENT : THOT_DRY_RUN=$dryRun dans votre environnement."
        Write-Warn "Un environnement de développement ne doit pas exécuter d'action réelle."
        Write-Warn "Ce script impose THOT_DRY_RUN=true aux commandes qu'il lance."
    }
    if ($autonomy -ne 'supervised' -and $autonomy -ne 'manual') {
        Write-Warn "AVERTISSEMENT : THOT_AUTONOMY=$autonomy dans votre environnement."
        Write-Warn "Le mode « auto » exécute des actions sans approbation humaine ; ce"
        Write-Warn "script ne le recommande ni ne le pose."
    }

    $envFile = Join-Path (Get-Location) '.env'
    if (Test-Path -LiteralPath $envFile) {
        $content = Get-Content -LiteralPath $envFile -ErrorAction SilentlyContinue
        $fileDryRun = ($content | Where-Object { $_ -match '^THOT_DRY_RUN=' } | Select-Object -Last 1)
        $fileAutonomy = ($content | Where-Object { $_ -match '^THOT_AUTONOMY=' } | Select-Object -Last 1)
        if ($fileDryRun) {
            $value = $fileDryRun.Split('=', 2)[1].Trim()
            if ($value -ne 'true') {
                Write-Warn "AVERTISSEMENT : .env contient THOT_DRY_RUN=$value."
                Write-Warn "Toute commande lancée hors de ce script utilisera cette valeur."
            }
        }
        if ($fileAutonomy) {
            $value = $fileAutonomy.Split('=', 2)[1].Trim()
            if ($value -ne 'supervised' -and $value -ne 'manual') {
                Write-Warn "AVERTISSEMENT : .env contient THOT_AUTONOMY=$value."
                Write-Warn "Le mode automatique ne doit pas être un défaut de développement."
            }
        }
    }

    Write-Ok "Garde-fous imposés pour ce script : THOT_DRY_RUN=true, THOT_AUTONOMY=supervised."
}

# -----------------------------------------------------------------------------
# 3. Environnement virtuel
# -----------------------------------------------------------------------------
function New-Venv {
    param([Parameter(Mandatory = $true)][hashtable]$PythonInfo)

    $venvPath = Join-Path (Get-Location) $VenvDir
    $venvPython = Join-Path $venvPath 'Scripts\python.exe'

    if ($Recreate -and (Test-Path -LiteralPath $venvPath)) {
        Write-Warn "-Recreate : l'environnement virtuel $VenvDir va être SUPPRIMÉ puis recréé."
        Write-Step "Aucune donnée utilisateur n'y est stockée : la base locale est dans .\data."
        if (-not (Read-Confirmation "Supprimer $VenvDir et le recréer ?")) {
            Write-Warn "Recréation refusée : l'environnement existant est conservé."
        }
        else {
            Invoke-Mutation "Remove-Item -Recurse -Force $venvPath" {
                Remove-Item -LiteralPath $venvPath -Recurse -Force
            }
        }
    }

    if (Test-Path -LiteralPath $venvPython) {
        $version = (& $venvPython -V 2>&1 | Select-Object -First 1)
        Write-Ok "Environnement virtuel réutilisé : $VenvDir ($version)"
        return $venvPython
    }

    Write-Info "Création de l'environnement virtuel ($VenvDir)…"
    Invoke-Mutation "$($PythonInfo.Display) -m venv $venvPath" {
        $exe = $PythonInfo.Exe[0]
        $extra = @()
        if ($PythonInfo.Exe.Count -gt 1) { $extra = $PythonInfo.Exe[1..($PythonInfo.Exe.Count - 1)] }
        # Out-Host : la sortie de l'outil va à la console et ne pollue pas la
        # valeur de retour de la fonction (PowerShell capture le flux standard).
        & $exe @extra '-m' 'venv' $venvPath | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "python -m venv a échoué (code $LASTEXITCODE)." }
    }

    if (-not $DryRun -and -not (Test-Path -LiteralPath $venvPython)) {
        Stop-Script "python -m venv n'a pas produit $venvPython." 1
    }
    Write-Ok "Environnement virtuel prêt : $VenvDir"
    return $venvPython
}

# -----------------------------------------------------------------------------
# 4. Dépendances (avec repli hors ligne)
# -----------------------------------------------------------------------------
function Install-Package {
    param([Parameter(Mandatory = $true)][string]$VenvPython)

    Write-Info "Installation du paquet en mode éditable…"
    if ($Offline) {
        Write-Step "-Offline : mise à jour de pip ignorée (elle exigerait le réseau)."
    }
    else {
        try {
            Invoke-Mutation "pip install --upgrade pip" {
                & $VenvPython -m pip install --upgrade pip | Out-Host
                if ($LASTEXITCODE -ne 0) { throw "pip --upgrade a échoué (code $LASTEXITCODE)." }
            }
        }
        catch {
            Write-Warn "pip n'a pas pu être mis à jour (réseau indisponible ?) : on continue."
        }
    }

    if ($Offline) {
        Write-Info "Installation hors ligne : pip install -e . --no-deps --no-build-isolation"
        Invoke-Mutation "pip install -e . --no-deps --no-build-isolation" {
            & $VenvPython -m pip install -e '.' --no-deps --no-build-isolation | Out-Host
            if ($LASTEXITCODE -ne 0) {
                Stop-Script "Installation hors ligne impossible : les dépendances (fastapi, pydantic, PyYAML…) ne sont pas disponibles dans ce venv.
Solution : créez le venv avec accès réseau une première fois, ou installez depuis un wheelhouse local (pip install --no-index --find-links <dir>)." 1
            }
        }
        Write-Warn "Installation SANS dépendances : les outils de développement (pytest, ruff, mypy, httpx) peuvent manquer."
        Write-Step "Pour les obtenir plus tard, avec réseau : $VenvPython -m pip install -e `".[dev]`""
        return 'no-deps'
    }

    Write-Step 'commande : pip install -e ".[dev]"   (pytest, ruff, mypy, httpx)'
    $installed = $false
    try {
        Invoke-Mutation 'pip install -e ".[dev]"' {
            & $VenvPython -m pip install -e '.[dev]' | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "pip install -e .[dev] a échoué (code $LASTEXITCODE)." }
        }
        $installed = $true
    }
    catch {
        Write-Warn "L'installation avec les outils de développement a échoué (réseau indisponible ?)."
    }

    if ($installed) {
        Write-Ok "Installation complète : paquet éditable + outils de développement."
        return 'dev'
    }

    # REPLI : le réseau est souvent indisponible en environnement cloisonné. On
    # installe alors le paquet sans ses dépendances : utilisable si elles sont
    # déjà présentes dans le venv, et surtout cela ne laisse pas le développeur
    # devant un « ça ne marche pas » sans explication.
    Write-Warn "REPLI hors ligne : pip install -e . --no-deps --no-build-isolation"
    Invoke-Mutation "pip install -e . --no-deps --no-build-isolation" {
        & $VenvPython -m pip install -e '.' --no-deps --no-build-isolation | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Le repli a également échoué : le paquet n'est pas installé."
            Write-Step "Les commandes passeront par « python -m thotsecure.cli » avec PYTHONPATH=src."
        }
    }
    Write-Warn "Installation SANS dépendances : les outils de développement peuvent manquer."
    Write-Step "« make test » n'existe pas sous Windows : utilisez « python -m unittest discover -s tests -t . »"
    return 'no-deps'
}

function Test-Importable {
    param([Parameter(Mandatory = $true)][string]$VenvPython)
    if ($DryRun) {
        Write-Host '    [dry-run] python -c "import thotsecure, pydantic, yaml"' -ForegroundColor DarkGray
        return
    }
    $savedPath = $env:PYTHONPATH
    $env:PYTHONPATH = 'src'
    $output = ''
    $ok = $false
    try {
        $output = (& $VenvPython -c 'import thotsecure, pydantic, yaml' 2>&1 | Out-String)
        $ok = ($LASTEXITCODE -eq 0)
    }
    catch {
        $output = $_.Exception.Message
    }
    finally {
        $env:PYTHONPATH = $savedPath
    }
    if ($ok) {
        Write-Ok "Paquet et dépendances d'exécution importables."
        return
    }
    Write-Err "Le paquet ou ses dépendances ne s'importent pas dans $VenvDir."
    Write-Step "Dépendances d'exécution requises : fastapi, uvicorn, pydantic, pydantic-settings, PyYAML, Jinja2."
    Write-Step "Avec réseau : $VenvPython -m pip install -e `".[dev]`""
    if ($output) {
        $last = ($output.Trim() -split "`r?`n" | Where-Object { $_ } | Select-Object -Last 1)
        if ($last) { Write-Step "Détail : $last" }
    }
    Stop-Script "Environnement incomplet : corrigez les dépendances puis relancez $ScriptName." 1
}

# -----------------------------------------------------------------------------
# 5. Fichiers locaux : .env et périmètre déclaré
# -----------------------------------------------------------------------------
function New-LocalEnvFile {
    if ($NoEnvFile) {
        Write-Step "-NoEnvFile : aucun fichier .env local créé."
        return
    }
    $envFile = Join-Path (Get-Location) '.env'
    if (Test-Path -LiteralPath $envFile) {
        Write-Ok ".env existant conservé (jamais écrasé par ce script)."
        return
    }

    Write-Info "Création du fichier .env local (développement, ignoré par Git)…"
    $content = @'
# =============================================================================
#  Thot Secure — environnement de DÉVELOPPEMENT local (généré par dev-setup.ps1)
#  Ce fichier est ignoré par Git (.gitignore) et ne doit JAMAIS être versionné.
#  Il ne contient aucun secret partagé : uniquement des réglages locaux.
# =============================================================================
THOT_ENV=dev
THOT_HOST=127.0.0.1
THOT_PORT=8080
THOT_DB_URL=sqlite:///./data/thotsecure.db
THOT_BUS=memory
THOT_LOG_LEVEL=INFO
THOT_LOG_FORMAT=console
THOT_RETENTION_DAYS=30

# --- SÛRETÉ : valeurs par défaut du projet, NE PAS INVERSER -------------------
# THOT_DRY_RUN=true        : aucune contre-mesure n'a d'effet réel.
# THOT_AUTONOMY=supervised : une action critique exige une approbation humaine.
# Le passage au mode réel est une décision d'exploitation écrite et datée, jamais
# un réglage de confort de développement.
THOT_DRY_RUN=true
THOT_AUTONOMY=supervised
'@
    Invoke-Mutation "écriture de $envFile (UTF-8 sans BOM)" {
        # UTF8Encoding($false) plutôt que « -Encoding utf8NoBOM » (PS 7 uniquement) :
        # le script doit fonctionner aussi sous Windows PowerShell 5.1, où
        # « -Encoding utf8 » ajouterait un BOM en tête du premier nom de variable.
        $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
        [System.IO.File]::WriteAllText($envFile, $content, $utf8NoBom)
    }
    if ($DryRun) {
        Write-Ok '.env (dry-run : non créé)'
        return
    }
    # Restriction d'accès au compte courant (équivalent Windows d'un chmod 0600).
    # Non bloquante : un échec d'ACL ne doit pas empêcher de développer.
    try {
        $acl = Get-Acl -LiteralPath $envFile
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList @("$env:USERDOMAIN\$env:USERNAME", 'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -LiteralPath $envFile -AclObject $acl
        Write-Ok '.env créé, accès restreint au compte courant.'
    }
    catch {
        Write-Warn ".env créé, mais la restriction d'accès a échoué : $($_.Exception.Message)"
        Write-Step "Vérifiez les autorisations à la main : icacls `"$envFile`""
    }
}

function Assert-TargetsFile {
    $targets = Join-Path (Get-Location) 'config\targets.yaml'
    $example = Join-Path (Get-Location) 'config\targets.example.yaml'
    if (Test-Path -LiteralPath $targets) {
        Write-Ok "Périmètre déclaré déjà présent : config\targets.yaml"
        return
    }
    if (-not (Test-Path -LiteralPath $example)) {
        Write-Warn "config\targets.example.yaml absent : périmètre non déclaré."
        Write-Step "« thotsecure doctor » signalera l'absence de périmètre (contrôle non critique)."
        return
    }
    Write-Info "Déclaration initiale du périmètre : copie de l'exemple…"
    Invoke-Mutation "Copy-Item $example $targets" {
        Copy-Item -LiteralPath $example -Destination $targets
    }
    Write-Ok "config\targets.yaml créé (ignoré par Git)."
    Write-Warn "ÉDITEZ-LE : c'est la SEULE source de vérité sur ce que Thot Secure a le"
    Write-Warn "droit d'observer et de modifier. Aucune cible n'est devinée automatiquement."
}

# -----------------------------------------------------------------------------
# 6. CLI applicative (toujours avec les garde-fous de sûreté posés)
# -----------------------------------------------------------------------------
function Invoke-ThotCli {
    <#
        Lance la CLI avec THOT_DRY_RUN=true et THOT_AUTONOMY=supervised imposés :
        même si votre environnement dit le contraire, la simulation reste active.
        Utilise « & executable @arguments » — jamais Invoke-Expression.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$VenvPython,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $launcher = Join-Path (Get-Location) (Join-Path $VenvDir 'Scripts\thotsecure.exe')
    $savedDryRun = $env:THOT_DRY_RUN
    $savedAutonomy = $env:THOT_AUTONOMY
    $savedPath = $env:PYTHONPATH
    $env:THOT_DRY_RUN = 'true'
    $env:THOT_AUTONOMY = 'supervised'
    $env:PYTHONPATH = 'src'
    try {
        if ($DryRun) {
            $shown = if (Test-Path -LiteralPath $launcher) { $launcher } else { "$VenvPython -m thotsecure.cli" }
            Write-Host "    [dry-run] $shown $($Arguments -join ' ')" -ForegroundColor DarkGray
            return 0
        }
        if (Test-Path -LiteralPath $launcher) {
            & $launcher @Arguments | Out-Host
        }
        else {
            & $VenvPython -m thotsecure.cli @Arguments | Out-Host
        }
        return $LASTEXITCODE
    }
    finally {
        $env:THOT_DRY_RUN = $savedDryRun
        $env:THOT_AUTONOMY = $savedAutonomy
        $env:PYTHONPATH = $savedPath
    }
}

function Initialize-DevelopmentEnvironment {
    param([Parameter(Mandatory = $true)][string]$VenvPython)

    Write-Info "Initialisation de la base locale…"
    $code = Invoke-ThotCli -VenvPython $VenvPython -Arguments @('init-db')
    if ($code -ne 0) { Stop-Script "init-db a échoué (code $code)." 1 }
    Write-Ok "Base prête (idempotent : relancer ne détruit rien)."

    Write-Info "Tenant de démonstration « $Tenant »…"
    # --mode supervised et simulation active : le tenant de démonstration ne peut
    # pas déclencher d'action réelle, et ses cibles protégées sont explicites.
    $code = Invoke-ThotCli -VenvPython $VenvPython -Arguments @(
        'tenant', 'create',
        '--id', $Tenant,
        '--name', "Démonstration locale ($Tenant)",
        '--mode', 'supervised',
        '--protected', '10.0.0.1', '10.0.0.0/24'
    )
    if ($code -ne 0) { Stop-Script "tenant create a échoué (code $code)." 1 }
    Write-Ok "Tenant « $Tenant » enregistré ou mis à jour (upsert, donc idempotent)."

    if ($NoDemo) {
        Write-Step "-NoDemo : jeu de démonstration non injecté."
    }
    else {
        Write-Info "Injection du jeu de démonstration (événements → findings → actions simulées)…"
        $code = Invoke-ThotCli -VenvPython $VenvPython -Arguments @('demo', '--tenant', $Tenant)
        if ($code -ne 0) { Write-Warn "La démonstration s'est terminée avec le code $code." }
        else { Write-Ok "Démonstration rejouable : les occurrences sont regroupées par règle et par clé." }
    }

    Write-Info "Diagnostic applicatif (thotsecure doctor)…"
    $doctorCode = Invoke-ThotCli -VenvPython $VenvPython -Arguments @('doctor')
    switch ($doctorCode) {
        0 { Write-Ok "Doctor : aucun contrôle critique en échec." }
        3 {
            Write-Warn "Doctor : au moins un contrôle CRITIQUE est en échec (ci-dessus)."
            Write-Step "C'est fréquent sur un dépôt fraîchement cloné : périmètre non déclaré,"
            Write-Step "politiques absentes, ou base non initialisée."
        }
        default { Write-Warn "Doctor s'est terminé avec le code $doctorCode." }
    }
    return $doctorCode
}

function Write-Summary {
    param([Parameter(Mandatory = $true)][string]$VenvPython)

    Write-Host ''
    Write-Host 'Environnement de développement prêt.' -ForegroundColor White
    Write-Host ''
    Write-Host 'Commandes utiles' -ForegroundColor White
    Write-Step "$VenvPython -m uvicorn thotsecure.main:app --host 127.0.0.1 --port 8080 --reload"
    Write-Step '  → API + console : http://127.0.0.1:8080/  (/healthz, /readyz, /metrics)'
    Write-Step ".\$VenvDir\Scripts\thotsecure.exe findings list --tenant $Tenant"
    Write-Step ".\$VenvDir\Scripts\thotsecure.exe audit verify"
    Write-Step "$VenvPython -m unittest discover -s tests -t . -v      (suite de tests, stdlib)"
    Write-Host ''
    Write-Host 'Fichiers créés ou réutilisés' -ForegroundColor White
    Write-Step "$VenvDir\                  environnement virtuel (ignoré par Git)"
    Write-Step '.env                       réglages locaux (accès restreint, ignoré par Git)'
    Write-Step 'config\targets.yaml        périmètre déclaré — À ÉDITER (ignoré par Git)'
    Write-Step 'data\thotsecure.db         base SQLite locale (ignorée par Git)'
    Write-Host ''
    Write-Host 'SÛRETÉ — à ne pas perdre de vue' -ForegroundColor White
    Write-Step '* THOT_DRY_RUN=true et THOT_AUTONOMY=supervised sont les valeurs par défaut.'
    Write-Step '  Ce script ne les a PAS inversées : aucune action réelle n''est possible.'
    Write-Step '* Pour observer un comportement réel, ne désactivez pas la simulation en'
    Write-Step '  développement : utilisez un environnement de recette dédié, une décision'
    Write-Step '  écrite, et des cibles que vous possédez (config\targets.yaml).'
    Write-Step '* Thot Secure est STRICTEMENT DÉFENSIF : aucune capacité offensive, jamais.'
    Write-Step '  Ne l''utilisez que sur des actifs que vous exploitez, et avec autorisation.'
    Write-Step '* Le journal d''audit est chaîné par hash : vérifiez-le avant et après toute'
    Write-Step '  manipulation de données (thotsecure audit verify).'
    Write-Host ''
    Write-Host 'Prochaines lectures : docs/quickstart.md, docs/configuration.md,' -ForegroundColor DarkGray
    Write-Host 'docs/architecture/api-contract.md (contrat gelé), CONTRIBUTING.md.' -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# Point d'entrée
# -----------------------------------------------------------------------------
Write-Host "Thot Secure — $ScriptName $ScriptVersion" -ForegroundColor White
Write-Warn "Lisez ce script avant de l'exécuter : il modifie le dépôt (venv, .env, base locale)."
if ($DryRun) { Write-Warn 'MODE -DryRun : rien ne sera modifié.' }

try {
    $null = Resolve-RepoRoot
    $pythonInfo = Resolve-PythonExe
    Write-Ok "Interpréteur : $($pythonInfo.Display) (Python $($pythonInfo.Version))"

    Write-SafetyWarnings

    $venvPython = New-Venv -PythonInfo $pythonInfo
    $null = Install-Package -VenvPython $venvPython
    Test-Importable -VenvPython $venvPython
    New-LocalEnvFile
    Assert-TargetsFile

    $doctorCode = Initialize-DevelopmentEnvironment -VenvPython $venvPython
    Write-Summary -VenvPython $venvPython

    if ($DryRun) {
        Write-Warn 'Mode -DryRun : aucune modification n''a été appliquée.'
        exit 0
    }
    if ($doctorCode -eq $ExitVerify) {
        Write-Warn 'Environnement fonctionnel, mais le diagnostic signale un point critique (voir ci-dessus).'
        exit $ExitVerify
    }
    Write-Ok 'Terminé.'
    exit 0
}
catch {
    Write-Err "Échec de $ScriptName : $($_.Exception.Message)"
    Write-Err 'Rien n''est cassé : relancez le script après avoir corrigé le point ci-dessus.'
    Write-Err 'L''environnement virtuel et la base existants sont conservés.'
    exit 1
}
