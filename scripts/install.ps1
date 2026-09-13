<#
.SYNOPSIS
    Thot Secure (nom technique du paquet : « thotsecure ») — scripts/install.ps1

.DESCRIPTION
    Installation de Thot Secure sous Windows, à partir d'une archive VÉRIFIÉE.

    Ce que fait ce script, dans l'ordre :
      1. vérifie que le condensé SHA-256 de l'archive correspond à celui attendu ;
         sans condensé de référence, l'installation est REFUSÉE (code 3). Il
         n'existe aucune option pour contourner ce contrôle, volontairement ;
         si une preuve de signature Sigstore (*.sigstore.json) accompagne
         l'archive, elle est vérifiée avec cosign — et un échec est éliminatoire ;
      2. crée les répertoires (programme, données, configuration, journaux,
         sauvegardes) et restreint leurs autorisations (Administrateurs +
         SYSTEM + compte de service) ;
      3. crée un environnement virtuel et y installe le paquet (wheel ou sdist) ;
      4. écrit le fichier d'environnement thotsecure.env (secrets générés
         localement, JAMAIS affichés) ;
      5. génère le lanceur thotsecure.cmd, qui charge ce fichier d'environnement
         puis appelle la CLI — les secrets ne sont donc jamais dans la ligne de
         commande ni dans l'historique ;
      6. initialise la base (thotsecure init-db) ;
      7. affiche les étapes suivantes, avec « thotsecure doctor » et
         l'AVERTISSEMENT sur THOT_DRY_RUN.

    SÛRETÉ — invariant du projet : Thot Secure est STRICTEMENT DÉFENSIF.
      * THOT_DRY_RUN=true et THOT_AUTONOMY=supervised sont écrits par défaut dans
        le fichier d'environnement. Ce script ne les inverse JAMAIS : il se
        contente d'AVERTIR si le fichier les a été modifiés. Aucune action réelle
        n'est exécutée tant que l'exploitant ne l'a pas décidé explicitement ;
      * aucune expression n'est évaluée dynamiquement (pas d'Invoke-Expression) ;
      * aucun secret n'est journalisé : THOT_SECRET_KEY et la clé d'amorçage sont
        générés localement et écrits uniquement dans le fichier d'environnement.

    Codes de sortie : 0 succès, 1 erreur, 2 usage, 3 vérification négative
    (condensé absent ou invalide, signature invalide).

.EXAMPLE
    .\scripts\install.ps1 -Archive .\dist\thotsecure-0.1.0-py3-none-any.whl `
        -Sha256 3f786850e387550fdab836ed7e6dc881de23001b5a8f5b0e1e4f2c8f2c9e0f1a

.EXAMPLE
    # Archive accompagnée de son scellé « <archive>.sha256 » (produit par backup.sh
    # ou téléchargé depuis la release signée) :
    .\scripts\install.ps1 -Archive .\thotsecure-0.1.0.tar.gz

.EXAMPLE
    .\scripts\install.ps1 -Archive .\thotsecure-0.1.0-py3-none-any.whl -DryRun

.NOTES
    Lisez ce script avant de l'exécuter en administrateur : il écrit dans
    ProgramData et crée un environnement Python. Licence Apache-2.0.
#>

[CmdletBinding()]
param(
    # Archive à installer : wheel (.whl), archive source (.tar.gz) ou .zip
    # contenant le paquet. Son condensé SHA-256 EST VÉRIFIÉ avant toute écriture.
    [Parameter(Mandatory = $true, HelpMessage = 'Chemin de l''archive à installer (.whl, .tar.gz, .zip).')]
    [ValidateNotNullOrEmpty()]
    [string]$Archive,

    # Condensé SHA-256 attendu (64 caractères hexadécimaux). À obtenir par un canal
    # indépendant : notes de release signées, manifeste SHA256SUMS, ou « <archive>.sha256 ».
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$Sha256 = '',

    # Fichier contenant le condensé (« <digest>  <nom> » ou condensé seul).
    [string]$Sha256File = '',

    # Répertoire d'installation (programme + venv + lanceur + données).
    # Défaut : %ProgramData%\thotsecure (nécessite les droits d'administration).
    [string]$InstallDir = (Join-Path $env:ProgramData 'thotsecure'),

    # Répertoires dérivés de -InstallDir si vous ne les précisez pas.
    [string]$DataDir = '',
    [string]$EtcDir = '',
    [string]$LogDir = '',
    [string]$BackupDir = '',
    [string]$BinDir = '',

    # Interpréteur Python >= 3.11 pour créer l'environnement virtuel.
    # Vide = détection automatique (py -3.11, py -3, python).
    [string]$Python = '',

    # Compte qui exécutera le service (ex. « CONTOSO\svc-thotsecure »). Vide = le
    # compte courant. Ce compte reçoit la lecture de la configuration et
    # l'écriture sur les données ; jamais plus.
    [string]$ServiceAccount = '',

    # Port d'écoute écrit dans le fichier d'environnement.
    [ValidateRange(1, 65535)]
    [int]$Port = 8080,

    # Installer le paquet sans ses dépendances (environnement hors ligne).
    [switch]$NoDeps,

    # Ne pas exécuter « thotsecure init-db ».
    [switch]$NoInitDb,

    # Ne pas créer le fichier d'environnement (vous le fournissez autrement).
    [switch]$NoEnvFile,

    # Ajouter le répertoire des binaires au PATH de l'utilisateur courant.
    [switch]$AddToPath,

    # Écraser une installation existante sans demander confirmation.
    [switch]$Force,

    # Ne poser aucune question (automatisation).
    [switch]$Yes,

    # Vérifier et afficher le plan, sans rien installer.
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptName = 'install.ps1'
$ScriptVersion = '0.1.0'
$ExitUsage = 2
$ExitVerify = 3
$VenvDirName = 'venv'
$EnvFileName = 'thotsecure.env'
$LauncherName = 'thotsecure.cmd'
$TempRoot = ''

# -----------------------------------------------------------------------------
# Journalisation (mêmes codes couleur que scripts/install.sh)
# -----------------------------------------------------------------------------
function Write-Info  { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Message) Write-Host "  ok $Message" -ForegroundColor Green }
function Write-Warn  { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err   { param([string]$Message) Write-Host "[x] $Message" -ForegroundColor Red }
function Write-Step  { param([string]$Message) Write-Host "    $Message" -ForegroundColor DarkGray }

function Stop-Script {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [int]$Code = 1
    )
    Write-Err $Message
    exit $Code
}

function Invoke-Mutation {
    <# Exécute une opération qui MODIFIE le système, ou l'affiche en -DryRun. #>
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

function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-Confirmation {
    param([Parameter(Mandatory = $true)][string]$Prompt)
    if ($Yes) {
        Write-Warn "$Prompt -> confirmé par -Yes."
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

function New-Secret {
    <# 32 octets aléatoires cryptographiques, en hexadécimal : jamais affichés. #>
    param([int]$Bytes = 32)
    $buffer = New-Object -TypeName 'byte[]' -ArgumentList $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    }
    finally {
        $rng.Dispose()
    }
    return ($buffer | ForEach-Object { $_.ToString('x2') }) -join ''
}

# -----------------------------------------------------------------------------
# 1. Résolution des chemins et vérification de l'hôte
# -----------------------------------------------------------------------------
function Resolve-Layout {
    if (-not $DataDir)     { $script:DataDir = Join-Path $InstallDir 'data' }
    if (-not $EtcDir)      { $script:EtcDir = Join-Path $InstallDir 'etc' }
    if (-not $LogDir)      { $script:LogDir = Join-Path $InstallDir 'log' }
    if (-not $BackupDir)   { $script:BackupDir = Join-Path $InstallDir 'backups' }
    if (-not $BinDir)      { $script:BinDir = Join-Path $InstallDir 'bin' }

    $script:VenvDir = Join-Path $InstallDir $VenvDirName
    $script:VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
    $script:EnvFilePath = Join-Path $EtcDir $EnvFileName
    $script:LauncherPath = Join-Path $BinDir $LauncherName
    # Convention SQLite côté produit : sqlite:///C:/chemin/absolu.db (barres obliques).
    $dbPath = (Join-Path $DataDir 'thotsecure.db') -replace '\\', '/'
    $script:DbPath = $dbPath
    $script:DbUrl = "sqlite:///$dbPath"
}

function Assert-Prerequisites {
    if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
        Stop-Script "Archive introuvable : $Archive" $ExitUsage
    }
    $script:Archive = (Resolve-Path -LiteralPath $Archive).Path

    if (-not (Test-Administrator)) {
        $underProgramData = $InstallDir -like "$env:ProgramData*"
        if ($underProgramData -and -not $DryRun) {
            Stop-Script "Ce script écrit dans $InstallDir : relancez PowerShell en tant qu'administrateur, ou choisissez un répertoire d'utilisateur (-InstallDir `"$env:LOCALAPPDATA\thotsecure`")." 1
        }
        Write-Warn "Droits d'administration absents : l'installation pourrait échouer."
        Write-Step "Relancez « en tant qu'administrateur » pour une installation machine."
    }

    if ($ServiceAccount) {
        Write-Step "Compte de service déclaré : $ServiceAccount"
    }
    else {
        Write-Step "Compte de service : compte courant ($env:USERDOMAIN\$env:USERNAME)"
    }
}

# -----------------------------------------------------------------------------
# 2. VÉRIFICATION DU CONDENSÉ SHA-256 (étape non contournable)
# -----------------------------------------------------------------------------
function Resolve-ExpectedDigest {
    <# Ordre de priorité : -Sha256, puis -Sha256File, puis « <archive>.sha256 ». #>
    if ($Sha256) {
        Write-Step "Condensé de référence : fourni par -Sha256."
        return $Sha256.ToLowerInvariant()
    }

    if ($Sha256File) {
        if (-not (Test-Path -LiteralPath $Sha256File -PathType Leaf)) {
            Stop-Script "Fichier de condensés introuvable : $Sha256File" $ExitVerify
        }
        $line = Get-Content -LiteralPath $Sha256File | Where-Object { $_.Trim() } | Select-Object -First 1
        if (-not $line) { Stop-Script "Fichier de condensés vide : $Sha256File" $ExitVerify }
        $candidate = ($line.Trim() -split '\s+')[0]
        if ($candidate -notmatch '^[0-9a-fA-F]{64}$') {
            Stop-Script "Le fichier $Sha256File ne contient pas de condensé SHA-256 exploitable." $ExitVerify
        }
        Write-Step "Condensé de référence : lu dans $Sha256File."
        return $candidate.ToLowerInvariant()
    }

    $sidecar = "$Archive.sha256"
    if (Test-Path -LiteralPath $sidecar -PathType Leaf) {
        $line = Get-Content -LiteralPath $sidecar | Where-Object { $_.Trim() } | Select-Object -First 1
        $candidate = ($line.Trim() -split '\s+')[0]
        if ($candidate -notmatch '^[0-9a-fA-F]{64}$') {
            Stop-Script "Le scellé $sidecar ne contient pas de condensé SHA-256 exploitable." $ExitVerify
        }
        Write-Step "Condensé de référence : lu dans $(Split-Path -Leaf $sidecar)."
        return $candidate.ToLowerInvariant()
    }

    Write-Err 'AUCUN CONDENSÉ DE RÉFÉRENCE pour cette archive.'
    Write-Step 'Sans condensé, rien ne prouve que l''archive n''a pas été altérée.'
    Write-Step 'Fournissez le condensé publié avec la release, par un canal indépendant :'
    Write-Step '  -Sha256 <hex>            (64 caractères hexadécimaux)'
    Write-Step '  -Sha256File <fichier>    (manifeste SHA256SUMS)'
    Write-Step '  ou déposez « <archive>.sha256 » à côté de l''archive.'
    Stop-Script "Installation REFUSÉE : condensé de vérification absent." $ExitVerify
}

function Assert-Checksum {
    $expected = Resolve-ExpectedDigest
    Write-Info "Contrôle du condensé SHA-256 de $(Split-Path -Leaf $Archive)..."

    if ($DryRun) {
        Write-Host "    [dry-run] Get-FileHash -Algorithm SHA256 `"$Archive`"" -ForegroundColor DarkGray
        Write-Step "attendu : $expected"
        return
    }

    $actual = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        Write-Err "CONDENSÉ SHA-256 INVALIDE pour $(Split-Path -Leaf $Archive)."
        Write-Step "attendu : $expected"
        Write-Step "obtenu  : $actual"
        Write-Err "REFUS D'INSTALLER : l'archive est corrompue, tronquée ou remplacée."
        Write-Step 'Ne l''utilisez pas. Récupérez-la depuis la release officielle et signalez'
        Write-Step "l'incident via le canal indiqué dans SECURITY.md."
        Stop-Script 'Vérification du condensé échouée.' $ExitVerify
    }
    Write-Ok "Condensé SHA-256 vérifié : $actual"
}

function Test-Signature {
    <#
        Si une preuve Sigstore accompagne l'archive, elle est vérifiée : la
        signature keyless lie l'artefact à l'identité OIDC du dépôt. Un échec est
        éliminatoire. Sans preuve, on le dit clairement — le condensé seul prouve
        l'intégrité, pas l'origine.
    #>
    $bundle = "$Archive.sigstore.json"
    if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) {
        Write-Warn "Aucune preuve de signature Sigstore à côté de l'archive."
        Write-Step 'Le condensé vérifie l''intégrité, PAS l''origine. Pour un déploiement'
        Write-Step 'réel, préférez l''artefact accompagné de son *.sigstore.json, puis :'
        Write-Step '  cosign verify-blob --bundle <archive>.sigstore.json `'
        Write-Step '    --certificate-identity-regexp "^https://github.com/thotsecure/thot-secure/" `'
        Write-Step '    --certificate-oidc-issuer https://token.actions.githubusercontent.com <archive>'
        return
    }

    Write-Info 'Preuve de signature Sigstore détectée : vérification avec cosign...'
    $cosign = Get-Command 'cosign' -ErrorAction SilentlyContinue
    if (-not $cosign) {
        Write-Err "Une preuve de signature est présente ($(Split-Path -Leaf $bundle)) mais cosign est absent."
        Write-Step 'Installez cosign (https://docs.sigstore.dev/cosign/installation/) puis relancez.'
        Write-Step 'La vérification de signature est obligatoire lorsqu''une preuve est fournie.'
        Stop-Script 'cosign est requis pour vérifier cette archive.' $ExitVerify
    }

    if ($DryRun) {
        Write-Host "    [dry-run] cosign verify-blob --bundle `"$bundle`" `"$Archive`"" -ForegroundColor DarkGray
        return
    }

    & $cosign.Source 'verify-blob' `
        '--bundle' $bundle `
        '--certificate-identity-regexp' '^https://github.com/thotsecure/thot-secure/' `
        '--certificate-oidc-issuer' 'https://token.actions.githubusercontent.com' `
        $Archive | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Err "SIGNATURE SIGSTORE INVALIDE : REFUS D'INSTALLER $(Split-Path -Leaf $Archive)."
        Stop-Script 'Vérification de signature échouée.' $ExitVerify
    }
    Write-Ok 'Signature Sigstore vérifiée (identité OIDC du dépôt thotsecure/thot-secure).'
}

# -----------------------------------------------------------------------------
# 3. Répertoires et autorisations restreintes
# -----------------------------------------------------------------------------
function Protect-Path {
    <#
        Retire l'héritage et n'autorise que les Administrateurs, SYSTEM et (en
        lecture ou modification selon le cas) le compte de service. Les SID sont
        utilisés plutôt que des noms : ils fonctionnent sur un Windows localisé.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Read', 'Modify')][string]$ServiceRight
    )
    if ($DryRun) {
        Write-Host "    [dry-run] icacls `"$Path`" /inheritance:r /grant:r Administrateurs+SYSTEM+$ServiceAccount" -ForegroundColor DarkGray
        return
    }
    try {
        $right = if ($ServiceRight -eq 'Modify') { 'M' } else { 'R' }
        $account = if ($ServiceAccount) { $ServiceAccount } else { "$env:USERDOMAIN\$env:USERNAME" }
        $null = & icacls $Path /inheritance:r /grant:r `
            '*S-1-5-32-544:(OI)(CI)F' `
            '*S-1-5-18:(OI)(CI)F' `
            "${account}:(OI)(CI)$right" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Autorisations non restreintes sur $Path (icacls a renvoyé $LASTEXITCODE)."
            Write-Step "Vérifiez à la main : icacls `"$Path`""
        }
    }
    catch {
        Write-Warn "Autorisations non restreintes sur ${Path} : $($_.Exception.Message)"
        Write-Step "Un système de fichiers non NTFS (FAT32/exFAT) ne gère pas les ACL."
    }
}

function New-Layout {
    Write-Info 'Création des répertoires...'
    $directories = @(
        @{ Path = $InstallDir; Right = 'Modify' },
        @{ Path = $DataDir;    Right = 'Modify' },
        @{ Path = (Join-Path $DataDir 'quarantine'); Right = 'Modify' },
        @{ Path = $EtcDir;     Right = 'Read' },
        @{ Path = $LogDir;     Right = 'Modify' },
        @{ Path = $BackupDir;  Right = 'Modify' },
        @{ Path = $BinDir;     Right = 'Read' }
    )
    foreach ($directory in $directories) {
        Invoke-Mutation "New-Item -ItemType Directory $($directory.Path)" {
            if (-not (Test-Path -LiteralPath $directory.Path)) {
                $null = New-Item -ItemType Directory -Path $directory.Path -Force
            }
        }
        Protect-Path -Path $directory.Path -ServiceRight $directory.Right
        Write-Step "$($directory.Path)  ($($directory.Right))"
    }
    Write-Ok 'Répertoires prêts : programme, données, configuration, journaux, sauvegardes.'
}

# -----------------------------------------------------------------------------
# 4. Archive : extraction, environnement virtuel, installation
# -----------------------------------------------------------------------------
function Expand-Payload {
    <# Extrait l'archive dans un répertoire temporaire et retourne ce répertoire. #>
    $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("thotsecure-install-" + [Guid]::NewGuid().ToString('N'))
    $extractDir = Join-Path $TempRoot 'payload'

    if ($DryRun) {
        Write-Host "    [dry-run] extraction de $(Split-Path -Leaf $Archive) vers $extractDir" -ForegroundColor DarkGray
        return $extractDir
    }

    $null = New-Item -ItemType Directory -Path $extractDir -Force
    $leaf = Split-Path -Leaf $Archive

    if ($leaf -match '\.(whl|pyz)$') {
        # Un wheel ne s'extrait pas : pip l'installe directement.
        Copy-Item -LiteralPath $Archive -Destination (Join-Path $extractDir $leaf)
        return $extractDir
    }
    if ($leaf -match '\.zip$') {
        Expand-Archive -LiteralPath $Archive -DestinationPath $extractDir -Force
        return $extractDir
    }
    if ($leaf -match '\.(tar\.gz|tgz|tar\.bz2|tar\.xz|tar)$') {
        $tar = Get-Command 'tar' -ErrorAction SilentlyContinue
        if (-not $tar) {
            Stop-Script "« tar » est requis pour extraire $leaf (présent nativement depuis Windows 10 1803)." 1
        }
        & $tar.Source '-xzf' $Archive '-C' $extractDir | Out-Host
        if ($LASTEXITCODE -ne 0) { Stop-Script "Extraction impossible : $leaf (code $LASTEXITCODE)." 1 }
        return $extractDir
    }
    Stop-Script "Format d'archive non géré : $leaf (attendu : .whl, .tar.gz, .zip)." $ExitUsage
}

function Resolve-PythonExe {
    <# Retourne la commande à utiliser (tableau) pour créer l'environnement virtuel. #>
    $candidates = @()
    if ($Python) { $candidates += ,@($Python) }
    $candidates += ,@('py', '-3.11')
    $candidates += ,@('py', '-3')
    $candidates += ,@('python')

    foreach ($candidate in $candidates) {
        $command = Get-Command $candidate[0] -ErrorAction SilentlyContinue
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
        if (-not $version -or $version -notmatch '^\d+\.\d+$') { continue }
        $parts = $version.Split('.')
        if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 11)) {
            Write-Warn "Python $version est trop ancien (>= 3.11 requis) : candidat ignoré."
            continue
        }
        return @{ Exe = $candidate; Display = ($candidate -join ' '); Version = $version }
    }
    Stop-Script 'Aucun interpréteur Python >= 3.11 trouvé. Installez Python (python.org) ou passez -Python <chemin>.' 1
}

function Install-IntoVenv {
    param(
        [Parameter(Mandatory = $true)][string]$ExtractDir,
        [Parameter(Mandatory = $true)][hashtable]$PythonInfo
    )

    $wheel = Get-ChildItem -LiteralPath $ExtractDir -Filter '*.whl' -File -ErrorAction SilentlyContinue |
        Sort-Object Name | Select-Object -First 1
    $sdist = Get-ChildItem -LiteralPath $ExtractDir -Recurse -Filter 'pyproject.toml' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    $native = Get-ChildItem -LiteralPath $ExtractDir -Recurse -Include 'thotsecure.exe', 'thotsecure' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1

    Write-Info "Création de l'environnement virtuel dans $VenvDir..."
    Invoke-Mutation "$($PythonInfo.Display) -m venv $VenvDir" {
        $exe = $PythonInfo.Exe[0]
        $extra = @()
        if ($PythonInfo.Exe.Count -gt 1) { $extra = $PythonInfo.Exe[1..($PythonInfo.Exe.Count - 1)] }
        & $exe @extra '-m' 'venv' $VenvDir | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "python -m venv a échoué (code $LASTEXITCODE)." }
    }
    if ($DryRun) { return }

    if ($wheel) {
        Write-Info "Installation du wheel $(Split-Path -Leaf $wheel.FullName)..."
        $pipArgs = @('-m', 'pip', 'install')
        if ($NoDeps) {
            $pipArgs += @('--no-deps')
            Write-Warn '-NoDeps : les dépendances (fastapi, uvicorn, pydantic, PyYAML, Jinja2) doivent déjà être présentes.'
        }
        $pipArgs += $wheel.FullName
        & $VenvPython @pipArgs | Out-Host
        if ($LASTEXITCODE -ne 0) { Stop-Script "Installation du wheel impossible (code $LASTEXITCODE)." 1 }
        Write-Ok 'Paquet installé dans l''environnement virtuel.'
        return
    }

    if ($sdist) {
        $projectDir = Split-Path -Parent $sdist.FullName
        Write-Info "Installation depuis les sources ($projectDir)..."
        $pipArgs = @('-m', 'pip', 'install')
        if ($NoDeps) { $pipArgs += @('--no-deps', '--no-build-isolation') }
        $pipArgs += $projectDir
        & $VenvPython @pipArgs | Out-Host
        if ($LASTEXITCODE -ne 0) { Stop-Script "Installation depuis les sources impossible (code $LASTEXITCODE)." 1 }
        Write-Ok 'Paquet installé dans l''environnement virtuel.'
        return
    }

    if ($native) {
        # Archive binaire autonome : rien à installer dans le venv. Le lanceur
        # l'appellera directement ; l'environnement virtuel reste disponible pour
        # « python -m uvicorn », utile si vous servez l'application autrement.
        Write-Warn "Archive binaire détectée ($(Split-Path -Leaf $native.FullName)) : copie vers $BinDir."
        Invoke-Mutation "Copy-Item $($native.FullName) $BinDir" {
            Copy-Item -LiteralPath $native.FullName -Destination (Join-Path $BinDir $native.Name) -Force
        }
        $script:NativeBinary = Join-Path $BinDir $native.Name
        Write-Ok "Binaire installé : $script:NativeBinary"
        return
    }

    Stop-Script "Aucun paquet Python (wheel, pyproject.toml) ni binaire thotsecure dans $(Split-Path -Leaf $Archive)." 1
}

# -----------------------------------------------------------------------------
# 5. Fichier d'environnement et lanceur
# -----------------------------------------------------------------------------
function New-EnvironmentFile {
    if ($NoEnvFile) {
        Write-Step '-NoEnvFile : fichier d''environnement non créé (vous le fournissez).'
        return
    }

    Write-Info "Fichier d'environnement $EnvFilePath (accès restreint)..."
    if ($DryRun) {
        Write-Host "    [dry-run] écriture de $EnvFilePath (THOT_SECRET_KEY générée localement, jamais affichée)" -ForegroundColor DarkGray
        return
    }

    $secretKey = New-Secret
    $bootstrapKey = 'ao_' + (New-Secret 24)
    $rulesDir = (Join-Path $EtcDir 'rules') -replace '\\', '/'
    $policiesDir = (Join-Path $EtcDir 'policies') -replace '\\', '/'
    $playbooksDir = (Join-Path $EtcDir 'playbooks') -replace '\\', '/'
    $targetsFile = (Join-Path $EtcDir 'targets.yaml') -replace '\\', '/'

    $content = @"
# =============================================================================
#  Thot Secure — environnement du service (généré par $ScriptName)
#  Fichier protégé : accès restreint (Administrateurs, SYSTEM, compte de service).
#  Ne le versionnez JAMAIS dans Git. Les secrets ci-dessous ne sont affichés nulle part.
# =============================================================================
THOT_ENV=prod
THOT_HOST=127.0.0.1
THOT_PORT=$Port
THOT_DB_URL=$DbUrl
THOT_BUS=sqlite
THOT_RULES_DIR=$rulesDir
THOT_POLICIES_DIR=$policiesDir
THOT_PLAYBOOKS_DIR=$playbooksDir
THOT_TARGETS_FILE=$targetsFile
THOT_LOG_LEVEL=INFO
THOT_LOG_FORMAT=json
THOT_RETENTION_DAYS=30

# --- SÛRETÉ : valeurs par défaut du projet, NE PAS INVERSER ------------------
# THOT_DRY_RUN=true : aucune action réelle, tout est simulé et journalisé.
# THOT_AUTONOMY=supervised : une action critique exige une approbation humaine.
# Le passage en réel est une décision écrite et datée, jamais un défaut.
THOT_DRY_RUN=true
THOT_AUTONOMY=supervised

# --- Secrets (générés localement, jamais journalisés) ------------------------
THOT_SECRET_KEY=$secretKey
THOT_BOOTSTRAP_API_KEY=$bootstrapKey
"@

    Invoke-Mutation "écriture de $EnvFilePath (UTF-8 sans BOM)" {
        # UTF8Encoding($false) plutôt que « -Encoding utf8NoBOM » (PS 7 uniquement) :
        # le script doit fonctionner aussi sous Windows PowerShell 5.1, où
        # « -Encoding utf8 » ajouterait un BOM en tête du fichier d'environnement.
        $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
        [System.IO.File]::WriteAllText($EnvFilePath, $content, $utf8NoBom)
    }
    Protect-Path -Path $EnvFilePath -ServiceRight 'Read'
    $secretKey = $null
    $bootstrapKey = $null
    Write-Ok 'Environnement écrit avec des secrets générés localement (non affichés).'

    # Le fichier de règles/politiques/playbooks est copié en lecture seule depuis
    # l'installation si le dépôt est présent à côté de l'archive.
    $repoRoot = Split-Path -Parent $PSScriptRoot
    foreach ($name in @('rules', 'policies', 'playbooks')) {
        $source = Join-Path $repoRoot $name
        if (Test-Path -LiteralPath $source) {
            $destination = Join-Path $EtcDir $name
            Invoke-Mutation "Copy-Item $source -> $destination (lecture seule)" {
                $null = New-Item -ItemType Directory -Path $destination -Force
                Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse -Force
            }
            Protect-Path -Path $destination -ServiceRight 'Read'
            Write-Step "$name : contenu déclaratif installé en lecture seule."
        }
        else {
            Write-Warn "$name introuvable à côté du script : configurez THOT_*_DIR vous-même."
        }
    }
}

function New-Launcher {
    <#
        Génère le lanceur thotsecure.cmd : il charge le fichier d'environnement
        (secrets compris) puis appelle la CLI. Les secrets ne figurent donc jamais
        dans une ligne de commande, un historique de shell ou un « ps ».
    #>
    Write-Info "Lanceur $LauncherName..."
    $target = if ($NativeBinary) { $NativeBinary } else { '' }

    $launcher = @"
@echo off
rem ===========================================================================
rem  Lanceur Thot Secure (genere par $ScriptName $ScriptVersion)
rem  Charge le fichier d'environnement (secrets inclus) puis appelle la CLI.
rem  Ne modifiez PAS les reglages ici : editez $EnvFilePath
rem  THOT_DRY_RUN=true et THOT_AUTONOMY=supervised restent les valeurs par defaut.
rem  Pas d'expansion differee (EnableDelayedExpansion) : une valeur contenant
rem  un point d'exclamation ne doit pas etre tronquee silencieusement.
rem ===========================================================================
setlocal EnableExtensions
set "THOT_HOME=$InstallDir"
set "THOT_ENV_FILE=$EnvFilePath"
if exist "%THOT_ENV_FILE%" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%THOT_ENV_FILE%") do set "%%~A=%%~B"
) else (
  echo [!] Fichier d'environnement introuvable : %THOT_ENV_FILE% 1>&2
  echo [!] Les secrets ne sont pas charges : la CLI peut echouer. 1>&2
)
if /i "%THOT_DRY_RUN%"=="false" (
  echo [!] ATTENTION : THOT_DRY_RUN=false - les contre-mesures peuvent avoir un effet reel. 1>&2
)
if /i "%THOT_AUTONOMY%"=="auto" (
  echo [!] ATTENTION : THOT_AUTONOMY=auto - des actions peuvent etre executees sans approbation. 1>&2
)
"@

    if ($target) {
        $launcher += "`r`n`"$target`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    }
    else {
        $launcher += "`r`n`"$VenvPython`" -m thotsecure.cli %*`r`nexit /b %ERRORLEVEL%`r`n"
    }

    if ($DryRun) {
        Write-Host "    [dry-run] écriture de $LauncherPath" -ForegroundColor DarkGray
        return
    }
    Set-Content -LiteralPath $LauncherPath -Value $launcher -Encoding ascii
    Write-Ok "Lanceur installé : $LauncherPath"

    # Lanceur complémentaire pour le service (uvicorn en premier plan).
    $serveScript = Join-Path $BinDir 'thotsecure-serve.cmd'
    $serveContent = @"
@echo off
rem Demarre l'API et la console en premier plan (a lancer par un planificateur de
rem taches, NSSM, ou dans une session dediee). Port pilote par THOT_PORT.
rem THOT_DRY_RUN=true et THOT_AUTONOMY=supervised restent les valeurs par defaut
rem du fichier d'environnement : ce lanceur ne les inverse pas.
setlocal EnableExtensions
set "THOT_ENV_FILE=$EnvFilePath"
if exist "%THOT_ENV_FILE%" for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%THOT_ENV_FILE%") do set "%%~A=%%~B"
"$VenvPython" -m uvicorn thotsecure.main:app --host %THOT_HOST% --port %THOT_PORT% --proxy-headers
exit /b %ERRORLEVEL%
"@
    Set-Content -LiteralPath $serveScript -Value $serveContent -Encoding ascii
    Write-Step "Service (premier plan) : $serveScript"

    if ($AddToPath) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($userPath -notlike "*$BinDir*") {
            Invoke-Mutation "ajout de $BinDir au PATH de l'utilisateur" {
                $newPath = if ($userPath) { "$userPath;$BinDir" } else { $BinDir }
                [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            }
            Write-Ok "PATH utilisateur mis à jour (nouvelle session requise) : $BinDir"
        }
        else {
            Write-Step "$BinDir est déjà dans le PATH de l'utilisateur."
        }
    }
    else {
        Write-Step "Pour appeler « thotsecure » depuis n'importe où : -AddToPath, ou ajoutez $BinDir au PATH."
    }
}

# -----------------------------------------------------------------------------
# 6. Initialisation de la base
# -----------------------------------------------------------------------------
function Initialize-Database {
    if ($NoInitDb) {
        Write-Step '-NoInitDb : initialisation de la base ignorée.'
        return
    }
    Write-Info 'Initialisation de la base SQLite...'
    if ($DryRun) {
        Write-Host "    [dry-run] $LauncherPath init-db" -ForegroundColor DarkGray
        return
    }
    & $LauncherPath 'init-db' | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "init-db a échoué (code $LASTEXITCODE) : relancez-le après vérification."
        Write-Step "  $LauncherPath init-db"
        return
    }
    Write-Ok 'Base initialisée (ou déjà à jour).'
}

# -----------------------------------------------------------------------------
# 7. Étapes suivantes et avertissements de sûreté
# -----------------------------------------------------------------------------
function Write-NextSteps {
    Write-Host ''
    Write-Host 'Installation terminée.' -ForegroundColor White
    Write-Host ''
    Write-Host "1. Diagnostic de l'installation" -ForegroundColor White
    Write-Step "$LauncherPath doctor"
    Write-Step '(code de sortie 3 = au moins un contrôle critique en échec)'
    Write-Host ''
    Write-Host '2. Créer un tenant et une clé API (la clé n''est affichée QU''UNE FOIS)' -ForegroundColor White
    Write-Step "$LauncherPath tenant create --id acme --name `"ACME SAS`" --mode supervised"
    Write-Step "$LauncherPath key create --tenant acme --role responder --label poste-admin"
    Write-Host ''
    Write-Host '3. Servir l''API et la console' -ForegroundColor White
    Write-Step "$LauncherPath serve            (boucle locale : http://127.0.0.1:$Port/)"
    Write-Step "http://127.0.0.1:$Port/healthz    sonde de vie ; /readyz : base + bus + règles"
    Write-Step "$(Join-Path $BinDir 'thotsecure-serve.cmd')   (premier plan, pour un planificateur de tâches)"
    Write-Step 'Windows ne fournit pas de superviseur natif pour un service Python :'
    Write-Step 'utilisez le Planificateur de tâches (« au démarrage »), NSSM, ou Docker/WSL2.'
    Write-Host ''
    Write-Host 'SÛRETÉ — à ne pas perdre de vue' -ForegroundColor White
    Write-Step '* Thot Secure est STRICTEMENT DÉFENSIF : aucune capacité offensive, jamais.'
    Write-Step "* THOT_DRY_RUN=true et THOT_AUTONOMY=supervised sont les valeurs par défaut"
    Write-Step "  de $EnvFilePath : ce script ne les a PAS inversées."
    Write-Step '* Si vous les modifiez, vous autorisez des contre-mesures RÉELLES sur des'
    Write-Step '  systèmes réels. Ce doit être une décision écrite, datée et approuvée, avec'
    Write-Step '  des cibles déclarées dans targets.yaml (aucune cible n''est devinée).'
    Write-Step '* Le lanceur affiche un avertissement à chaque appel si ces garde-fous ont'
    Write-Step '  été modifiés : ne le supprimez pas.'
    Write-Step '* Vérifiez la chaîne d''audit après toute manipulation :'
    Write-Step "  $LauncherPath audit verify      (code 3 = chaîne rompue : incident)"
    Write-Step '* Coupez l''accès réseau direct au port si vous n''utilisez pas TLS :'
    Write-Step "  THOT_HOST=127.0.0.1 dans $EnvFilePath, puis publiez via un reverse-proxy HTTPS."
    Write-Step '* Secrets : uniquement dans le fichier d''environnement. Jamais dans Git,'
    Write-Step '  un ticket, une ligne de commande ou un message.'
    Write-Host ''
    Write-Host 'Prochaines lectures : docs/installation.md, docs/configuration.md,' -ForegroundColor DarkGray
    Write-Host 'docs/operations/deployment.md et SECURITY.md (canal de signalement).' -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# Point d'entrée
# -----------------------------------------------------------------------------
Write-Host "Thot Secure — $ScriptName $ScriptVersion" -ForegroundColor White
Write-Warn "Lisez ce script avant de l'exécuter en administrateur."
Write-Info 'Thot Secure est strictement défensif : aucune capacité offensive, jamais.'
if ($DryRun) { Write-Warn 'MODE -DryRun : le système ne sera pas modifié.' }

$script:NativeBinary = ''

try {
    Resolve-Layout
    Assert-Prerequisites

    # 1) Vérification AVANT toute écriture : condensé, puis signature si fournie.
    Assert-Checksum
    Test-Signature

    Write-Host ''
    Write-Info "Plan d'installation :"
    Write-Step "archive      : $(Split-Path -Leaf $Archive)  ($([math]::Round((Get-Item -LiteralPath $Archive).Length / 1KB, 1)) Kio)"
    Write-Step "programme    : $InstallDir"
    Write-Step "données      : $DataDir  (base : $DbPath)"
    Write-Step "environnement: $EnvFilePath  (secrets générés localement)"
    Write-Step "lanceur      : $LauncherPath"
    if (-not $DryRun -and (Test-Path -LiteralPath $LauncherPath) -and -not $Force) {
        if (-not (Read-Confirmation "Une installation existe déjà dans $InstallDir : la remplacer ?")) {
            Write-Warn 'Installation annulée : rien n''a été modifié.'
            exit 0
        }
    }

    # 2) Répertoires protégés.
    New-Layout

    # 3) Extraction et installation dans un environnement virtuel.
    $extractDir = Expand-Payload
    $pythonInfo = Resolve-PythonExe
    Write-Ok "Interpréteur : $($pythonInfo.Display) (Python $($pythonInfo.Version))"
    Install-IntoVenv -ExtractDir $extractDir -PythonInfo $pythonInfo

    # 4) Fichier d'environnement, puis lanceur qui le charge.
    New-EnvironmentFile
    New-Launcher

    # 5) Base initialisée via le lanceur (donc avec les bons secrets).
    Initialize-Database

    Write-NextSteps

    if ($DryRun) {
        Write-Warn 'Mode -DryRun : aucune modification n''a été appliquée.'
    }
    exit 0
}
catch {
    Write-Err "Échec de $ScriptName : $($_.Exception.Message)"
    Write-Err 'Aucune modification n''a été appliquée au-delà de l''étape en cours.'
    Write-Step "Détail : $($_.ScriptStackTrace)"
    exit 1
}
finally {
    if ($TempRoot -and (Test-Path -LiteralPath $TempRoot)) {
        try {
            Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Step "Répertoire temporaire non supprimé : $TempRoot"
        }
    }
}
