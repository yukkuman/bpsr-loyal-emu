# LoyalBoarlet Monitor - Build & distribution package script
# Usage: .\build.ps1          (release build)
#        .\build.ps1 -Debug   (debug build with console window)
#
# Requirements:
#   - Go 1.23+
#   - MinGW-w64 (GCC) in PATH (e.g. C:\mingw64\bin)
#   - Npcap SDK installed
#     Default: C:\npcap-sdk  (override with -NpcapSdk)
#
# Runtime requirement on target PC:
#   - Npcap (https://npcap.com/) must be installed

param(
    [switch]$Debug,
    [string]$NpcapSdk = "C:\npcap-sdk",
    [string]$OutDir   = ".\release",
    [string]$GccPath  = ""
)

$ErrorActionPreference = "Stop"

# -- Version --
$Version = "1.0.0"
$ExeName = "LoyalBoarlet.exe"
$ZipName = "LoyalBoarlet-v$Version-windows-amd64.zip"

Write-Host "=== LoyalBoarlet Monitor Build ===" -ForegroundColor Cyan
Write-Host "Version : $Version"
Write-Host "Mode    : $(if ($Debug) { 'Debug (with console)' } else { 'Release (no console)' })"
Write-Host ""

# -- Check Npcap SDK --
if (-not (Test-Path "$NpcapSdk\Lib\x64\wpcap.lib")) {
    Write-Error "Npcap SDK not found: $NpcapSdk\Lib\x64\wpcap.lib"
}
Write-Host "[OK] Npcap SDK: $NpcapSdk" -ForegroundColor Green

# -- Check MinGW / GCC --
# If -GccPath is specified, prepend it to PATH
if ($GccPath -ne "" -and (Test-Path $GccPath)) {
    $env:PATH = "$GccPath;$env:PATH"
    Write-Host "[INFO] Added to PATH: $GccPath" -ForegroundColor Gray
}
# Auto-search common GCC locations if not in PATH
$gccFound = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gccFound) {
    $candidates = @(
        "C:\TDM-GCC-64\bin",
        "C:\mingw64\bin",
        "C:\mingw32\bin",
        "C:\msys64\mingw64\bin",
        "C:\msys64\ucrt64\bin",
        "C:\Program Files\Git\usr\bin"
    )
    foreach ($c in $candidates) {
        if (Test-Path "$c\gcc.exe") {
            $env:PATH = "$c;$env:PATH"
            Write-Host "[INFO] Found GCC at: $c" -ForegroundColor Gray
            $gccFound = Get-Command gcc -ErrorAction SilentlyContinue
            break
        }
    }
}
if (-not $gccFound) {
    Write-Error "GCC (MinGW-w64) not found. Specify path with: .\build.ps1 -GccPath C:\mingw64\bin"
}
Write-Host "[OK] GCC: $($gccFound.Source)" -ForegroundColor Green

# -- Prepare output directory --
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory $OutDir | Out-Null
New-Item -ItemType Directory "$OutDir\data" | Out-Null

# -- CGO flags --
$NpcapInc = "$NpcapSdk\Include"
$NpcapLib = "$NpcapSdk\Lib\x64"

$env:CGO_ENABLED   = "1"
$env:GOOS          = "windows"
$env:GOARCH        = "amd64"
$env:CGO_CFLAGS    = "-I`"$NpcapInc`""
$env:CGO_LDFLAGS   = "-L`"$NpcapLib`" -lwpcap"

# -- LD flags --
$ldflags = "-s -w -X main.Version=$Version"
if (-not $Debug) {
    $ldflags += " -H windowsgui"
}

# -- Build --
$exePath = "$OutDir\$ExeName"
Write-Host "Building $ExeName ..." -ForegroundColor Yellow
$buildArgs = @(
    "build",
    "-trimpath",
    "-ldflags", $ldflags,
    "-o", $exePath,
    "."
)
& go @buildArgs
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed (exit $LASTEXITCODE)" }
Write-Host "[OK] Built: $exePath" -ForegroundColor Green

# -- Copy distribution files --
Write-Host "Copying distribution files ..." -ForegroundColor Yellow

if (Test-Path "config.json") {
    Copy-Item "config.json" "$OutDir\config.json"
} elseif (Test-Path "config.example.json") {
    Copy-Item "config.example.json" "$OutDir\config.json"
}

if (Test-Path "data\locations.json") {
    Copy-Item "data\locations.json" "$OutDir\data\locations.json"
}

if (Test-Path "channels.txt") {
    Copy-Item "channels.txt" "$OutDir\channels.txt"
}

$readmeLines = @(
    "LoyalBoarlet Monitor v$Version",
    "===============================",
    "",
    "[Required software]",
    "  Npcap (for network capture)",
    "  Download and install from https://npcap.com/",
    "  Check WinPcap API-compatible Mode during installation.",
    "",
    "[How to run]",
    "  Double-click LoyalBoarlet.exe",
    "",
    "[Config files]",
    "  config.json         - Discord Webhook URL and other settings",
    "  channels.txt        - Channel numbers to patrol (one per line)",
    "  data/locations.json - Map location name data",
    "",
    "[Log]",
    "  Saved to log.txt in the working directory."
)
$readmeLines | Out-File -FilePath "$OutDir\README.txt" -Encoding UTF8

Write-Host "[OK] Files copied to $OutDir\" -ForegroundColor Green

# -- Create ZIP --
$zipPath = ".\$ZipName"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$OutDir\*" -DestinationPath $zipPath
Write-Host "[OK] Archive: $zipPath" -ForegroundColor Green

Write-Host ""
Write-Host "=== Build complete! ===" -ForegroundColor Cyan
Write-Host "  Exe     : $exePath"
Write-Host "  Archive : $zipPath"
Write-Host ""
Write-Host "NOTE: Npcap must be installed on the target PC. https://npcap.com/" -ForegroundColor Yellow