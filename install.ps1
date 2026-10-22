# Orvpass Universal Windows Installer (PowerShell & Windows Terminal)
# Usage:
#   irm https://raw.githubusercontent.com/krtvysinghhhh/Orvpass/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host "⚡ Installing Orvpass CLI (Ultra-Fast Zero-Knowledge Secrets Manager)..." -ForegroundColor Cyan

$Repo = "krtvysinghhhh/Orvpass"
$Tag = "v5.5.0"
$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }

if ($Arch -ne "x86_64") {
    Write-Host "❌ Unsupported 32-bit architecture. Orvpass requires 64-bit Windows." -ForegroundColor Red
    exit 1
}

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\orvpass"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ZipName = "orvpass-$Tag-windows-x86_64.zip"
$Url = "https://github.com/$Repo/releases/download/$Tag/$ZipName"
$TempZip = Join-Path $env:TEMP $ZipName

Write-Host "📥 Fetching Orvpass for Windows ($Tag)..." -ForegroundColor Yellow

$Downloaded = $false
try {
    Invoke-WebRequest -Uri $Url -OutFile $TempZip -UseBasicParsing -TimeoutSec 30
    Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
    Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
    $Downloaded = $true
} catch {
    Write-Host "📦 Pre-built binary release archive not available, checking for cargo..." -ForegroundColor Gray
}

if (-not $Downloaded) {
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Host "🔨 Building Orvpass from source via cargo..." -ForegroundColor Yellow
        cargo install --git "https://github.com/$Repo.git" orvpass-cli
        Write-Host "✨ Orvpass installed successfully via cargo!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "❌ Neither release archive nor cargo was found." -ForegroundColor Red
        Write-Host "👉 Please install Rust from https://rustup.rs or download orvpass.exe directly." -ForegroundColor Yellow
        exit 1
    }
}

# Add to User PATH if not already present
$UserPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "🔧 Adding $InstallDir to User PATH..." -ForegroundColor Cyan
    [System.Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host "✨ Orvpass installed successfully to: $(Join-Path $InstallDir 'orvpass.exe')" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 Getting Started in Windows CMD or PowerShell:" -ForegroundColor Cyan
Write-Host "   orvpass           -> Launch interactive TokyoNight TUI dashboard"
Write-Host "   orvpass --help    -> List all CLI subcommands"
Write-Host "   orvpass which-shell -> Configure Windows shell aliases (doskey / PowerShell)"
