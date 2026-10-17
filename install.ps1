# MCP-Shield Windows Quick Installer
# Usage: irm https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

Write-Host "🛡️ Installing mcp-sentinel for Windows..." -ForegroundColor Cyan

$Repo = "joutvhu/mcp-sentinel"
$InstallDir = "$env:LOCALAPPDATA\Programs\mcp-sentinel"
$BinName = "mcp-sentinel.exe"
$TargetPath = Join-Path $InstallDir $BinName

# Determine CPU Architecture
$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
if ($Arch -ne "x86_64") {
    Write-Error "Unsupported architecture: $Arch. Only 64-bit Windows is supported."
    exit 1
}

# Fetch latest release info from GitHub
Write-Host "Fetching latest release information..." -ForegroundColor Yellow
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $ReleaseInfo = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "mcp-sentinel-installer" }
    $Version = $ReleaseInfo.tag_name
} catch {
    Write-Host "Warning: Could not query latest release tag from GitHub API, falling back to latest download URL." -ForegroundColor DarkYellow
    $Version = "latest"
}

$AssetFilename = "mcp-sentinel-x86_64-pc-windows-msvc.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetFilename"
if ($Version -eq "latest") {
    $DownloadUrl = "https://github.com/$Repo/releases/latest/download/$AssetFilename"
}

# Create installation directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$TempZip = Join-Path $env:TEMP "mcp-sentinel-windows.zip"
Write-Host "Downloading $AssetFilename ($Version)..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing

Write-Host "Extracting binary..." -ForegroundColor Yellow
Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
Remove-Item -Path $TempZip -Force

# Add to User PATH if not present
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "Adding $InstallDir to User PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", [EnvironmentVariableTarget]::User)
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host "`n✅ mcp-sentinel successfully installed to: $TargetPath" -ForegroundColor Green
Write-Host "Restart your terminal or run: & '$TargetPath' --version" -ForegroundColor Cyan
