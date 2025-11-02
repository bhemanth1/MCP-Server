# MCP Scanner - Automated Tool Installation Script for Windows
# This script installs all required scanning tools automatically

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MCP Scanner - Tool Installation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Warning: Not running as Administrator. Some installations may require elevated privileges." -ForegroundColor Yellow
    Write-Host ""
}

# Function to check if command exists
function Test-Command {
    param($CommandName)
    $null -ne (Get-Command $CommandName -ErrorAction SilentlyContinue)
}

# Function to check if path exists in PATH
function Test-PathInEnv {
    param($Path)
    $env:Path -split ';' | Where-Object { $_ -eq $Path } | Measure-Object | Select-Object -ExpandProperty Count
}

# Function to add to PATH
function Add-ToPath {
    param($Path)
    if (-not (Test-PathInEnv $Path)) {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$Path", "User")
        $env:Path += ";$Path"
        Write-Host "Added to PATH: $Path" -ForegroundColor Green
    }
}

# 1. Install Chocolatey (if not installed)
Write-Host "[1/6] Checking Chocolatey..." -ForegroundColor Yellow
if (-not (Test-Command choco)) {
    Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Host "Chocolatey installed!" -ForegroundColor Green
} else {
    Write-Host "Chocolatey already installed" -ForegroundColor Green
}

# 2. Install Nmap
Write-Host ""
Write-Host "[2/6] Installing Nmap..." -ForegroundColor Yellow
if (-not (Test-Command nmap)) {
    if (Test-Command choco) {
        choco install nmap -y
        Write-Host "Nmap installed via Chocolatey" -ForegroundColor Green
    } else {
        Write-Host "Chocolatey not available. Please install Nmap manually from https://nmap.org/download.html" -ForegroundColor Red
    }
} else {
    Write-Host "Nmap already installed" -ForegroundColor Green
}

# 3. Install Go
Write-Host ""
Write-Host "[3/6] Installing Go (required for subfinder & gobuster)..." -ForegroundColor Yellow
if (-not (Test-Command go)) {
    if (Test-Command choco) {
        choco install golang -y
        Write-Host "Go installed via Chocolatey" -ForegroundColor Green
        
        # Refresh PATH
        $goPath = "$env:ProgramFiles\Go\bin"
        Add-ToPath $goPath
        
        # Set GOPATH and add Go bin to PATH
        $goUserBin = "$env:USERPROFILE\go\bin"
        if (-not (Test-Path $goUserBin)) {
            New-Item -ItemType Directory -Path $goUserBin -Force | Out-Null
        }
        Add-ToPath $goUserBin
        
        # Reload PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        Write-Host "Go bin added to PATH: $goUserBin" -ForegroundColor Green
    } else {
        Write-Host "Chocolatey not available. Please install Go manually from https://golang.org/dl/" -ForegroundColor Red
    }
} else {
    Write-Host "Go already installed" -ForegroundColor Green
    $goUserBin = "$env:USERPROFILE\go\bin"
    Add-ToPath $goUserBin
}

# 4. Install Subfinder
Write-Host ""
Write-Host "[4/6] Installing Subfinder..." -ForegroundColor Yellow
if (-not (Test-Command subfinder)) {
    if (Test-Command go) {
        Write-Host "Installing subfinder via Go..." -ForegroundColor Yellow
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        $goBin = "$env:USERPROFILE\go\bin"
        Add-ToPath $goBin
        
        & go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        
        if (Test-Path "$goBin\subfinder.exe") {
            Write-Host "Subfinder installed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Subfinder installation may have failed. Please run: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Go not installed. Cannot install subfinder automatically." -ForegroundColor Red
    }
} else {
    Write-Host "Subfinder already installed" -ForegroundColor Green
}

# 5. Install Gobuster
Write-Host ""
Write-Host "[5/6] Installing Gobuster..." -ForegroundColor Yellow
if (-not (Test-Command gobuster)) {
    if (Test-Command go) {
        Write-Host "Installing gobuster via Go..." -ForegroundColor Yellow
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        $goBin = "$env:USERPROFILE\go\bin"
        Add-ToPath $goBin
        
        & go install github.com/OJ/gobuster/v3@latest
        
        if (Test-Path "$goBin\gobuster.exe") {
            Write-Host "Gobuster installed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Gobuster installation may have failed. Please run: go install github.com/OJ/gobuster/v3@latest" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Go not installed. Cannot install gobuster automatically." -ForegroundColor Red
    }
} else {
    Write-Host "Gobuster already installed" -ForegroundColor Green
}

# 6. Install Nikto (Windows version or suggest WSL)
Write-Host ""
Write-Host "[6/6] Installing Nikto..." -ForegroundColor Yellow
if (-not (Test-Command nikto)) {
    Write-Host "Nikto installation options:" -ForegroundColor Yellow
    Write-Host "  Option 1: Install via WSL (recommended)" -ForegroundColor Cyan
    Write-Host "  Option 2: Download from GitHub" -ForegroundColor Cyan
    
    # Check if WSL is available
    if (Test-Command wsl) {
        Write-Host "WSL detected. Installing Nikto via WSL..." -ForegroundColor Yellow
        wsl bash -c "sudo apt-get update && sudo apt-get install -y nikto"
        Write-Host "Nikto installed via WSL. Use 'wsl nikto' to run it." -ForegroundColor Green
        Write-Host "Note: You may need to update scanner to use 'wsl nikto' command" -ForegroundColor Yellow
    } else {
        Write-Host "WSL not available. Downloading Nikto from GitHub..." -ForegroundColor Yellow
        $niktoDir = "$env:USERPROFILE\tools\nikto"
        if (-not (Test-Path $niktoDir)) {
            New-Item -ItemType Directory -Path $niktoDir -Force | Out-Null
        }
        
        # Download Nikto from GitHub releases
        $niktoUrl = "https://github.com/sullo/nikto/archive/refs/heads/master.zip"
        $zipPath = "$niktoDir\nikto.zip"
        
        try {
            Invoke-WebRequest -Uri $niktoUrl -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $niktoDir -Force
            
            # Find perl executable (Nikto requires Perl)
            $perlPath = Get-Command perl -ErrorAction SilentlyContinue
            if ($perlPath) {
                Write-Host "Nikto downloaded to: $niktoDir" -ForegroundColor Green
                Write-Host "Note: You'll need to configure Perl and update scanner paths" -ForegroundColor Yellow
            } else {
                Write-Host "Perl not found. Nikto requires Perl. Install Strawberry Perl or use WSL." -ForegroundColor Red
            }
        } catch {
            Write-Host "Failed to download Nikto: $_" -ForegroundColor Red
            Write-Host "Please install manually or use WSL" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "Nikto already installed" -ForegroundColor Green
}

# Final verification
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installation Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$tools = @("nmap", "subfinder", "gobuster", "nikto", "nslookup", "tracert")
foreach ($tool in $tools) {
    $cmd = if ($tool -eq "tracert") { "tracert" } else { $tool }
    if (Test-Command $cmd) {
        Write-Host "OK $tool - Installed" -ForegroundColor Green
    } else {
        Write-Host "X $tool - Not found" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Important Notes:" -ForegroundColor Yellow
Write-Host "1. You may need to restart your terminal/PowerShell for PATH changes to take effect" -ForegroundColor White
Write-Host "2. If tools are still not found after restart, check PATH manually" -ForegroundColor White
Write-Host "3. For Nikto on Windows, WSL is recommended for best compatibility" -ForegroundColor White
Write-Host ""
Write-Host "To verify installations, restart your terminal and run:" -ForegroundColor Cyan
Write-Host "  nmap --version" -ForegroundColor White
Write-Host "  subfinder -version" -ForegroundColor White
Write-Host "  gobuster --help" -ForegroundColor White
Write-Host ""
