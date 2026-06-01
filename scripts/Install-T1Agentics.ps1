<#
.SYNOPSIS
    T1 Agentics - Automated Windows Installation Script

.DESCRIPTION
    This script automates the complete installation of T1 Agentics SOAR platform on Windows.
    It checks prerequisites, installs dependencies, configures the environment, and starts all services.

.PARAMETER SkipHealthChecks
    Skip the health check phase after starting services

.PARAMETER Verbose
    Enable verbose logging

.EXAMPLE
    .\Install-T1Agentics.ps1
    Run the complete installation with default settings

.EXAMPLE
    .\Install-T1Agentics.ps1 -SkipHealthChecks
    Install without waiting for health checks

.NOTES
    Author: T1 Agentics Team
    Requires: Windows 10/11, PowerShell 5.1+, Docker Desktop
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipHealthChecks
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Speed up Invoke-WebRequest

# Script configuration
$MIN_RAM_GB = 8
$RECOMMENDED_RAM_GB = 16
$MIN_DISK_GB = 20
$RECOMMENDED_DISK_GB = 50
$MIN_CPU_CORES = 4
$RECOMMENDED_CPU_CORES = 8
$HEALTH_CHECK_WAIT_SECONDS = 30
$DOCKER_STARTUP_WAIT_SECONDS = 60

#region Helper Functions

function Write-ColorOutput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Success', 'Warning', 'Error', 'Info', 'Header')]
        [string]$Type = 'Info'
    )

    $color = switch ($Type) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Info'    { 'White' }
        'Header'  { 'Cyan' }
    }

    $prefix = switch ($Type) {
        'Success' { '[✓]' }
        'Warning' { '[!]' }
        'Error'   { '[✗]' }
        'Info'    { '[i]' }
        'Header'  { '===' }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Write-Banner {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  T1 Agentics - Windows Installation  " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemRAM {
    $os = Get-CimInstance Win32_OperatingSystem
    return [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
}

function Get-FreeDiskSpace {
    $drive = (Get-Location).Drive.Name
    $disk = Get-PSDrive -Name $drive
    return [math]::Round($disk.Free / 1GB, 2)
}

function Get-CPUCores {
    return (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
}

function Test-DockerInstalled {
    try {
        $null = Get-Command docker -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-DockerRunning {
    try {
        $null = docker ps 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Start-DockerDesktop {
    Write-ColorOutput "Attempting to start Docker Desktop..." -Type Info

    $dockerPaths = @(
        "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    )

    $dockerExe = $dockerPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($dockerExe) {
        Start-Process $dockerExe
        Write-ColorOutput "Docker Desktop started. Waiting for it to be ready..." -Type Info

        $maxWait = $DOCKER_STARTUP_WAIT_SECONDS
        $waited = 0
        while (-not (Test-DockerRunning) -and $waited -lt $maxWait) {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 5
            $waited += 5
        }
        Write-Host ""

        if (Test-DockerRunning) {
            Write-ColorOutput "Docker Desktop is now running" -Type Success
            return $true
        } else {
            Write-ColorOutput "Docker Desktop did not start in time" -Type Warning
            return $false
        }
    } else {
        Write-ColorOutput "Docker Desktop executable not found" -Type Warning
        return $false
    }
}

function New-SecureRandomKey {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes) -replace '\+', '-' -replace '/', '_' -replace '=', ''
}

function New-FernetKey {
    # Generate a proper Fernet key (32 bytes base64 encoded)
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

#endregion

#region Main Script

try {
    # Change to script directory
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ProjectRoot = Split-Path -Parent $ScriptDir
    Set-Location $ProjectRoot

    Write-Banner

    Write-ColorOutput "This script will:" -Type Info
    Write-ColorOutput "  1. Check system requirements" -Type Info
    Write-ColorOutput "  2. Verify Docker Desktop is installed and running" -Type Info
    Write-ColorOutput "  3. Create configuration files" -Type Info
    Write-ColorOutput "  4. Build and start all services" -Type Info
    Write-ColorOutput "  5. Run health checks" -Type Info
    Write-Host ""

    # ============================================================================
    # STEP 1: CHECK SYSTEM REQUIREMENTS
    # ============================================================================
    Write-ColorOutput "Step 1: Checking system requirements..." -Type Header
    Write-Host ""

    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
        Write-ColorOutput "PowerShell 5.1 or higher is required. Current version: $($psVersion.ToString())" -Type Error
        exit 1
    }
    Write-ColorOutput "PowerShell version: $($psVersion.ToString())" -Type Success

    # Check RAM
    $totalRAM = Get-SystemRAM
    if ($totalRAM -lt $MIN_RAM_GB) {
        Write-ColorOutput "WARNING: System has ${totalRAM}GB RAM. Minimum ${MIN_RAM_GB}GB recommended." -Type Warning
        Write-ColorOutput "Platform may run slowly or fail to start." -Type Warning
    } elseif ($totalRAM -lt $RECOMMENDED_RAM_GB) {
        Write-ColorOutput "RAM: ${totalRAM}GB (minimum met, ${RECOMMENDED_RAM_GB}GB recommended)" -Type Success
    } else {
        Write-ColorOutput "RAM: ${totalRAM}GB (sufficient)" -Type Success
    }

    # Check disk space
    $freeDisk = Get-FreeDiskSpace
    if ($freeDisk -lt $MIN_DISK_GB) {
        Write-ColorOutput "ERROR: Only ${freeDisk}GB free disk space. Minimum ${MIN_DISK_GB}GB required." -Type Error
        exit 1
    } elseif ($freeDisk -lt $RECOMMENDED_DISK_GB) {
        Write-ColorOutput "Disk space: ${freeDisk}GB (minimum met, ${RECOMMENDED_DISK_GB}GB recommended)" -Type Success
    } else {
        Write-ColorOutput "Disk space: ${freeDisk}GB (sufficient)" -Type Success
    }

    # Check CPU cores
    $cpuCores = Get-CPUCores
    if ($cpuCores -lt $MIN_CPU_CORES) {
        Write-ColorOutput "WARNING: System has $cpuCores CPU cores. Minimum $MIN_CPU_CORES recommended." -Type Warning
    } else {
        Write-ColorOutput "CPU cores: $cpuCores (sufficient)" -Type Success
    }

    Write-Host ""

    # ============================================================================
    # STEP 2: CHECK DOCKER DESKTOP
    # ============================================================================
    Write-ColorOutput "Step 2: Checking Docker Desktop..." -Type Header
    Write-Host ""

    # Check if Docker is installed
    if (-not (Test-DockerInstalled)) {
        Write-ColorOutput "Docker Desktop is not installed!" -Type Error
        Write-Host ""
        Write-ColorOutput "Please install Docker Desktop:" -Type Info
        Write-ColorOutput "  1. Download from: https://www.docker.com/products/docker-desktop/" -Type Info
        Write-ColorOutput "  2. Install Docker Desktop" -Type Info
        Write-ColorOutput "  3. Enable WSL 2 backend if prompted" -Type Info
        Write-ColorOutput "  4. Restart your computer" -Type Info
        Write-ColorOutput "  5. Run this script again" -Type Info
        Write-Host ""
        exit 1
    }

    # Get Docker version
    $dockerVersion = (docker --version) -replace 'Docker version ', '' -replace ',.*', ''
    Write-ColorOutput "Docker installed: $dockerVersion" -Type Success

    # Check if Docker is running
    if (-not (Test-DockerRunning)) {
        Write-ColorOutput "Docker Desktop is not running" -Type Warning

        $startDocker = Start-DockerDesktop

        if (-not $startDocker) {
            Write-ColorOutput "Failed to start Docker Desktop automatically" -Type Error
            Write-Host ""
            Write-ColorOutput "Please start Docker Desktop manually:" -Type Info
            Write-ColorOutput "  1. Open Docker Desktop from Start Menu" -Type Info
            Write-ColorOutput "  2. Wait for it to be ready (icon in system tray)" -Type Info
            Write-ColorOutput "  3. Run this script again" -Type Info
            Write-Host ""
            exit 1
        }
    } else {
        Write-ColorOutput "Docker Desktop is running" -Type Success
    }

    # Check docker compose
    try {
        $composeVersion = (docker compose version) -replace 'Docker Compose version ', '' -replace 'v', ''
        Write-ColorOutput "Docker Compose: $composeVersion" -Type Success
    } catch {
        Write-ColorOutput "Docker Compose plugin not found" -Type Error
        Write-ColorOutput "Please ensure Docker Desktop is up to date" -Type Info
        exit 1
    }

    Write-Host ""

    # ============================================================================
    # STEP 3: CREATE CONFIGURATION
    # ============================================================================
    Write-ColorOutput "Step 3: Creating configuration..." -Type Header
    Write-Host ""

    $envFile = Join-Path $ProjectRoot ".env"

    if (Test-Path $envFile) {
        Write-ColorOutput ".env file already exists" -Type Success
        Write-ColorOutput "Keeping existing configuration" -Type Info
    } else {
        Write-ColorOutput "Creating new .env file..." -Type Info

        # Generate secure keys
        $jwtSecret = New-SecureRandomKey -Length 32
        $encryptionKey = New-FernetKey

        $envContent = @"
# T1 Agentics Configuration
# Generated by Install-T1Agentics.ps1 on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

# Admin credentials (CHANGE IN PRODUCTION!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@t1agentics.local

# Database
POSTGRES_PASSWORD=agentcore_dev_password

# JWT Authentication
JWT_SECRET_KEY=$jwtSecret
JWT_EXPIRE_MINUTES=1440

# Encryption (for credentials vault)
CREDENTIALS_ENCRYPTION_KEY=$encryptionKey

# URLs
BASE_URL=http://localhost:8000
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# AI Provider (lm_studio for development, vllm for production)
AI_PROVIDER=lm_studio
LM_STUDIO_URL=http://host.docker.internal:1234

# Optional: vLLM Configuration (uncomment if using vLLM)
# VLLM_URL=http://host.docker.internal:8001
# VLLM_MODEL=openai/gpt-oss-20b
"@

        Set-Content -Path $envFile -Value $envContent -Encoding UTF8
        Write-ColorOutput ".env file created with secure random keys" -Type Success
    }

    # Create docker-volumes directory if needed
    $volumesDir = Join-Path $ProjectRoot "docker-volumes"
    if (-not (Test-Path $volumesDir)) {
        New-Item -ItemType Directory -Path $volumesDir | Out-Null
        Write-ColorOutput "Created docker-volumes directory" -Type Success
    }

    Write-Host ""

    # ============================================================================
    # STEP 4: BUILD AND START SERVICES
    # ============================================================================
    Write-ColorOutput "Step 4: Building and starting services..." -Type Header
    Write-Host ""

    Write-ColorOutput "This may take 10-15 minutes on first run..." -Type Info
    Write-Host ""

    # Build frontend
    Write-ColorOutput "Building frontend container (this takes longest)..." -Type Info
    docker compose build --no-cache frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed"
    }
    Write-ColorOutput "Frontend built successfully" -Type Success
    Write-Host ""

    # Build backend
    Write-ColorOutput "Building backend container..." -Type Info
    docker compose build backend
    if ($LASTEXITCODE -ne 0) {
        throw "Backend build failed"
    }
    Write-ColorOutput "Backend built successfully" -Type Success
    Write-Host ""

    # Start all services
    Write-ColorOutput "Starting all services..." -Type Info
    docker compose up -d
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start services"
    }
    Write-ColorOutput "All services started" -Type Success
    Write-Host ""

    # ============================================================================
    # STEP 5: HEALTH CHECKS
    # ============================================================================
    if (-not $SkipHealthChecks) {
        Write-ColorOutput "Step 5: Running health checks..." -Type Header
        Write-Host ""

        Write-ColorOutput "Waiting $HEALTH_CHECK_WAIT_SECONDS seconds for services to initialize..." -Type Info
        for ($i = 1; $i -le $HEALTH_CHECK_WAIT_SECONDS; $i++) {
            Write-Progress -Activity "Initializing services" -Status "$i of $HEALTH_CHECK_WAIT_SECONDS seconds" -PercentComplete (($i / $HEALTH_CHECK_WAIT_SECONDS) * 100)
            Start-Sleep -Seconds 1
        }
        Write-Progress -Activity "Initializing services" -Completed
        Write-Host ""

        # Check PostgreSQL
        try {
            $pgCheck = docker exec t1agentics-postgres pg_isready -U agentcore 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "PostgreSQL: Running" -Type Success
            } else {
                Write-ColorOutput "PostgreSQL: Not ready yet (may need more time)" -Type Warning
            }
        } catch {
            Write-ColorOutput "PostgreSQL: Not ready yet" -Type Warning
        }

        # Check Backend
        try {
            $null = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            Write-ColorOutput "Backend: Running" -Type Success
        } catch {
            Write-ColorOutput "Backend: Not ready yet (may need more time)" -Type Warning
        }

        # Check Frontend
        try {
            $null = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            Write-ColorOutput "Frontend: Running" -Type Success
        } catch {
            Write-ColorOutput "Frontend: Not ready yet (may need more time)" -Type Warning
        }

        # Check ClickHouse
        try {
            $null = Invoke-WebRequest -Uri "http://localhost:8123/ping" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            Write-ColorOutput "ClickHouse: Running" -Type Success
        } catch {
            Write-ColorOutput "ClickHouse: Not ready yet (may need more time)" -Type Warning
        }

        Write-Host ""
    }

    # ============================================================================
    # SUCCESS MESSAGE
    # ============================================================================
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "   Installation Complete! [OK]          " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""

    Write-ColorOutput "T1 Agentics is running!" -Type Success
    Write-Host ""

    Write-ColorOutput "Access URLs:" -Type Header
    Write-Host "  Frontend:   http://localhost:3000" -ForegroundColor White
    Write-Host "  Backend:    http://localhost:8000" -ForegroundColor White
    Write-Host "  API Docs:   http://localhost:8000/docs" -ForegroundColor White
    Write-Host ""

    Write-ColorOutput "Default Login:" -Type Header
    Write-Host "  Username: admin" -ForegroundColor White
    Write-Host "  Password: admin123" -ForegroundColor White
    Write-Host ""

    Write-ColorOutput "Useful Commands:" -Type Header
    Write-Host "  View logs:     docker compose logs -f" -ForegroundColor Gray
    Write-Host "  Stop:          docker compose down" -ForegroundColor Gray
    Write-Host "  Restart:       docker compose restart <service>" -ForegroundColor Gray
    Write-Host "  Status:        docker ps" -ForegroundColor Gray
    Write-Host ""

    Write-ColorOutput "WARNING - Production Deployment:" -Type Warning
    Write-Host "  - Change default passwords in .env" -ForegroundColor Yellow
    Write-Host "  - Review security settings" -ForegroundColor Yellow
    Write-Host "  - Set up HTTPS/TLS" -ForegroundColor Yellow
    Write-Host "  - Configure automated backups" -ForegroundColor Yellow
    Write-Host ""

    Write-ColorOutput "Documentation: See docs\guides\WINDOWS-INSTALLATION.md" -Type Info
    Write-Host ""

    # Save installation log
    $logFile = Join-Path $ProjectRoot "install-windows.log"
    $logContent = @"
T1 Agentics Windows Installation Log
=====================================
Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
PowerShell: $($PSVersionTable.PSVersion.ToString())
Docker: $dockerVersion
Docker Compose: $composeVersion
System RAM: ${totalRAM}GB
Free Disk: ${freeDisk}GB
CPU Cores: $cpuCores

Installation completed successfully.
"@
    Add-Content -Path $logFile -Value $logContent
    Write-ColorOutput "Installation log saved to: install-windows.log" -Type Info
    Write-Host ""

} catch {
    Write-Host ""
    Write-ColorOutput "Installation failed: $_" -Type Error
    Write-ColorOutput "Check the error message above for details" -Type Error
    Write-Host ""
    Write-ColorOutput "Common fixes:" -Type Info
    Write-ColorOutput "  - Ensure Docker Desktop is running" -Type Info
    Write-ColorOutput "  - Check you have enough disk space" -Type Info
    Write-ColorOutput "  - Try running: docker compose down" -Type Info
    Write-ColorOutput "  - Then run this script again" -Type Info
    Write-Host ""
    exit 1
}

#endregion
