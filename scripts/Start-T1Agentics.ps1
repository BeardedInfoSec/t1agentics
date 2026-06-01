<#
.SYNOPSIS
    T1 Agentics - Startup Script for Windows

.DESCRIPTION
    Starts the T1 Agentics SOAR platform services on Windows.
    Use this script for regular startup after initial installation.

.PARAMETER Auto
    Run in automatic mode without prompts

.PARAMETER RebuildFrontend
    Force rebuild of the frontend container

.PARAMETER ViewLogs
    Display logs after startup

.EXAMPLE
    .\Start-T1Agentics.ps1
    Interactive startup with prompts

.EXAMPLE
    .\Start-T1Agentics.ps1 -Auto
    Automatic startup with no prompts

.EXAMPLE
    .\Start-T1Agentics.ps1 -RebuildFrontend -ViewLogs
    Rebuild frontend and show logs after startup

.NOTES
    Author: T1 Agentics Team
    Requires: Docker Desktop running
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Auto,

    [Parameter(Mandatory=$false)]
    [switch]$RebuildFrontend,

    [Parameter(Mandatory=$false)]
    [switch]$ViewLogs
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

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

function Test-DockerRunning {
    try {
        $null = docker ps 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Get-ContainerStatus {
    param([string]$ContainerName)

    try {
        $status = docker inspect --format='{{.State.Status}}' $ContainerName 2>$null
        return $status
    } catch {
        return "not found"
    }
}

#endregion

#region Main Script

try {
    # Change to script directory
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ProjectRoot = Split-Path -Parent $ScriptDir
    Set-Location $ProjectRoot

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "     T1 Agentics - Startup" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # ============================================================================
    # STEP 1: PRE-FLIGHT CHECKS
    # ============================================================================
    Write-ColorOutput "Step 1: Pre-flight checks..." -Type Header
    Write-Host ""

    # Check Docker is running
    if (-not (Test-DockerRunning)) {
        Write-ColorOutput "Docker Desktop is not running!" -Type Error
        Write-Host ""
        Write-ColorOutput "Please start Docker Desktop and try again." -Type Info
        Write-ColorOutput "  - Open Docker Desktop from Start Menu" -Type Info
        Write-ColorOutput "  - Wait for it to show 'Docker Desktop is running'" -Type Info
        Write-Host ""
        exit 1
    }
    Write-ColorOutput "Docker Desktop is running" -Type Success

    # Check .env file exists
    $envFile = Join-Path $ProjectRoot ".env"
    if (-not (Test-Path $envFile)) {
        Write-ColorOutput ".env file not found!" -Type Warning
        Write-ColorOutput "Run Install-T1Agentics.ps1 first to create configuration" -Type Info
        Write-Host ""

        $create = Read-Host "Create default .env file now? (Y/N)"
        if ($create -eq 'Y' -or $create -eq 'y') {
            Write-ColorOutput "Creating default .env file..." -Type Info

            # Simple default config
            $envContent = @"
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@t1agentics.local
POSTGRES_PASSWORD=agentcore_dev_password
JWT_SECRET_KEY=change-this-in-production
CREDENTIALS_ENCRYPTION_KEY=zB4xkJPQW7nR9tYwLmN2dVoKjX5gHcE8sA1qF6iU3pM=
BASE_URL=http://localhost:8000
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
AI_PROVIDER=lm_studio
"@
            Set-Content -Path $envFile -Value $envContent -Encoding UTF8
            Write-ColorOutput ".env file created" -Type Success
        } else {
            exit 1
        }
    } else {
        Write-ColorOutput ".env file found" -Type Success
    }

    # Check if containers are already running
    $backendStatus = Get-ContainerStatus "t1agentics-backend"
    $frontendStatus = Get-ContainerStatus "t1agentics-frontend"

    if ($backendStatus -eq "running" -and $frontendStatus -eq "running") {
        Write-ColorOutput "Services are already running!" -Type Success
        Write-Host ""
        Write-ColorOutput "Access URLs:" -Type Header
        Write-Host "  Frontend: http://localhost:3000" -ForegroundColor White
        Write-Host "  Backend:  http://localhost:8000" -ForegroundColor White
        Write-Host ""

        if (-not $Auto) {
            $restart = Read-Host "Restart services anyway? (Y/N)"
            if ($restart -ne 'Y' -and $restart -ne 'y') {
                Write-ColorOutput "No changes made" -Type Info
                exit 0
            }
        } else {
            Write-ColorOutput "Auto mode: Skipping restart of running services" -Type Info
            exit 0
        }
    }

    Write-Host ""

    # ============================================================================
    # STEP 2: OPTIONAL REBUILD
    # ============================================================================
    if (-not $Auto -and -not $RebuildFrontend) {
        Write-ColorOutput "Step 2: Build options..." -Type Header
        Write-Host ""

        $rebuild = Read-Host "Rebuild frontend container? (recommended on first startup) (Y/N)"
        $RebuildFrontend = ($rebuild -eq 'Y' -or $rebuild -eq 'y')
        Write-Host ""
    }

    if ($RebuildFrontend) {
        Write-ColorOutput "Rebuilding frontend container..." -Type Info
        docker compose build --no-cache frontend
        if ($LASTEXITCODE -ne 0) {
            throw "Frontend rebuild failed"
        }
        Write-ColorOutput "Frontend rebuilt successfully" -Type Success
        Write-Host ""
    }

    # ============================================================================
    # STEP 3: START SERVICES
    # ============================================================================
    Write-ColorOutput "Step 3: Starting services..." -Type Header
    Write-Host ""

    docker compose up -d
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start services"
    }
    Write-ColorOutput "All services started" -Type Success
    Write-Host ""

    # ============================================================================
    # STEP 4: WAIT FOR SERVICES
    # ============================================================================
    Write-ColorOutput "Step 4: Waiting for services to be ready..." -Type Header
    Write-Host ""

    Write-ColorOutput "This may take 30-60 seconds..." -Type Info
    for ($i = 1; $i -le 30; $i++) {
        Write-Progress -Activity "Services starting up" -Status "$i of 30 seconds" -PercentComplete (($i / 30) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity "Services starting up" -Completed
    Write-Host ""

    # ============================================================================
    # STEP 5: CHECK SERVICE STATUS
    # ============================================================================
    Write-ColorOutput "Step 5: Service status..." -Type Header
    Write-Host ""

    # Check each service
    $services = @(
        @{Name = "PostgreSQL"; Container = "t1agentics-postgres"; Port = 5432}
        @{Name = "Backend"; Container = "t1agentics-backend"; Port = 8000}
        @{Name = "Frontend"; Container = "t1agentics-frontend"; Port = 3000}
        @{Name = "ClickHouse"; Container = "t1agentics-clickhouse"; Port = 8123}
    )

    foreach ($service in $services) {
        $status = Get-ContainerStatus $service.Container
        if ($status -eq "running") {
            Write-ColorOutput "$($service.Name): Running" -Type Success
        } elseif ($status -eq "not found") {
            Write-ColorOutput "$($service.Name): Container not found" -Type Warning
        } else {
            Write-ColorOutput "$($service.Name): $status" -Type Warning
        }
    }

    Write-Host ""

    # ============================================================================
    # SUCCESS MESSAGE
    # ============================================================================
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "   T1 Agentics is Running! [OK]" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
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

    # Show backend logs if requested
    if ($ViewLogs -or (-not $Auto)) {
        if (-not $Auto) {
            $showLogs = Read-Host "View backend logs? (Y/N)"
            $ViewLogs = ($showLogs -eq 'Y' -or $showLogs -eq 'y')
        }

        if ($ViewLogs) {
            Write-Host ""
            Write-ColorOutput "Backend logs (last 20 lines):" -Type Header
            Write-Host ""
            docker logs t1agentics-backend --tail 20
            Write-Host ""
            Write-ColorOutput "To follow logs in real-time: docker compose logs -f" -Type Info
        }
    }

    Write-Host ""

} catch {
    Write-Host ""
    Write-ColorOutput "Startup failed: $_" -Type Error
    Write-Host ""
    Write-ColorOutput "Troubleshooting:" -Type Info
    Write-ColorOutput "  - Check Docker Desktop is running" -Type Info
    Write-ColorOutput "  - View logs: docker compose logs" -Type Info
    Write-ColorOutput "  - Check status: docker ps" -Type Info
    Write-ColorOutput "  - Try: docker compose down && docker compose up -d" -Type Info
    Write-Host ""
    exit 1
}

#endregion
