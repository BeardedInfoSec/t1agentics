<#
.SYNOPSIS
    T1 Agentics - Stop Script for Windows

.DESCRIPTION
    Stops the T1 Agentics SOAR platform services on Windows.

.PARAMETER RemoveVolumes
    Remove all data volumes (WARNING: Deletes all data!)

.PARAMETER Force
    Skip confirmation prompts

.EXAMPLE
    .\Stop-T1Agentics.ps1
    Stop all services (keeps data)

.EXAMPLE
    .\Stop-T1Agentics.ps1 -RemoveVolumes
    Stop services and remove all data volumes

.EXAMPLE
    .\Stop-T1Agentics.ps1 -RemoveVolumes -Force
    Stop and remove volumes without confirmation

.NOTES
    Author: T1 Agentics Team
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$RemoveVolumes,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

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

#endregion

#region Main Script

try {
    # Change to script directory
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ProjectRoot = Split-Path -Parent $ScriptDir
    Set-Location $ProjectRoot

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "     T1 Agentics - Shutdown" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Confirmation for volume removal
    if ($RemoveVolumes -and -not $Force) {
        Write-ColorOutput "WARNING: You are about to remove all data volumes!" -Type Warning
        Write-ColorOutput "This will DELETE all alerts, investigations, and configuration!" -Type Warning
        Write-Host ""

        $confirm = Read-Host "Are you absolutely sure? Type 'yes' to confirm"
        if ($confirm -ne 'yes') {
            Write-ColorOutput "Aborted" -Type Info
            exit 0
        }
        Write-Host ""
    }

    # Stop containers
    Write-ColorOutput "Stopping all services..." -Type Info
    docker compose down
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to stop services"
    }
    Write-ColorOutput "All services stopped" -Type Success
    Write-Host ""

    # Remove volumes if requested
    if ($RemoveVolumes) {
        Write-ColorOutput "Removing data volumes..." -Type Warning

        # Get the project name from docker-compose
        $projectName = Split-Path -Leaf $ProjectRoot
        $projectName = $projectName.ToLower() -replace '[^a-z0-9]', ''

        $volumes = @(
            "${projectName}_postgres-data",
            "${projectName}_clickhouse-data",
            "${projectName}_clickhouse-logs",
            "${projectName}_vllm-cache",
            "t1agentics_postgres-data",
            "t1agentics_clickhouse-data",
            "t1agentics_clickhouse-logs",
            "t1agentics_vllm-cache"
        )

        $removedCount = 0
        foreach ($volume in $volumes) {
            try {
                $result = docker volume rm $volume 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-ColorOutput "Removed volume: $volume" -Type Success
                    $removedCount++
                }
            } catch {
                # Volume might not exist, that's OK
            }
        }

        if ($removedCount -gt 0) {
            Write-ColorOutput "Removed $removedCount data volume(s)" -Type Success
        } else {
            Write-ColorOutput "No volumes found to remove" -Type Info
        }

        # Also remove docker-volumes directory if it exists
        $dockerVolumesDir = Join-Path $ProjectRoot "docker-volumes"
        if (Test-Path $dockerVolumesDir) {
            Write-ColorOutput "Removing docker-volumes directory..." -Type Warning
            Remove-Item -Path $dockerVolumesDir -Recurse -Force
            Write-ColorOutput "docker-volumes directory removed" -Type Success
        }

        Write-Host ""
    }

    # Success message
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "   Shutdown Complete! [OK]" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""

    if ($RemoveVolumes) {
        Write-ColorOutput "All services stopped and data volumes removed" -Type Success
        Write-Host ""
        Write-ColorOutput "To reinstall:" -Type Info
        Write-ColorOutput "  .\scripts\Install-T1Agentics.ps1" -Type Info
    } else {
        Write-ColorOutput "All services stopped (data preserved)" -Type Success
        Write-Host ""
        Write-ColorOutput "To start again:" -Type Info
        Write-ColorOutput "  .\scripts\Start-T1Agentics.ps1" -Type Info
    }

    Write-Host ""

    # Show remaining containers (should be none)
    $remainingContainers = docker ps -a --filter "name=t1agentics" --format "{{.Names}}" 2>$null
    if ($remainingContainers) {
        Write-ColorOutput "Note: Some containers still exist (stopped):" -Type Info
        docker ps -a --filter "name=t1agentics"
        Write-Host ""
        Write-ColorOutput "To remove containers: docker compose rm" -Type Info
    }

} catch {
    Write-Host ""
    Write-ColorOutput "Shutdown failed: $_" -Type Error
    Write-Host ""
    Write-ColorOutput "Try manual cleanup:" -Type Info
    Write-ColorOutput "  docker compose down" -Type Info
    Write-ColorOutput "  docker compose down -v  # (removes volumes)" -Type Info
    Write-Host ""
    exit 1
}

#endregion
