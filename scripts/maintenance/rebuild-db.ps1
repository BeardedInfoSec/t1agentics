# Database Rebuild Script (PowerShell)
# Use this to reset PostgreSQL and start fresh

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "         T1 Agentics Database Rebuild Script                   " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This will DELETE all data in PostgreSQL!" -ForegroundColor Yellow
Write-Host ""

$confirmation = Read-Host "Are you sure you want to continue? (yes/N)"
if ($confirmation -ne 'yes') {
    Write-Host "Aborted" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Starting database rebuild process..." -ForegroundColor Cyan
Write-Host ""

# Stop containers
Write-Host "================================================================" -ForegroundColor Gray
Write-Host "Step 1: Stopping containers..." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Gray
docker-compose down

# Remove PostgreSQL volume (this deletes all data!)
Write-Host ""
Write-Host "================================================================" -ForegroundColor Gray
Write-Host "Step 2: Removing PostgreSQL volume..." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Gray
docker volume rm source_postgres-data 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "   PostgreSQL volume removed" -ForegroundColor Green
} else {
    Write-Host "   Volume already removed" -ForegroundColor Gray
}

# Optional: Remove MongoDB volume too
Write-Host ""
$mongoResponse = Read-Host "Do you want to also reset MongoDB? (y/N)"
if ($mongoResponse -eq 'y' -or $mongoResponse -eq 'Y') {
    Write-Host "   Removing MongoDB volume..." -ForegroundColor Yellow
    docker volume rm source_mongodb-data 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   MongoDB volume removed" -ForegroundColor Green
    } else {
        Write-Host "   Volume already removed" -ForegroundColor Gray
    }
}

# Rebuild backend (includes database schema)
Write-Host ""
Write-Host "================================================================" -ForegroundColor Gray
Write-Host "Step 3: Rebuilding backend container (no cache)..." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Gray
docker-compose build --no-cache backend

# Start all services
Write-Host ""
Write-Host "================================================================" -ForegroundColor Gray
Write-Host "Step 4: Starting all services..." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Gray
docker-compose up -d

# Wait for services to initialize
Write-Host ""
Write-Host "Waiting for services to initialize (30 seconds)..." -ForegroundColor Yellow
for ($i = 1; $i -le 30; $i++) {
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 1
}
Write-Host " Done!" -ForegroundColor Green

# Verify PostgreSQL is running
Write-Host ""
Write-Host "================================================================" -ForegroundColor Gray
Write-Host "Verifying PostgreSQL..." -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Gray
Write-Host ""
Write-Host "Tables created:" -ForegroundColor White
docker exec t1agentics-postgres psql -U t1agentics -d t1agentics -c "\dt"

# Check default users
Write-Host ""
Write-Host "================================================================" -ForegroundColor Gray
Write-Host "Default users created:" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Gray
docker exec t1agentics-postgres psql -U t1agentics -d t1agentics -c "SELECT username, email, role, disabled FROM users;"

# Check backend logs
Write-Host ""
Write-Host "================================================================" -ForegroundColor Gray
Write-Host "Backend startup logs (last 20 lines):" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Gray
docker logs t1agentics-backend --tail 20

# Success message
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "                  Rebuild Complete!                             " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Access T1 Agentics:" -ForegroundColor Cyan
Write-Host "   URL:      http://localhost:3000" -ForegroundColor White
Write-Host "   Username: admin" -ForegroundColor White
Write-Host "   Password: admin123" -ForegroundColor White
Write-Host ""
Write-Host "Additional test accounts:" -ForegroundColor Cyan
Write-Host "   analyst / analyst123" -ForegroundColor White
Write-Host "   viewer  / viewer123" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "   docker-compose logs -f backend   # Watch backend logs" -ForegroundColor Gray
Write-Host "   docker-compose logs -f postgres  # Watch database logs" -ForegroundColor Gray
Write-Host "   docker-compose ps                # Check service status" -ForegroundColor Gray
Write-Host "   .\rebuild-db.ps1                 # Run this script again" -ForegroundColor Gray
Write-Host ""
Write-Host "Your database is fresh and ready!" -ForegroundColor Green
Write-Host ""
