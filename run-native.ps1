# Native (no-Docker) launcher for T1 Agentics -- Windows PowerShell.
# Creates a venv, installs deps, builds the frontend if needed, then runs the
# embedded-Postgres single-node app on http://localhost:8000.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$ver = & $py -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ($ver -ne "3.11" -and $ver -ne "3.12") {
  Write-Error "Python 3.11 or 3.12 is required (the backend's pinned deps target it). Found $ver. Set `$env:PYTHON to override."
  exit 1
}

if (-not (Test-Path .native\venv)) {
  Write-Host "Creating virtualenv (.native\venv) ..."
  & $py -m venv .native\venv
}
& .native\venv\Scripts\Activate.ps1

Write-Host "Installing Python dependencies ..."
pip install --quiet --upgrade pip
pip install --quiet -r backend\requirements.txt -r requirements-native.txt

if (-not (Test-Path frontend\build\index.html)) {
  Write-Host "Building frontend (one-time) ..."
  Push-Location frontend; npm install; npm run build; Pop-Location
}

python run_native.py
