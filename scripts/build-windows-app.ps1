$ErrorActionPreference = "Stop"

Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host "==> Installing Node dependencies"
npm install

Write-Host "==> Installing Python dependencies"
if (Test-Path ".venv\Scripts\python.exe") {
  .\.venv\Scripts\python.exe -m pip install -r requirements.txt
} else {
  python -m pip install -r requirements.txt
}

Write-Host "==> Building Windows installer"
npm run build:win

Write-Host ""
Write-Host "Done. Output files are in:"
Write-Host "  release\"
