$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    python -m pip install -r requirements.txt
    python -m playwright install chromium
}
finally {
    Pop-Location
}
