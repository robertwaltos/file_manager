Param(
    [string]$Config = ""
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\\Scripts\\python.exe"

if (-not (Test-Path $python)) {
    Write-Error "Missing .venv. Run: python -m venv .venv; .\\.venv\\Scripts\\Activate.ps1; pip install -r requirements.txt"
    exit 1
}

if ($Config) {
    $env:FILE_MANAGER_CONFIG = $Config
}

& $python (Join-Path $root "src\\main.py")
