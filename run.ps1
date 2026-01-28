Param(
    [string]$Config = "",
    [int]$MaxRestarts = 0,
    [int]$RestartDelaySeconds = 30
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\\Scripts\\python.exe"
$logsDir = Join-Path $root "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir | Out-Null
}

if (-not (Test-Path $python)) {
    Write-Error "Missing .venv. Run: python -m venv .venv; .\\.venv\\Scripts\\Activate.ps1; pip install -r requirements.txt"
    exit 1
}

$venvBin = Split-Path -Parent $python
$env:PYTHONEXECUTABLE = $python
if (-not $env:VIRTUAL_ENV) {
    $env:VIRTUAL_ENV = Split-Path -Parent $venvBin
}
if (-not $env:PATH.StartsWith($venvBin, [System.StringComparison]::OrdinalIgnoreCase)) {
    $env:PATH = $venvBin + [System.IO.Path]::PathSeparator + $env:PATH
}

if ($Config) {
    $env:FILE_MANAGER_CONFIG = $Config
}

$autoRestart = $env:FILE_MANAGER_AUTO_RESTART
if ([string]::IsNullOrWhiteSpace($autoRestart)) {
    $autoRestart = "1"
}
if ($env:FILE_MANAGER_MAX_RESTARTS) {
    $MaxRestarts = [int]$env:FILE_MANAGER_MAX_RESTARTS
}
if ($env:FILE_MANAGER_RESTART_DELAY_SECONDS) {
    $RestartDelaySeconds = [int]$env:FILE_MANAGER_RESTART_DELAY_SECONDS
}

if (-not $env:FILE_MANAGER_DISABLE_TAIL) {
    $tailScript = Join-Path $root "tail_performance.ps1"
    if (Test-Path $tailScript) {
        Start-Process powershell -ArgumentList @(
            '-NoExit',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $tailScript
        )
    }
}

$attempt = 0
do {
    $attempt++
    & $python (Join-Path $root "src\\main.py")
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0 -or $autoRestart -eq "0") {
        exit $exitCode
    }
    if ($MaxRestarts -gt 0 -and $attempt -ge $MaxRestarts) {
        Write-Error "Max restarts reached ($MaxRestarts). Exiting with code $exitCode."
        exit $exitCode
    }
    $delay = [math]::Min($RestartDelaySeconds * [math]::Pow(2, ($attempt - 1)), 300)
    $logFile = Join-Path $logsDir ("auto_restart_" + (Get-Date -Format "yyyyMMdd") + ".log")
    Add-Content -Path $logFile -Value ("{0} restart {1} after exit {2}; sleeping {3}s" -f (Get-Date -Format o), $attempt, $exitCode, $delay)
    Start-Sleep -Seconds $delay
} while ($true)
