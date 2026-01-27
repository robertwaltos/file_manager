Param(
    [string]$LogsPath = "logs",
    [string]$Pattern = "performance_log_*.log",
    [int]$PollSeconds = 2,
    [string]$FilterRegex = ""
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$logs = Join-Path $root $LogsPath

while (-not (Test-Path $logs)) {
    Start-Sleep -Seconds $PollSeconds
}

$log = $null
while ($null -eq $log) {
    $log = Get-ChildItem $logs -Filter $Pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $log) {
        Start-Sleep -Seconds $PollSeconds
    }
}

Write-Host ("Tailing " + $log.FullName)
if ($FilterRegex) {
    Get-Content -Path $log.FullName -Wait -Tail 0 | Where-Object { $_ -match $FilterRegex }
} else {
    Get-Content -Path $log.FullName -Wait -Tail 0
}
