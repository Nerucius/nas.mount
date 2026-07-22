# nas-mount: Mount TrueNAS SMB shares as Windows drive letters.
# Replaces rclone with 4 MB pipelined reads/writes for ~8x throughput.
#
# NOTE: must NOT be $ErrorActionPreference = 'Stop'. Python's logging module
# writes INFO lines to stderr; under 'Stop', PowerShell treats any native
# stderr output as a terminating error and kills nas_mount.py the instant it
# logs its first connection message (before any drive gets mounted).
$ErrorActionPreference = 'Continue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $scriptDir '.venv\Scripts\python.exe'
$logFile = Join-Path $scriptDir 'nas-mount.log'

# Kill any leftover rclone or nas-mount processes on the same drives.
Get-Process rclone -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process python* -ErrorAction SilentlyContinue |
    Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -like '*nas_mount*' } |
    Stop-Process -Force
Start-Sleep -Seconds 3

Set-Location $scriptDir
# Route through cmd's redirection rather than PowerShell's *>> : PowerShell
# wraps every stderr line (Python's normal logging output) as an ErrorRecord,
# which prints noisy "NativeCommandError" clutter in the log even though it's
# non-fatal under $ErrorActionPreference = 'Continue'. cmd writes raw bytes.
cmd /c "`"$python`" nas_mount.py >> `"$logFile`" 2>&1"
