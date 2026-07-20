# nas-mount: Mount TrueNAS SMB shares as Windows drive letters.
# Replaces rclone with 4 MB pipelined reads/writes for ~8x throughput.
$ErrorActionPreference = 'Stop'
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
& $python nas_mount.py *>> $logFile
