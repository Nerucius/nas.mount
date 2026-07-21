# nas-mount

Custom Python FUSE filesystem that mounts remote TrueNAS SMB shares as Windows drive letters (or macOS volumes) with pipelined 4 MB transfers and aggressively compounded/cached metadata for WAN links.

## Problem

rclone's SMB backend uses go-smb2 which hardcodes 64 KB reads. Over a 41 ms WAN link, the bandwidth-delay product limits that to ~5 MB/s: each read requires a full round trip before the next can begin.

`smbprotocol` allows configurable read sizes and out-of-band sends. With 4 MB requests pipelined 3 deep, the same link sustains **12.5+ MB/s — the remote site's full 100 Mbps uplink**; sliding-window writes sustain **76 MB/s (608 Mbps)**, its full downlink. Metadata operations are SMB2-compounded and cached, so browsing feels local.

## Architecture

```
Windows app / Finder
     │
WinFsp (fuse_fs.py) / FUSE-T (macos_fs.py)
     │
  fs_core.py  — read-ahead windows, write pipeline, dir/stat caches
     │
smb_client.py — pipelined + compounded SMB2 over WAN
     │
┌─────────────┐    WAN 41ms RTT    ┌──────────┐    <1ms    ┌──────────────┐
│  local-site    │───────────────────▶│ Gateway  │──────────▶│ TrueNAS CORE │
│  M: Y: Z:   │  example.org:3445  │ socat    │  :445     │ Samba        │
│  ~/nas/*    │                    │ (Debian) │           │ /mnt/storage │
└─────────────┘                    └──────────┘           └──────────────┘
```

The gateway socat relay is load-bearing: it splits the TCP path so both WAN
directions get a Linux sender (TrueNAS CORE's FreeBSD TCP stack collapses as
a WAN sender on this path — see ARCHITECTURE.md).

## Performance

Measured through the real mounts over the WAN (41 ms RTT). The remote site
is 600 Mbps down / 100 Mbps up, so line rate is 12.5 MB/s for reads and
~75 MB/s for writes:

| Platform | Read | Write |
|----------|------|-------|
| Windows (Explorer, 2 GB sustained) | **12.8 MB/s** | **76 MB/s (608 Mbps)** |
| macOS (FUSE-T) | **12.7 MB/s** | 50–54 MB/s |
| rclone SMB (before) | 5.0 MB/s | ~20 MB/s |

Both directions saturate the link on Windows; macOS reads saturate too and
writes pay a small NFS-translation tax.

Directory browsing is metadata-bound (41 ms per round trip), so metadata
operations are SMB2-compounded (stat and full listings each cost one round
trip), negative probes and repeated stats are cached, file opens are lazy,
and header sniffs read a 256 KB head instead of a full 4 MB window. A folder
of images paints instantly warm, ~0.3 s cold. Bulk operations are compounded
and pipelined too: deleting a folder runs at ~10 ms/file (Explorer deletes
file-by-file; each is a 1-RTT compound running 8 deep), renames are one
round trip.

## Requirements

- Windows 10/11 with [WinFsp](https://winfsp.dev/), **or** macOS with
  [FUSE-T](https://www.fuse-t.org/) (`brew install fuse-t` — kextless, no
  security-policy changes needed on Apple Silicon)
- Python 3.11+

## Installation

```
pip install -r requirements.txt   # picks winfspy or fusepy per platform
```

On macOS, mounts land under `~/nas/<name>` by default (configurable via the
`[macos]` section in config.toml).

## Usage

```
# Mount all configured shares
python nas_mount.py

# Mount a single drive from the config
python nas_mount.py --drive M

# Connectivity test / benchmarks (no mount)
python nas_mount.py --test
python nas_mount.py --bench media\somefile.mkv --bench-size 64
python nas_mount.py --bench-write
```

From VSCode: `Terminal > Run Task > NAS: Remount all (macOS/Windows)` stops
any running instance (unmounting the volumes) and starts a fresh one in a
dedicated terminal panel.

## Auto-start at login

**Windows** — register `mount.ps1` as a scheduled task (it kills stale
rclone/nas-mount processes and starts the mounter, logging to
`nas-mount.log`). From an elevated PowerShell in the repo directory:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PWD\mount.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "nas-mount" -Action $action -Trigger $trigger `
  -Settings $settings
Start-ScheduledTask -TaskName "nas-mount"   # mount now without relogging
```

The drive letters belong to the logon session, so the task runs as the
logged-in user (no admin needed for the task itself).

**macOS** — install the bundled launchd agent (the `mount.ps1` counterpart):

```bash
./mount.sh install     # writes ~/Library/LaunchAgents/com.nas-mount.plist, mounts now
./mount.sh status
./mount.sh uninstall
```

The agent mounts at login, restarts the mounter if it crashes (but not on a
clean exit), and logs to `nas-mount.log`.

## Configuration

Copy `config.example.toml` to `config.toml` and edit connection details:

```toml
[connection]
host = "example.org"
port = 3445
user = "herman"

[tuning]
read_size = 4194304        # 4 MB — proven optimal for ~41ms RTT
write_size = 4194304
read_pipeline_depth = 3    # concurrent reads in flight per stream
write_pipeline_depth = 4   # concurrent writes in flight per file
dir_cache_ttl = 300        # seconds
file_info_timeout = 5000   # ms the Windows kernel caches file metadata
dir_info_timeout = 1000    # ms the kernel caches listings

[mounts]
M = "storage/media"
Y = "storage/documents"
Z = "storage/backups"
```

## License

MIT
