# CLAUDE.md

## Project overview

A Python FUSE filesystem using WinFsp (via winfspy) and smbprotocol to mount remote TrueNAS SMB shares as Windows drive letters with configurable read sizes. The key value prop is 4 MB SMB reads instead of rclone's hardcoded 64 KB, which yields ~8x read throughput and ~40x write throughput on high-latency WAN links.

## Tech stack

- **Windows 10** - The running OS.
- **Python 3.11** - `.venv` contains a python 3.11.9 env with the packages installed. 
- **winfspy** (v0.8.4) - Python bindings for WinFsp (FUSE on Windows). WinFsp is already installed (used by rclone).
- **smbprotocol** (v1.17.0) - pure Python SMB2/3 client with pipelined write support via `send=False`.
- **toml** - config file format (stdlib tomllib for reading).

## Key constraints

- **Single SMB connection per mount** - smbprotocol connections can drop on network blips. Reconnect logic with exponential backoff handles this.
- **WinFsp callbacks run on arbitrary threads** - smbprotocol is not thread-safe per-connection. One `threading.Lock` per SMBClient serializes all SMB ops.
- **Directory listing can be slow** - cache READDIR results with configurable TTL (default 300s). Invalidated on create/delete/rename.
- **File metadata (size, dates) must be accurate** - Windows Explorer and media players rely on correct file sizes for seek/progress. Cached in SmbFileContext on open.
- **SMB credits limit request sizes** - server grants credits incrementally. Client requests credits on connect via echo and with each pipelined write. 64 credits = 4 MB max per single request.
- **Credential handling** - password stored in config.toml (same security posture as rclone.conf). Do not log passwords.

## Architecture decisions

- One SMB `Connection` + `Session` + `TreeConnect` per unique share name. Multiple mounts to the same share reuse one connection.
- File handles: WinFsp `open()`/`create()` returns `SmbFileContext` wrapping an smbprotocol `Open` object.
- Read strategy: 4 MB read-ahead buffer per file. Small reads (e.g., mpv 64 KB seeks) served from buffer without SMB round-trips.
- Write strategy: write-behind buffer accumulates WinFsp's 1 MB writes, flushes as 4x 4 MB pipelined SMB writes (16 MB batch). Reduces round-trips by ~16x.
- Caching: directory entries cached in memory with TTL. File content is NOT cached (WinFsp's `file_info_timeout=1000` enables kernel caching).
- Config: TOML file at `config.toml` in project root. Passwords can alternatively come from `NAS_MOUNT_PASSWORD` env var.

## File structure

```
nas.mount/
├── CLAUDE.md
├── ARCHITECTURE.md
├── README.md
├── config.example.toml     # Template config (no secrets)
├── config.toml             # Local config with credentials (gitignored)
├── requirements.txt
├── nas_mount.py            # Entry point - arg parsing, mount orchestration
├── smb_client.py           # SMB connection wrapper with reconnect + pipelined writes
└── fuse_fs.py              # WinFsp filesystem implementation (read-ahead + write-behind)
```

## Development commands

```powershell
# Install dependencies
pip install -r requirements.txt

# Run the mount (all configured drives)
python nas_mount.py

# Mount a single drive
python nas_mount.py --drive M

# Run with debug logging
python nas_mount.py --debug

# Test SMB connection and benchmark (no mount)
python nas_mount.py --test

# Benchmark a specific file
python nas_mount.py --bench media\somefile.mkv --bench-size 64
```

## Proven benchmarks (from testing session 2026-07-18/20)

Read benchmarks (raw SMB via smbprotocol against example.org:3445, ~37ms RTT):

| Read size | Speed | Notes |
|-----------|-------|-------|
| 64 KB | 1.3 MB/s | rclone's hardcoded limit |
| 256 KB | 4.0 MB/s | |
| 1 MB | 7.0 MB/s | |
| 4 MB | 10.7 MB/s | **Target** - 86% of line speed |

Write benchmarks (through FUSE mount, 321 MB test file):

| Mode | Speed | Notes |
|------|-------|-------|
| Sequential (no buffer) | ~20 MB/s | 1 MB WinFsp chunks, one SMB write per chunk |
| Write-behind 4 MB | 34-38 MB/s | Buffer + single flush |
| Pipelined 4x4 MB | 42-51 MB/s | Write-behind + pipelined flush |
| Raw pipelined (no FUSE) | 65 MB/s | Theoretical ceiling for 4x4 MB pipeline |

Server-side Samba tuning (already applied on TrueNAS):
```
smb2 max read = 8388608
smb2 max write = 8388608
smb2 max trans = 8388608
smb2 max credits = 8192
```

## Gotchas

- **Sandbox**: Claude Code's shell runs in a filesystem sandbox. Use `dangerouslyDisableSandbox: true` for any command that needs real filesystem/network access (mounting drives, testing SMB connections).
- **Port 445**: Windows kernel reserves port 445. The remote server is on port 3445 (socat proxy on gateway forwards to TrueNAS:445).
- **winfspy install**: may need Visual C++ build tools if no wheel is available. Check `pip install winfspy` first.
- **Process lifetime**: the FUSE mount runs as long as the process lives. For auto-start, use a scheduled task or Windows service wrapper.
- **SMB credits**: smbprotocol defaults to requesting minimal credits. We echo-request credits on connect and request replenishment with each pipelined write. Without this, 8 MB writes fail with "not enough credits".

## Coding agents

Plans go in `.claude/plans`, no exceptions.
