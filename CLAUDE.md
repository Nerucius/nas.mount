# CLAUDE.md

## Project overview

A Python FUSE filesystem using WinFsp (via winfspy) and smbprotocol to mount remote TrueNAS SMB shares as Windows drive letters with configurable read sizes. The key value prop is 4 MB SMB reads instead of rclone's hardcoded 64 KB, which yields 2x throughput on high-latency WAN links.

## Tech stack

- **Windows 10** - The running OS.
- **Python 3.11** - `.venv` contains a python 3.11.9 env with the packages installed. 
- **winfspy** - Python bindings for WinFsp (FUSE on Windows). WinFsp is already installed (used by rclone).
- **smbprotocol** - pure Python SMB2/3 client. Proven at 10.7 MB/s with 4 MB reads.
- **toml** - config file format (stdlib tomllib for reading, tomli-w if writing needed).

## Key constraints

- **Single SMB connection per mount is fragile** - smbprotocol connections can drop on network blips. Must handle reconnection gracefully.
- **WinFsp callbacks run on arbitrary threads** - smbprotocol is not thread-safe per-connection. Use a lock per SMB connection or a dedicated I/O thread with a queue.
- **Directory listing can be slow** - cache READDIR results with a configurable TTL.
- **File metadata (size, dates) must be accurate** - Windows Explorer and media players rely on correct file sizes for seek/progress. Query attributes on open, cache them.
- **Large reads must not block the FUSE thread pool** - WinFsp has a limited thread pool. Keep reads fast by reading directly from the SMB connection (already async at the TCP level).
- **Write support is secondary** - reads are the performance bottleneck. Writes through rclone are already 400 Mbps. Implement writes for completeness but don't over-optimize.
- **Credential handling** - password stored in config.toml (same security posture as rclone.conf). Do not log passwords.

## Architecture decisions

- One SMB `Connection` + `Session` + `TreeConnect` per mount point (M:, Y:, Z:). Each mount runs in its own thread.
- File handles: map WinFsp file handles to smbprotocol `Open` objects. Track in a dict keyed by a handle ID.
- Read strategy: sequential reads use the configured read_size (default 4 MB). This is the single most important tunable.
- Caching: directory entries cached in memory with TTL. File content is NOT cached (let the OS page cache handle it via WinFsp's cache settings).
- Config: TOML file at `config.toml` in project root. Passwords can alternatively come from environment variables.

## File structure

```
nas-mount/
├── CLAUDE.md
├── README.md
├── config.example.toml     # Template config (no secrets)
├── config.toml             # Local config with credentials (gitignored)
├── requirements.txt
├── nas_mount.py            # Entry point - arg parsing, mount orchestration
├── smb_client.py           # SMB connection wrapper with reconnect logic
├── fuse_fs.py              # WinFsp filesystem implementation
└── tests/
    └── test_smb_client.py  # Connection and read tests
```

## Development commands

```powershell
# Install dependencies
pip install -r requirements.txt

# Run the mount
python nas_mount.py

# Run with debug logging
python nas_mount.py --debug

# Test SMB connection only (no mount)
python nas_mount.py --test
```

## Proven benchmarks (from testing session 2026-07-18)

These results are from `smb_bench.py` using smbprotocol against example.org:3445:

| Read size | Speed | Notes |
|-----------|-------|-------|
| 64 KB | 1.3 MB/s | rclone's hardcoded limit |
| 256 KB | 4.0 MB/s | |
| 1 MB | 7.0 MB/s | |
| 4 MB | 10.7 MB/s | **Target** - 86% of line speed |

Server-side Samba tuning (already applied on TrueNAS):
```
smb2 max read = 8388608
smb2 max write = 8388608
smb2 max trans = 8388608
```

## Gotchas

- **Sandbox**: Claude Code's shell runs in a filesystem sandbox. Use `dangerouslyDisableSandbox: true` for any command that needs real filesystem/network access (mounting drives, testing SMB connections).
- **Port 445**: Windows kernel reserves port 445. The remote server is on port 3445 (socat proxy on gateway forwards to TrueNAS:445).
- **winfspy install**: may need Visual C++ build tools if no wheel is available. Check `pip install winfspy` first.
- **Process lifetime**: the FUSE mount runs as long as the process lives. For auto-start, use a scheduled task or Windows service wrapper.

## Coding agents

Plans go in `.claude/plans`, no exceptions.