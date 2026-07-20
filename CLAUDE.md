# CLAUDE.md

## Project overview

A Python FUSE filesystem using WinFsp (via winfspy) and smbprotocol to mount remote TrueNAS SMB shares as Windows drive letters with configurable read sizes. The key value prop is 4 MB SMB reads instead of rclone's hardcoded 64 KB, which yields ~8x read throughput and ~40x write throughput on high-latency WAN links.

## Tech stack

- **Windows 10** (primary) and **macOS** (Apple Silicon) - both mount the same shares.
- **Python 3.11** - `.venv` contains the env with packages installed.
- **winfspy** (v0.8.4, Windows only) - Python bindings for WinFsp. WinFsp is already installed (used by rclone).
- **fusepy + FUSE-T** (macOS only) - kextless FUSE; `brew install fuse-t`. macos_fs.py auto-detects the libfuse-t dylib.
- **smbprotocol** (v1.17.0) - pure Python SMB2/3 client, pipelined via `send=False`; internally thread-safe.
- **toml** - config file format (stdlib tomllib for reading).

## Key constraints

- **Single SMB connection per mount** - smbprotocol connections can drop on network blips. Reconnect logic with exponential backoff handles this (single-flight across threads).
- **WinFsp callbacks run on arbitrary threads** - smbprotocol's Connection IS internally thread-safe (socket send lock, sequence/credit lock, receiver thread with per-request events), so SMB ops run concurrently. Only connect/reconnect is serialized via a state lock; per-file buffer state is guarded by a per-context lock.
- **Directory listing can be slow** - cache READDIR results with configurable TTL (default 300s). Invalidated on create/delete/rename. Browsing is metadata-bound at 41ms RTT, so metadata ops are compounded (stat = CREATE+CLOSE, listing = CREATE+QUERY+CLOSE, each 1 RTT), fresh listings answer negative probes (desktop.ini/Thumbs.db) with 0 RTT, stat results have their own TTL cache, file opens are lazy (SMB CREATE deferred to first data op; small first read = compound CREATE+READ), and clean read-only closes happen in the background. Explorer folder paint went from ~4s to instant-warm/~0.3s-cold; per-file sniffs from ~170ms to ~76ms.
- **Bulk namespace ops (delete/rename/copy)** - the Windows shell deletes folders file-by-file, serially. Deletes are 1-RTT compounds fired in the background (parent-scoped draining before rmdir/create/rename/relisting; dir deletes sync); renames are CREATE+SET_INFO+CLOSE compounds. Caches are edited surgically (insert/update/remove/move) instead of invalidating the parent per file, so bulk batches stay warm. 30-file folder delete: ~10ms/file (was ~125). `dir_info_timeout` (1s) is split from `file_info_timeout` (5s) so renames/deletes never look unapplied on refresh.
- **File metadata (size, dates) must be accurate** - Windows Explorer and media players rely on correct file sizes for seek/progress. Cached in SmbFileContext on open.
- **SMB credits limit request sizes** - server grants credits incrementally. Client requests credits on connect via echo and with each pipelined write. 64 credits = 4 MB max per single request.
- **Credential handling** - password stored in config.toml (same security posture as rclone.conf). Do not log passwords.

## Architecture decisions

- One SMB `Connection` + `Session` + `TreeConnect` per unique share name. Multiple mounts to the same share reuse one connection.
- File handles: WinFsp `open()`/`create()` returns `SmbFileContext` wrapping an smbprotocol `Open` object.
- Read strategy: pipelined reads (`read_pipeline_depth` in flight via `send=False`) + async read-ahead — a shared thread pool prefetches the next `readahead_windows` 4 MB windows while the consumer drains the current one. Small reads (mpv 64 KB seeks) served from memory; sequential streams never stall on the network.
- Write strategy: WinFsp's ~1 MB writes coalesce into 4 MB chunks feeding a per-handle `PipelinedWriter` sliding window (`write_pipeline_depth` in flight). `submit()` applies backpressure when full; the connection never idles between chunks. Reads drain pending writes first (consistency).
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
├── nas_mount.py            # Entry point - arg parsing, platform dispatch, benchmarks
├── smb_client.py           # SMB connection wrapper: pipelined reads/writes, reconnect
├── fs_core.py              # Platform-agnostic engine: read-ahead, write pipeline, caches
├── fuse_fs.py              # Windows adapter (winfspy/WinFsp) over fs_core
├── macos_fs.py             # macOS adapter (fusepy/FUSE-T) over fs_core
└── mount.ps1               # Windows auto-mount scheduled-task helper
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

## Proven benchmarks (raw smbprotocol from macOS over real WAN, 2026-07-20, ~41ms RTT)

Reads (line rate = client-site 100 Mbps uplink):

| Mode | Speed | Notes |
|-----------|-------|-------|
| 64 KB single | 1.2 MB/s | rclone's hardcoded limit |
| 4 MB single | 10.9 MB/s | old stop-and-go read path |
| **4 MB pipelined x3** | **12.5 MB/s (100 Mbps)** | **new path - line rate, done** |

Writes (ceiling: iperf3 measured 511-581 Mbps end-to-end):

| Mode | Speed | Notes |
|------|-------|-------|
| Old batch pipeline (Windows, FUSE) | 42-51 MB/s | fill-drain-fill stalls |
| New sliding window (Mac, raw, 96 MB) | 40-48 MB/s | short-transfer TCP ramp dominates |
| New sliding window (Mac, raw, 192 MB) | 57 MB/s (458 Mbps) | client CPU only 8-11% |

Depth sweeps showed write_size=4MB/depth=4-6 is the sweet spot; deeper/larger doesn't help.
SMB signing cannot be disabled client-side (Samba rejects unsigned TreeConnect).

Mounted filesystems, final results (2026-07-21). Line rates: reads capped by
client-site's 100 Mbps uplink, writes by its 600 Mbps downlink:

| Platform | Read | Write | Notes |
|----------|------|-------|-------|
| Windows (WinFsp, Explorer, 2 GB sustained) | **12.8 MB/s** | **76 MB/s (608 Mbps)** | both directions AT line rate |
| macOS (FUSE-T, dd 192 MB) | **12.7 MB/s** | 50-54 MB/s | mac writes pay the NFS out-of-order tax; native macOS SMB does 11.1/42 |

Key macOS/FUSE-T lessons (why fs_core is shaped the way it is):
- FUSE-T = NFSv4 loopback; kernel interleaves its own readahead so reads
  arrive out of order -> LRU window cache, never purge on seek.
- NFS writeback delivers 32 KB writes out of order -> overlap-merging
  segment coalescer; and COMMITs every few MB -> flush(sync_disk=False).
- rwsize=1048576 mount option (default 32 KB callbacks).
- macOS NFS has no xattr path; falls back to AppleDouble ._* files which
  Samba fruit vetoes -> in-memory junk-file sink (also .DS_Store).

Server-side Samba tuning (applied on TrueNAS via midclt, persisted):
```
smb2 max read = 8388608
smb2 max write = 8388608
smb2 max trans = 8388608
smb2 max credits = 8192
use sendfile = yes
aio read size = 1
aio write size = 1
min receivefile size = 16384
```
(`socket options` line REMOVED 2026-07-20 - it pinned 512 KB buffers and set
IPTOS_LOWDELAY; Samba's default TCP_NODELAY + FreeBSD autotuning is correct.)

FreeBSD sysctls persisted as TrueNAS tunables: `kern.ipc.maxsockbuf=16M`,
`net.inet.tcp.sendbuf_max=8M`, `recvbuf_max=8M`, `sendbuf_inc=64K`.

## Gotchas

- **Sandbox**: Claude Code's shell runs in a filesystem sandbox. Use `dangerouslyDisableSandbox: true` for any command that needs real filesystem/network access (mounting drives, testing SMB connections).
- **Port 445**: Windows kernel reserves port 445. The remote server is on port 3445 (socat proxy on gateway forwards to TrueNAS:445).
- **DO NOT replace socat with kernel DNAT**: tried and root-caused 2026-07-20. FreeBSD 13.1's base TCP stack (TrueNAS CORE, no RACK/pacing modules) collapses to ~10 Mbps with retransmit storms as a WAN sender on this path, while a Linux sender does 77-92 Mbps clean (iperf3 + captures prove the path itself is loss-free: UDP 80 Mbps = 0%). Split TCP at the gateway gives both WAN directions a Linux sender. socat now runs as systemd unit `smb-relay.service` on the gateway (1 MB blocks, nodelay, no nice, autostart).
- **winfspy install**: may need Visual C++ build tools if no wheel is available. Check `pip install winfspy` first.
- **Process lifetime**: the FUSE mount runs as long as the process lives. For auto-start, use a scheduled task or Windows service wrapper.
- **SMB credits**: smbprotocol defaults to requesting minimal credits. We echo-request credits on connect and request replenishment with each pipelined write. Without this, 8 MB writes fail with "not enough credits".

## Coding agents

Plans go in `.claude/plans`, no exceptions.
Don't use `gh`, this repo uses a PAT to act as the github link and all commits should be under the user defined in conf.toml. 
