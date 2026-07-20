# nas-mount

Custom Python FUSE filesystem that mounts remote TrueNAS SMB shares as Windows drive letters with tunable read sizes for maximum throughput over WAN links.

## Problem

rclone's SMB backend uses go-smb2 which hardcodes 64 KB reads. Over a 37ms WAN link, this limits throughput to ~5 MB/s (40 Mbps) due to the bandwidth-delay product: each read requires a full round-trip before the next can begin.

Python's `smbprotocol` library allows configurable read sizes. At 4 MB reads, the same link achieves **10.7 MB/s (86 Mbps)** — nearly saturating the 100 Mbps upload cap at the remote site.

## Architecture

```
Windows (local-site)                          client-site LAN
┌─────────────┐    WAN 37ms RTT    ┌──────────┐    <1ms    ┌──────────────┐
│ nas-mount   │───────────────────▶│ Gateway  │──────────▶│ TrueNAS CORE │
│ (WinFsp)    │  example.org:3445  │ socat    │  :445     │ Samba        │
│ M: Y: Z:    │                    │ (Debian) │           │ /mnt/storage │
└─────────────┘                    └──────────┘           └──────────────┘
     │
     ▼
  smbprotocol (4 MB reads)
```

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

# Mount a single share
python nas_mount.py --share media --drive M
```

## Configuration

Copy `config.example.toml` to `config.toml` and edit connection details:

```toml
[connection]
host = "example.org"
port = 3445
user = "herman"

[tuning]
read_size = 4194304    # 4 MB — proven optimal for 37ms RTT
write_size = 4194304
dir_cache_ttl = 300    # seconds

[mounts]
M = "storage/media"
Y = "storage/documents"
Z = "storage/backups"
```

## License

MIT
