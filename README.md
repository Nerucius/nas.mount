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

| Method | Reads | Throughput |
|--------|-----------|------------|
| rclone SMB (64 KB) | 5.0 MB/s | 40 Mbps |
| nas-mount single 4 MB | 10.9 MB/s | 87 Mbps |
| nas-mount pipelined | **12.5 MB/s** | **100 Mbps — line rate** |

Writes: sliding-window pipeline measured at 57 MB/s (458 Mbps) raw; the
end-to-end TCP ceiling on this path is ~580 Mbps.

## Requirements

- Windows 10/11
- [WinFsp](https://winfsp.dev/) (FUSE for Windows)
- Python 3.10+

## Installation

```
pip install -r requirements.txt
```

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
