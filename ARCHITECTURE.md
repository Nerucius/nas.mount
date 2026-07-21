# Architecture

## Overview

A Python FUSE filesystem using smbprotocol to mount remote TrueNAS SMB shares
as Windows drive letters (WinFsp/winfspy) or macOS volumes (FUSE-T/fusepy),
with 4 MB pipelined transfers and compounded/cached metadata.

```
Windows App                    Finder / macOS app
     │                                │
WinFsp kernel driver           FUSE-T (NFSv4 loopback)
     │                                │
fuse_fs.py (NTSTATUS)          macos_fs.py (errno)
     └────────────┬───────────────────┘
             fs_core.py    — read-ahead windows, write coalescing + pipeline,
                  │           dir/stat caches, lazy opens, async deletes
             smb_client.py — pipelined reads/writes, compound metadata ops,
                  │           credit negotiation, single-flight reconnect
             SMB2 over WAN → socat @ gateway → TrueNAS Samba
```

### Why the gateway proxy (socat) stays

The WAN path has burst-sensitive behavior that FreeBSD 13.1's
base TCP stack (no RACK/pacing, TrueNAS CORE ships no alternative stack) handles
terribly as a sender: measured 10 Mbps with ~28% retransmit storms, while a
Linux sender achieves 77-92 Mbps with zero retransmits on the same path minute
by minute (validated with iperf3 + packet captures, 2026-07-20). Kernel-level
DNAT forwarding was tried and root-caused; split TCP at the gateway gives both
WAN directions a modern Linux sender. socat runs as a systemd unit
(`smb-relay.service`, 1 MB blocks, TCP_NODELAY, no explicit socket buffers so
Linux autotuning stays active).

## File Responsibilities

| File | Role | Key Class |
|------|------|-----------|
| smb_client.py | SMB connection wrapper — connect, pipelined reads (`read_file_pipelined`), sliding-window writes (`PipelinedWriter`), list, stat, rename, delete, single-flight reconnect. Concurrent ops (smbprotocol is internally thread-safe) | `SMBClient` |
| fs_core.py | Platform-agnostic engine — async read-ahead windows, write coalescing + backpressure, dir cache, path mapping, `FsError` taxonomy. Paths backslash-separated, timestamps FILETIME, attrs Windows bits | `FsCore`, `FileHandle` |
| fuse_fs.py | Windows adapter — WinFsp callbacks over FsCore: NTSTATUS mapping, security descriptors, delete-on-close semantics, readdir markers | `SmbFileSystemOperations(BaseFileSystemOperations)` |
| macos_fs.py | macOS adapter — fusepy (FUSE-T) callbacks over FsCore: errno mapping, epoch timestamps, POSIX unlink/rename, xattr fast-fail, handle table | `SmbMacOperations(Operations)` |
| nas_mount.py | Entry point — config loading (tomllib), arg parsing, platform dispatch (win32 → winfspy, darwin → fusepy threads), benchmarks | orchestration |

## Key Design Decisions

- **Concurrent SMB ops, no global lock** — smbprotocol's Connection is internally
  thread-safe (socket send lock, sequence/credit lock, dedicated receiver thread
  with per-request events). A state lock only covers connect/disconnect, and
  reconnects are single-flight.
- **Pipelined reads** — `read_file_pipelined()` keeps `read_pipeline_depth`
  (default 3) read requests in flight via `send=False`, so the pipe never
  drains between 4 MB chunks. Measured at the full 100 Mbps line rate vs
  87 Mbps for stop-and-go single requests.
- **Async read-ahead** — per-file windows (window = read_size) prefetched by a
  shared thread pool. Sequential readers cross the midpoint of a window and the
  next `readahead_windows` windows are scheduled in the background; the
  consumer never waits on the network in steady state. Random seeks drop the
  window chain and fetch synchronously.
- **Continuous write-behind** — WinFsp's ~1 MB writes coalesce into write_size
  chunks and feed a per-handle `PipelinedWriter` holding `write_pipeline_depth`
  (default 4) requests in flight. submit() blocks when the window is full
  (backpressure), so memory stays bounded and the connection never idles
  between chunks or batches. No fill-drain-fill stalls.
- **Write/read consistency** — reads drain pending writes first; overwrite,
  set_file_size and rename drain/discard coherently; `constrained_io` writes
  never extend the file.
- **No Python file content cache** — Windows kernel cache handles this when `file_info_timeout > 0`
- **Dir cache with TTL** — simple dict, configurable TTL (default 300s), invalidated on create/delete/rename
- **Fixed security descriptor** — "full access everyone" avoids translating SMB ACLs
- **1:1 mapping** — each adapter `open()` yields one `FileHandle`; its SMB Open materializes lazily on the first data operation
- **Path subpath support** — `M = "storage/media"` → share is `storage`, FUSE root is `media/` subdirectory
- **Metadata in one round trip or none** — browsing is metadata-bound at 41 ms
  RTT, so every metadata operation is either compounded or cached:
  - `stat_path` = CREATE+CLOSE related compound (1 RTT, the create response
    carries all metadata); `list_directory` = CREATE+QUERY(1 MB)+CLOSE compound
    (1 RTT for dirs provably complete in one page, paged loop above ~1600
    entries — which also fixed a silent-truncation bug for huge dirs).
  - A fresh cached listing is authoritative for **negatives** too: Explorer's
    desktop.ini/Thumbs.db probes on every folder visit cost zero round trips.
  - Stat results (positive and negative) get their own TTL cache — Explorer
    re-walks the ancestor chain of every path it touches.
- **Lazy open + compound sniff** — a cache-hit open() defers the SMB CREATE
  until the first data operation (most Explorer opens only read attributes we
  already have). When the first read is small (≤ 256 KB), CREATE+READ go out
  as one compound: open-and-sniff = 1 RTT. First-touch small reads fetch a
  256 KB head instead of a full 4 MB window (upgraded in place if reading
  continues), so a folder of images doesn't pull megabytes per thumbnail probe.
  Clean read-only handles close in the background (no close RTT on the caller).
- **Surgical cache edits + pipelined deletes** — bulk namespace changes
  (Explorer deleting/copying/renaming hundreds of files) edit the caches in
  place instead of invalidating the parent per file, so every subsequent
  lookup/open in the batch stays warm. Deletes are 1-RTT compounds
  (CREATE+CLOSE with delete-on-close) fired in the background and keyed by
  parent; ordering-sensitive ops (rmdir, create, rename, live listing) drain
  per-parent first, and directory deletes are synchronous so a finished
  folder delete is really on the server. Renames are CREATE+SET_INFO+CLOSE
  compounds (1 RTT). Measured: folder of 30 files deletes at ~10 ms/file vs
  ~125 ms/file before. `dir_info_timeout` (default 1000 ms) is split from
  `file_info_timeout` so the kernel's enumeration cache can't show a rename
  or delete as unapplied for seconds.
- **Cheap cold opens** — open() consults the dir cache only; on a miss it opens
  the SMB handle directly (the create response carries all metadata) instead of
  listing the whole parent directory first.
- **Credit negotiation** — echo-request credits on connect until the pool covers
  both pipelines; every pipelined request asks for replenishment; senders drain
  in-flight responses when the sequence window runs low (smbprotocol raises
  rather than blocks on credit exhaustion).

## SMB Client (smb_client.py)

### Connection Setup

One `SMBClient` per unique share name. Multiple mounts to the same share reuse one client. Each owns:
- `smbprotocol.connection.Connection` (one TCP socket)
- `smbprotocol.session.Session` (one authenticated session)
- `smbprotocol.tree.TreeConnect` (one share connection)
- `threading.RLock` (`_state_lock`) — connection lifecycle only; SMB
  operations themselves run concurrently (smbprotocol is internally
  thread-safe)

On connect, echo requests loop until the credit pool covers both pipelines
(`per_op_credits * (read_depth + write_depth) + 64`).

### Public Methods

- `connect()` — establish Connection, Session, TreeConnect, request credits
- `disconnect()` — clean teardown
- `reconnect()` — disconnect + connect with exponential backoff
- `open_file(path, read, write)` → Open — always includes DELETE access
- `open_and_read(path, length, write)` → (Open, bytes) — CREATE+READ
  compound: open-and-sniff in one round trip
- `close_file(open_handle)`
- `read_file(open_handle, offset, length)` → bytes — single request
- `read_file_pipelined(open_handle, offset, length)` → bytes — sliding
  window of `read_pipeline_depth` requests
- `make_writer(open_handle)` → PipelinedWriter
- `write_file(open_handle, data, offset)` → int — pipelines chunks via `send=False`
- `list_directory(path)` → list[dict] — CREATE+QUERY(1 MB)+CLOSE compound
  (1 RTT); paged loop for directories above ~1600 entries
- `stat_path(path)` → dict — CREATE+CLOSE compound (1 RTT)
- `query_volume_info()` → dict — total/free size
- `flush_file(open_handle)`
- `create_file(path, is_directory)` → Open — FILE_OPEN_IF for dirs, FILE_CREATE for files
- `delete_file(path)` / `delete_directory(path)` —
  CREATE(delete-on-close)+CLOSE compound (1 RTT)
- `set_delete_on_close(open_handle)` — FileDispositionInformation on existing handle
- `set_end_of_file(open_handle, size)` — FileEndOfFileInformation via SMB2SetInfoRequest
- `rename(old_path, new_path, replace_if_exists)` —
  CREATE+SET_INFO(FileRenameInformation)+CLOSE compound (1 RTT)

### Write Pipelining

`PipelinedWriter` (one per open handle) maintains a sliding window:
1. `submit(data, offset)` splits into `write_size` chunks; each chunk is built
   via `file_open.write(..., send=False)` and sent with a credit replenishment
   request.
2. When `write_pipeline_depth` requests are in flight, submit blocks collecting
   the oldest response before sending the next chunk — a true sliding window,
   not batch-and-drain, so there is no bubble between batches.
3. `drain()` collects everything outstanding; errors surface to the caller.

The FUSE write callback returns as soon as its chunk is queued, so the copy
source keeps producing while the network transmits.

### Reconnection Strategy

Every public method wraps SMB calls in try/except for connection errors. On failure:
1. Log the error
2. Echo-probe the current connection first — an error from a stale handle
   (opened before a previous reconnect) must not tear down a healthy
   connection
3. Call `_reconnect()` with exponential backoff (5s, 10s, 20s, ... capped at
   60s, up to `max_reconnect_attempts`), single-flight across threads
4. Re-raise if reconnect fails — surfaces as NTSTATUS/errno in the adapter
5. Do NOT auto-retry the original operation — the OS retries

### Thread Safety

smbprotocol's transport has its own socket send lock, the connection has a
sequence/credit lock, and responses are demultiplexed by a dedicated receiver
thread into per-request events — so SMB operations from multiple WinFsp
dispatcher threads run concurrently without serializing at a client-wide lock.
Streaming a movie no longer blocks Explorer metadata operations.

Per-file read/write state is guarded by `FileHandle.io_lock`; the
`SMBClient._state_lock` (RLock) covers connection lifecycle only, with
single-flight reconnect. FsCore's shared thread pool (readahead_workers)
carries prefetches, background closes and background deletes.

## Adapters (fuse_fs.py / macos_fs.py)

### File Handle

`fs_core.FileHandle` — returned from `open_handle()`/`create_handle()`,
stored by winfspy as the file context (the macOS adapter maps fh integers to
it):
- `path` — adapter path (backslash-separated)
- `smb_path` — SMB path (with subpath prepended)
- `smb_open` — the SMB file handle, or None for directories and **lazy
  opens** (cache-hit opens defer the CREATE until the first data op;
  `want_write` records the access to materialize with)
- `is_directory` — bool
- `file_attributes`, `file_size`, `allocation_size` — cached metadata
- `creation_time`, `last_access_time`, `last_write_time`, `change_time` — FILETIME integers
- `io_lock` — serializes read/write state per handle
- `ra_windows` (LRU), `ra_futures`, `ra_partial` — read-ahead window cache,
  in-flight prefetches, head-fetch markers
- `writer`, `wsegs` — pipelined writer + out-of-order-tolerant segment
  coalescer
- `delete_pending`, `dirty` — set in cleanup/write, drive surgical cache
  updates at close

### Windows callbacks (fuse_fs.py, thin over FsCore)

- `get_volume_info()` — real total/free via FileFsFullSizeInformation, 60 s cached
- `get_security_by_name(file_name)` — `lookup_or_stat` (caches, 0-1 RTT), fixed SD
- `open(...)` → FileHandle — lazy on cache hit (0 RTT)
- `close(file_context)` — drain writes if dirty; clean read-only handles
  close in the background
- `read(file_context, offset, length)` — read-ahead windows + head-fetch fast path
- `read_directory(file_context, marker)` — TTL-cached, bisect for marker filtering
- `create(file_name, ...)` — SMB create; inserts the entry into the parent's
  cached listing
- `write(...)` — segment coalescer feeding the pipelined writer with backpressure
- `overwrite` / `set_file_size` — SetEndOfFile; updates caches in place
- `flush(file_context)` — drain + SMB FLUSH
- `cleanup(file_context, file_name, flags)` — delete-on-close: background
  1-RTT compound delete (directories synchronous)
- `can_delete(file_context, file_name)` — drains pending deletes, then
  checks the directory is empty
- `rename(...)` — 1-RTT compound; moves the cached entry
- `set_basic_info(...)` — update cached timestamps
- `set_security(...)` — no-op (fixed SD)

The macOS adapter (`macos_fs.py`) exposes the same core through fusepy:
errno mapping, epoch timestamps, POSIX unlink/rename, `flush/fsync →
flush(sync_disk=False)` (NFS COMMIT), an in-memory sink for AppleDouble
`._*`/`.DS_Store` junk, and xattr accept-and-drop.

### Path Translation

WinFsp delivers backslash paths (`\folder\file.txt`). The config subpath (e.g., `media` from `storage/media`) is prepended: `\folder\file.txt` → `media\folder\file.txt`.

### Directory Cache

Simple dict-based TTL cache:
- Key: normalized SMB directory path
- Value: `(timestamp, entries)` using `time.monotonic()`
- Serves `get_security_by_name` and `read_directory` to avoid extra roundtrips
- A fresh listing answers negative lookups too (name absent → NOT_FOUND, 0 RTT)
- Our own mutations edit it surgically (create inserts, dirty close/truncate
  updates in place, delete removes + plants a negative stat, rename moves the
  entry) so bulk operations never blow the listing away per file

Plus a stat cache (`_stat_cache`): positive and negative single-path stat
results with the same TTL, invalidated together with the parent listing
(prefix scan covers renamed/deleted subtrees). Accepted staleness: files
created/removed remotely appear/disappear within `dir_cache_ttl`, same
contract as the listing cache.

## Entry Point (nas_mount.py)

### Volume Params

```python
FileSystem(
    mountpoint="M:",
    operations=ops,
    sector_size=4096,
    sectors_per_allocation_unit=1,
    file_info_timeout=5000,         # kernel caches file metadata 5s
    dir_info_timeout_valid=1,
    dir_info_timeout=1000,          # ...but listings only 1s, so renames/
                                    # deletes show promptly on refresh
    case_sensitive_search=0,
    case_preserved_names=1,
    unicode_on_disk=1,
    persistent_acls=0,
    read_only_volume=0,
    post_cleanup_when_modified_only=1,
    um_file_context_is_user_context2=1,
    file_system_name="nas-mount",
)
```

On macOS the equivalents are FUSE-T mount options: `rwsize=1048576` (default
32 KB callbacks), `daemon_timeout=600`, `noappledouble`, volname per mount.

### Mount Orchestration

For each configured mount (e.g., `M = "storage/media"`):
1. Parse share path: split on first `/` → share_name (`storage`) + subpath (`media`)
2. Reuse or create `SMBClient` for the share name
3. Create `SmbFileSystemOperations` with client and subpath
4. Create `winfspy.FileSystem` with volume params
5. Call `fs.start()`

Main loop blocks on `threading.Event().wait()` until Ctrl+C, then stops all mounts.

## Error Mapping

smbprotocol's `SMBResponseException` contains an NTSTATUS code. Key mappings:
- `0xC0000034` (ObjectNameNotFound) → `NTStatusObjectNameNotFound`
- `0xC000003A` (ObjectPathNotFound) → `NTStatusObjectNameNotFound`
- `0xC0000103` (NotADirectory) → `NTStatusObjectNameNotFound` (Explorer probing zips)
- `0xC0000022` (AccessDenied) → `STATUS_ACCESS_DENIED`
- `0xC0000035` (NameCollision) → `STATUS_OBJECT_NAME_COLLISION`
- `0xC0000043` (SharingViolation) → `STATUS_SHARING_VIOLATION`
- `0xC0000101` (DirectoryNotEmpty) → `NTStatusDirectoryNotEmpty`
- Connection errors → attempt reconnect, then `STATUS_UNEXPECTED_IO_ERROR`

## Status

All phases complete: SMB client with pipelined+compounded ops, Windows and
macOS mounts sharing the fs_core engine, reconnect with single-flight backoff
and echo health checks, full error mapping, multi-mount orchestration with
graceful shutdown (drains background deletes), and auto-start on both
platforms (`mount.ps1` scheduled task, `mount.sh` launchd agent — see
README). Measured at line rate both directions; metadata benchmarks in
CLAUDE.md.

Known limitation: open file handles do not survive a reconnect (no durable
handles) — a network blip during an active stream errors that stream once;
reopening recovers.
