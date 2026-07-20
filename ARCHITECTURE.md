# Architecture

## Overview

Three files, five phases. A Python FUSE filesystem using WinFsp (via winfspy) and smbprotocol to mount remote TrueNAS SMB shares as Windows drive letters with 4 MB reads and pipelined writes.

```
Windows App  →  WinFsp kernel driver  →  fuse_fs.py (callbacks)  →  smb_client.py  →  SMB over WAN  →  socat @ gateway  →  TrueNAS
                                              ↑                          ↑
                                     SmbFileSystemOperations       concurrent ops (smbprotocol is
                                     async read-ahead +            internally thread-safe); state
                                     pipelined write-behind        lock only for connect/reconnect
```

### Why the gateway proxy (socat) stays

The WAN path client-site→local-site has burst-sensitive behavior that FreeBSD 13.1's
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
- **1:1 mapping** — each WinFsp `open()` creates one SMB Open handle, stored in `SmbFileContext`
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
- `threading.Lock` — all SMB operations go through this lock

On connect, an echo request with `credit_request = (write_size / 64KB) * 4 + 32` pre-loads credits for pipelined writes.

### Public Methods (all acquire lock)

- `connect()` — establish Connection, Session, TreeConnect, request credits
- `disconnect()` — clean teardown
- `reconnect()` — disconnect + connect with exponential backoff
- `open_file(path, read, write)` → Open — always includes DELETE access
- `close_file(open_handle)`
- `read_file(open_handle, offset, length)` → bytes
- `write_file(open_handle, data, offset)` → int — pipelines chunks via `send=False`
- `list_directory(path)` → list[dict]
- `stat_path(path)` → dict
- `flush_file(open_handle)`
- `create_file(path, is_directory)` → Open — FILE_OPEN_IF for dirs, FILE_CREATE for files
- `delete_file(path)` — opens with FILE_DELETE_ON_CLOSE
- `delete_directory(path)` — same for directories
- `set_delete_on_close(open_handle)` — FileDispositionInformation on existing handle
- `set_end_of_file(open_handle, size)` — FileEndOfFileInformation via SMB2SetInfoRequest
- `rename(old_path, new_path, replace_if_exists)` — FileRenameInformation via SMB2SetInfoRequest

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
2. Call `_reconnect()` with exponential backoff (5s, 10s, 20s, ... capped at 60s, up to `max_reconnect_attempts`)
3. Re-raise if reconnect fails — surfaces as NTSTATUS error in the FUSE layer
4. Do NOT auto-retry the original operation — Windows will retry

### Thread Safety

smbprotocol's transport has its own socket send lock, the connection has a
sequence/credit lock, and responses are demultiplexed by a dedicated receiver
thread into per-request events — so SMB operations from multiple WinFsp
dispatcher threads run concurrently without serializing at a client-wide lock.
Streaming a movie no longer blocks Explorer metadata operations.

Per-file read/write state is guarded by `SmbFileContext.io_lock`; the
`SMBClient._state_lock` (RLock) covers connection lifecycle only, with
single-flight reconnect.

## FUSE Filesystem (fuse_fs.py)

### File Context

`SmbFileContext` — returned from `open()`/`create()`, stored by winfspy:
- `path` — WinFsp path (backslash-separated)
- `smb_path` — SMB path (with subpath prepended)
- `smb_open` — the open SMB file handle (or None for directories)
- `is_directory` — bool
- `file_attributes`, `file_size`, `allocation_size` — cached metadata
- `creation_time`, `last_access_time`, `last_write_time`, `change_time` — FILETIME integers
- `_buf`, `_buf_start`, `_buf_end` — read-ahead buffer
- `_wbuf`, `_wbuf_offset` — write-behind buffer
- `_delete_pending` — set in cleanup, used to invalidate cache in close

### Callbacks (BaseFileSystemOperations)

**Read-only (Phase 2):**
- `get_volume_info()` — hard-coded volume size and label
- `get_security_by_name(file_name)` — stat via cache or SMB, return fixed SD
- `open(file_name, create_options, granted_access)` → SmbFileContext — opens with write+delete access when requested
- `close(file_context)` — flush write buffer, close SMB handle, invalidate cache if delete pending
- `get_file_info(file_context)` — return cached metadata from context
- `read(file_context, offset, length)` → bytes — read-ahead: fetches `read_size` (4 MB) on cache miss, serves subsequent reads from buffer
- `read_directory(file_context, marker)` → list[dict] — TTL-cached, bisect for marker filtering

**Write support (Phase 3):**
- `create(file_name, ...)` — create new file/directory via SMB. FILE_OPEN_IF for dirs (idempotent)
- `write(file_context, buffer, offset, ...)` → bytes written — accumulates in write-behind buffer, flushes at `write_size * WRITE_PIPELINE_DEPTH` (16 MB)
- `overwrite(file_context, ...)` — truncate file via SetEndOfFile(0)
- `flush(file_context)` — drain write buffer + SMB flush
- `set_file_size(file_context, new_size, ...)` — SetEndOfFile via SMB2SetInfoRequest
- `cleanup(file_context, file_name, flags)` — handle delete flag via FileDispositionInformation on existing handle
- `can_delete(file_context, file_name)` — check directory is empty before allowing delete
- `rename(file_context, file_name, new_file_name, replace_if_exists)` — FileRenameInformation, invalidates both old and new parent caches
- `set_basic_info(...)` — update cached timestamps
- `set_security(...)` — no-op (fixed SD)

### Path Translation

WinFsp delivers backslash paths (`\folder\file.txt`). The config subpath (e.g., `media` from `storage/media`) is prepended: `\folder\file.txt` → `media\folder\file.txt`.

### Directory Cache

Simple dict-based TTL cache:
- Key: normalized SMB directory path
- Value: `(timestamp, entries)` using `time.monotonic()`
- Serves `get_security_by_name` and `read_directory` to avoid extra roundtrips
- A fresh listing answers negative lookups too (name absent → NOT_FOUND, 0 RTT)
- Invalidated on create/delete/rename (in `close()` for deletes, after the handle is actually closed)

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
    file_info_timeout=1000,         # 1s — enables kernel caching
    case_sensitive_search=0,
    case_preserved_names=1,
    unicode_on_disk=1,
    persistent_acls=0,
    read_only_volume=0,
    um_file_context_is_user_context2=1,
    file_system_name="nas-mount",
)
```

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

## Implementation Phases

1. **SMB Client** ✅ — connect/disconnect, list_directory, stat, read, write, lock, reconnect. Testable with `--test` flag.
2. **Read-only FUSE mount** ✅ — minimal callbacks with read-ahead buffer. Browse in Explorer, stream in mpv at 9.5 MB/s.
3. **Write support** ✅ — create, write (pipelined), delete, rename. 42-51 MB/s uploads through FUSE.
4. **Robustness** — reconnection with backoff ✅, full error mapping ✅, logging improvements ✅. Remaining: graceful degradation, health checks.
5. **Multi-mount orchestration** — config loading ✅, parallel mounts (M:, Y:, Z:) ✅, graceful Ctrl+C ✅. Remaining: `--drive` filter ✅, auto-start wrapper.
