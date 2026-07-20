# Architecture

## Overview

Three files, five phases. A Python FUSE filesystem using WinFsp (via winfspy) and smbprotocol to mount remote TrueNAS SMB shares as Windows drive letters with 4 MB reads and pipelined writes.

```
Windows App  →  WinFsp kernel driver  →  fuse_fs.py (callbacks)  →  smb_client.py (thread-safe)  →  SMB over WAN  →  TrueNAS
                                              ↑                          ↑
                                     SmbFileSystemOperations       One lock per connection
                                     (BaseFileSystemOperations)    serializes all SMB ops
```

## File Responsibilities

| File | Role | Key Class |
|------|------|-----------|
| smb_client.py | SMB connection wrapper — connect, read, write (pipelined), list, stat, rename, delete, reconnect. One lock serializes all ops (smbprotocol isn't thread-safe) | `SMBClient` |
| fuse_fs.py | WinFsp callbacks — translates FUSE ops to SMB calls, manages dir cache, read-ahead buffer, and write-behind buffer | `SmbFileSystemOperations(BaseFileSystemOperations)` |
| nas_mount.py | Entry point — config loading (tomllib), arg parsing, creates one SMBClient + FileSystem per mount letter, signal handling | orchestration |

## Key Design Decisions

- **Lock per connection** (not a queue/thread) — simpler, and the bottleneck is 37ms network RTT not lock contention
- **No Python file content cache** — Windows kernel cache handles this when `file_info_timeout > 0`
- **Dir cache with TTL** — simple dict, configurable TTL (default 300s), invalidated on create/delete/rename
- **Fixed security descriptor** — "full access everyone" avoids translating SMB ACLs
- **1:1 mapping** — each WinFsp `open()` creates one SMB Open handle, stored in `SmbFileContext`
- **Path subpath support** — `M = "storage/media"` → share is `storage`, FUSE root is `media/` subdirectory
- **Read-ahead buffer** — per-file 4 MB prefetch; small reads (mpv seeks) served from memory
- **Write-behind buffer** — accumulates WinFsp's 1 MB writes into 16 MB batches before flushing
- **Pipelined writes** — flush sends 4x 4 MB writes simultaneously via `send=False`, collects responses after. 2.76x faster than sequential at the raw SMB level
- **Credit negotiation** — echo-request credits on connect; request replenishment with each pipelined write

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

`_write_file()` splits data into `write_size` chunks (4 MB default). If multiple chunks:
1. Build each SMB2WriteRequest via `file_open.write(data, offset, send=False)`
2. Send all requests via `connection.send()` with `credit_request` for replenishment
3. Collect all responses via `recv_func(request)`

This overlaps network latency across chunks. At 37ms RTT, 4 pipelined writes complete in ~40ms total instead of ~150ms sequential.

### Reconnection Strategy

Every public method wraps SMB calls in try/except for connection errors. On failure:
1. Log the error
2. Call `_reconnect()` with exponential backoff (5s, 10s, 20s, ... capped at 60s, up to `max_reconnect_attempts`)
3. Re-raise if reconnect fails — surfaces as NTSTATUS error in the FUSE layer
4. Do NOT auto-retry the original operation — Windows will retry

### Thread Safety

A single `threading.Lock` per `SMBClient` instance serializes all SMB operations. WinFsp's dispatcher has multiple threads, so concurrent callbacks serialize at the lock. Since the bottleneck is network RTT (37ms) not lock contention, this is adequate.

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
- Invalidated on create/delete/rename (in `close()` for deletes, after the handle is actually closed)

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
