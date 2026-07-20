# Architecture

## Overview

Three files, five phases. A Python FUSE filesystem using WinFsp (via winfspy) and smbprotocol to mount remote TrueNAS SMB shares as Windows drive letters with 4 MB reads.

```
Windows App  →  WinFsp kernel driver  →  fuse_fs.py (callbacks)  →  smb_client.py (thread-safe)  →  SMB over WAN  →  TrueNAS
                                              ↑                          ↑
                                     SmbFileSystemOperations       One lock per connection
                                     (BaseFileSystemOperations)    serializes all SMB ops
```

## File Responsibilities

| File | Role | Key Class |
|------|------|-----------|
| smb_client.py | SMB connection wrapper — connect, read, write, list, stat, reconnect. One lock serializes all ops (smbprotocol isn't thread-safe) | `SMBClient` |
| fuse_fs.py | WinFsp callbacks — translates FUSE ops to SMB calls, manages dir cache and file contexts | `SmbFileSystemOperations(BaseFileSystemOperations)` |
| nas_mount.py | Entry point — config loading (tomllib), arg parsing, creates one SMBClient + FileSystem per mount letter, signal handling | orchestration |

## Key Design Decisions

- **Lock per connection** (not a queue/thread) — simpler, and the bottleneck is 37ms network RTT not lock contention
- **No Python file content cache** — Windows kernel cache handles this when `file_info_timeout > 0`
- **Dir cache with TTL** — simple dict, configurable TTL (default 300s), invalidated on create/delete/rename
- **Fixed security descriptor** — "full access everyone" avoids translating SMB ACLs
- **1:1 mapping** — each WinFsp `open()` creates one SMB Open handle, stored in `SmbFileContext`
- **Path subpath support** — `M = "storage/media"` → share is `storage`, FUSE root is `media/` subdirectory

## SMB Client (smb_client.py)

### Connection Setup

One `SMBClient` per mount. Each owns:
- `smbprotocol.connection.Connection` (one TCP socket)
- `smbprotocol.session.Session` (one authenticated session)
- `smbprotocol.tree.TreeConnect` (one share connection)
- `threading.Lock` — all SMB operations go through this lock

### Public Methods (all acquire lock)

- `connect()` — establish Connection, Session, TreeConnect
- `disconnect()` — clean teardown
- `reconnect()` — disconnect + connect with exponential backoff
- `open_file(path, access, disposition, options)` → Open
- `close_file(open_handle)`
- `read_file(open_handle, offset, length)` → bytes
- `write_file(open_handle, data, offset)` → int
- `list_directory(path)` → list[dict]
- `stat_path(path)` → dict
- `flush_file(open_handle)`

### Reconnection Strategy

Every public method wraps SMB calls in try/except for connection errors. On failure:
1. Log the error
2. Call `_reconnect()` with exponential backoff (5s, 10s, 20s, ... up to `max_reconnect_attempts`)
3. Re-raise if reconnect fails — surfaces as NTSTATUS error in the FUSE layer
4. Do NOT auto-retry the original operation — Windows will retry

### Thread Safety

A single `threading.Lock` per `SMBClient` instance serializes all SMB operations. WinFsp's dispatcher has multiple threads, so concurrent callbacks serialize at the lock. Since the bottleneck is network RTT (37ms) not lock contention, this is adequate.

## FUSE Filesystem (fuse_fs.py)

### File Context

`SmbFileContext` — returned from `open()`/`create()`, stored by winfspy:
- `path` — path relative to share root
- `smb_open` — the open SMB file handle
- `is_directory` — bool
- `file_attributes`, `file_size`, `allocation_size` — cached metadata
- `creation_time`, `last_access_time`, `last_write_time`, `change_time` — FILETIME integers

### Callbacks (BaseFileSystemOperations)

**Phase 2 — Read-only (minimum viable mount):**
- `get_volume_info()` — hard-coded volume size and label
- `get_security_by_name(file_name)` — stat via cache or SMB, return fixed SD
- `open(file_name, create_options, granted_access)` → SmbFileContext
- `close(file_context)` — close SMB handle
- `get_file_info(file_context)` — return cached metadata from context
- `read(file_context, offset, length)` → bytes — the performance-critical path
- `read_directory(file_context, marker)` → list[dict]

**Phase 3 — Write support:**
- `create(file_name, ...)` — create new file/directory via SMB
- `write(file_context, buffer, offset, ...)` → bytes written
- `overwrite(file_context, ...)` — truncate file
- `flush(file_context)` — flush SMB handle
- `set_file_size(file_context, new_size, ...)`
- `cleanup(file_context, file_name, flags)` — handle delete flag
- `can_delete(file_context, file_name)` — check if directory is empty
- `rename(file_context, file_name, new_file_name, replace_if_exists)`
- `set_basic_info(...)` — update timestamps (no-op initially)
- `get_security(file_context)` — return fixed SD
- `set_security(...)` — no-op

### Path Translation

WinFsp delivers backslash paths (`\folder\file.txt`). SMB uses forward slashes (`folder/file.txt`). The config subpath (e.g., `media` from `storage/media`) is prepended to all paths.

### Directory Cache

Simple dict-based TTL cache:
- Key: normalized SMB directory path
- Value: `(timestamp, entries)` using `time.monotonic()`
- Serves `get_security_by_name` and `get_dir_info_by_name` to avoid extra roundtrips
- Invalidated on create/delete/rename

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
    file_system_name="nas-mount",
)
```

### Mount Orchestration

For each configured mount (e.g., `M = "storage/media"`):
1. Parse share path: split on first `/` → share_name (`storage`) + subpath (`media`)
2. Create `SMBClient` and connect
3. Create `SmbFileSystemOperations`
4. Create `winfspy.FileSystem` with volume params
5. Call `fs.start()`

Main loop blocks on `threading.Event().wait()` until Ctrl+C, then stops all mounts.

## Error Mapping

smbprotocol's `SMBResponseException` contains an NTSTATUS code from the server response. Extract it and raise the matching winfspy `NTStatusError`. Key mappings:
- `ObjectNameNotFound` → `NTStatusObjectNameNotFound`
- `AccessDenied` → `NTStatusAccessDenied`
- `ObjectNameCollision` → `NTStatusObjectNameCollision`
- `DirectoryNotEmpty` → `NTStatusDirectoryNotEmpty`
- Connection errors → attempt reconnect, then `STATUS_CONNECTION_DISCONNECTED`

## Implementation Phases

1. **SMB Client** — connect/disconnect, list_directory, stat, read, write, lock, reconnect. Testable with `--test` flag.
2. **Read-only FUSE mount** — minimal callbacks. Enough to browse in Explorer and play media.
3. **Write support** — create, write, delete, rename.
4. **Robustness** — dir caching, reconnection with backoff, full error mapping, logging.
5. **Multi-mount orchestration** — config loading, parallel mounts (M:, Y:, Z:), graceful Ctrl+C.
