# Plan: macOS support (2026-07-21)

## Goal

Mount the same config.toml shares on macOS (M5 MacBook Pro) with the exact same
performance engine — pipelined reads at line rate, sliding-window writes,
async read-ahead — sharing all perf-critical code with the Windows build.

## Bar to beat (measured 2026-07-20, native macOS SMB via tuned socat relay)

| Path | Reads | Writes |
|------|-------|--------|
| Native `mount_smbfs //…:445/storage` | 11.1 MB/s (89 Mbps) | 42 MB/s (336 Mbps) |
| Our engine, raw (same Mac) | **12.5 MB/s (line rate)** | **57 MB/s (458 Mbps)** |

Native is the zero-code fallback (`open 'smb://user@example.org:445/storage'`),
already usable today. The FUSE port is worth it for: +13% reads, +35% writes,
controlled read-ahead for streaming (mpv), and knob parity with Windows.

## FUSE backend choice

**FUSE-T (recommended first)** — kextless (translates FUSE to a localhost NFSv4
server), no Recovery-mode security downgrade needed on Apple Silicon. brew
formula exists (v1.2.7). Ships libfuse-2-ABI-compatible `libfuse-t.dylib`;
fusepy binds to it via `FUSE_LIBRARY_PATH`.

**macFUSE (fallback)** — kernel extension; on Apple Silicon requires enabling
"Reduced Security" in Recovery. Only if FUSE-T shows a perf/compat problem.

Python binding: **fusepy** (ctypes, libfuse2 API, multithreaded callbacks) —
same callback-object model as winfspy, minimal impedance.

## Refactor: extract the shared engine (no behavior change on Windows)

```
smb_client.py     unchanged — already 100% portable (all pipelining lives here)
fs_core.py        NEW: platform-agnostic engine extracted from fuse_fs.py
fuse_fs.py        becomes a thin winfspy adapter over fs_core
macos_fs.py       NEW: thin fusepy adapter over fs_core
nas_mount.py      platform dispatch (sys.platform) + config additions
```

### What moves into fs_core.py (the perf-critical 60%)

- `FileHandle` (was SmbFileContext): io_lock, read-ahead windows + futures,
  write coalescer + PipelinedWriter hookup, drain/discard logic
- Read path: `_read_from_windows`, `_promote_window`, `_ensure_prefetch`,
  `_drop_readahead`, shared ThreadPoolExecutor
- Write path: coalescing + backpressure + consistency rules
  (read-drains-writes, overwrite/truncate/rename drain)
- DirCache (TTL dict + invalidation), path mapping (subpath handling)
- Metadata normalization: keep timestamps as **epoch floats + raw SMB attrs**
  in core; adapters convert (Windows→FILETIME via existing helpers,
  macOS→st_mtime passthrough)
- Error taxonomy: core raises `FsError(code)` with a small enum
  (NOT_FOUND, ACCESS_DENIED, EXISTS, SHARING_VIOLATION, DIR_NOT_EMPTY,
  IS_DIRECTORY, IO_ERROR). Win adapter → NTStatus*; mac adapter → errno
  (ENOENT, EACCES, EEXIST, EBUSY, ENOTEMPTY, EISDIR, EIO).

### winfspy adapter keeps (Windows-only 20%)

Security descriptors, FILETIME conversion, cleanup/can_delete/delete-on-close
dance, create_options/granted_access bit decoding, dot/dotdot entries, marker
bisect in read_directory.

### fusepy adapter provides (macOS-only 20%)

- `getattr/readdir/open/create/read/write/release/truncate/unlink/mkdir/rmdir/
  rename/statfs/flush/fsync` mapped onto fs_core
- Handle table: fusepy passes integer `fh` — dict int→FileHandle
- POSIX semantics: unlink is direct (no delete-on-close), rename overwrites
  (`replace_if_exists=True`), fake modes 0755/0644, uid/gid = mount user
- xattr calls return ENOTSUP immediately (never hit the wire)
- statfs: same fake 1 TB volume

## macOS-specific performance traps (mitigations planned)

1. **AppleDouble noise**: mount with `-o noappledouble` (kills `._*` file
   traffic). `.DS_Store` writes still happen — small, dir cache absorbs lookups.
2. **Callback granularity**: FUSE-T/NFS caps per-call read/write ~128-512 KB.
   Irrelevant to throughput — the engine's windows/coalescer already convert
   small callbacks into 4 MB pipelined SMB ops (Windows behaves the same at 1 MB).
   Python callback overhead at 500 calls/s is trivial (measured 8-11% CPU at
   57 MB/s).
3. **getattr storms**: Finder stats every entry after readdir → served from
   DirCache, zero round trips (same pattern as Explorer today).
4. **Daemon timeouts**: WAN ops can exceed default FUSE timeouts → set
   `daemon_timeout` generously so a slow reconnect doesn't force-eject the volume.
5. **FUSE-T rwsize**: tune its NFS window (`-o rwsize`) upward if defaults
   throttle; A/B against macFUSE only if numbers disappoint.

## Config additions (backward compatible)

```toml
[mounts]            # Windows drive letters (unchanged)
M = "storage/media"

[macos]
mount_root = "~/nas"     # M -> ~/nas/media (dir basename), created on demand
# optional explicit overrides:
# [macos.mounts]
# M = "/Volumes/nas-media"
```

`nas_mount.py` dispatches on sys.platform: darwin → macos_fs (fusepy),
win32 → fuse_fs (winfspy). `--test`/`--bench`/`--bench-write` already
platform-neutral.

## Execution order (Windows stays green throughout)

1. **Extract fs_core.py** — pure refactor. Verify: `--bench`/`--bench-write`
   from the Mac + User's re-tests the Windows mount before proceeding.
2. **macos_fs.py + dispatch** — fusepy adapter, brew install fuse-t, mount on
   this Mac.
3. **Test matrix on this Mac (real WAN)**: dd sequential read (target ≥12 MB/s),
   dd write (target ≥55 MB/s), mpv stream + seeks, Finder browse/copy/rename/
   delete, ls -la storms, reconnect survival (bounce smb-relay mid-stream).
4. **Tune**: noappledouble, rwsize/iosize, xattr suppression, daemon_timeout.
5. **Docs**: README (macOS install/usage), CLAUDE.md (fuse-t gotchas),
   ARCHITECTURE.md (three-layer diagram).

## Risks / open questions

- fusepy + FUSE-T dylib discovery (`FUSE_LIBRARY_PATH=/usr/local/lib/libfuse-t.dylib`)
  — verify first thing in step 2; macFUSE is the fallback.
- FUSE-T NFS translation semantics (locking, mmap) — media/copy workloads
  don't exercise these hard.
- Case sensitivity: SMB share is case-insensitive; FUSE-T NFS layer defaults
  need checking so Finder doesn't get confused.
- Sleep/wake: WAN TCP dies on lid close → single-flight reconnect already
  handles it; verify the volume survives without force-eject.
