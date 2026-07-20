"""Platform-agnostic filesystem engine.

Everything performance-critical lives here, shared by the Windows (winfspy)
and macOS (fusepy) adapters: async read-ahead windows, write coalescing into
a pipelined sliding window with backpressure, the directory cache, path
mapping, and SMB error translation.

Conventions:
- Paths are backslash-separated ("\\folder\\file.txt"), matching SMB and
  WinFsp. The macOS adapter converts from POSIX slashes at its boundary.
- Timestamps are Windows FILETIME integers (100ns ticks since 1601), SMB's
  native representation. The macOS adapter converts to epoch floats.
- File attributes are Windows FILE_ATTRIBUTE bits (0x10 directory, ...).
- Errors surface as FsError with a small code enum; adapters map them to
  NTSTATUS or errno.
"""

import time
import bisect
import logging
import threading
from enum import Enum, auto
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

from smbprotocol.exceptions import (
    SMBResponseException,
    SMBConnectionClosed,
    ObjectNameNotFound,
    ObjectPathNotFound,
)

log = logging.getLogger(__name__)

EPOCH_AS_FILETIME = 116444736000000000  # 1601-01-01 in 100ns ticks

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_NORMAL = 0x80

STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA


def filetime_now():
    return EPOCH_AS_FILETIME + int(time.time() * 10_000_000)


def filetime_to_epoch(ft):
    if not ft:
        return 0.0
    return (ft - EPOCH_AS_FILETIME) / 10_000_000


def smb_dt_to_filetime(dt):
    if dt is None:
        return 0
    try:
        return EPOCH_AS_FILETIME + int(dt.timestamp() * 10_000_000)
    except Exception:
        return 0


def normalize_attrs(smb_attrs):
    if smb_attrs & FILE_ATTRIBUTE_DIRECTORY:
        return smb_attrs
    # Samba maps Unix dotfiles to HIDDEN; strip it so WinFsp allows
    # FILE_OVERWRITE_IF without the caller specifying HIDDEN.
    smb_attrs &= ~FILE_ATTRIBUTE_HIDDEN
    if smb_attrs == 0:
        return FILE_ATTRIBUTE_NORMAL
    return smb_attrs


class ErrorCode(Enum):
    NOT_FOUND = auto()
    ACCESS_DENIED = auto()
    EXISTS = auto()
    SHARING_VIOLATION = auto()
    DIR_NOT_EMPTY = auto()
    IS_DIRECTORY = auto()
    END_OF_FILE = auto()
    INVALID_HANDLE = auto()
    IO_ERROR = auto()
    UNMAPPED = auto()  # carries the raw NTSTATUS in FsError.ntstatus


class FsError(Exception):
    def __init__(self, code, message="", ntstatus=None):
        super().__init__(message or code.name)
        self.code = code
        self.ntstatus = ntstatus


_SMB_STATUS_MAP = {
    0xC0000034: ErrorCode.NOT_FOUND,       # ObjectNameNotFound
    0xC000003A: ErrorCode.NOT_FOUND,       # ObjectPathNotFound
    0xC0000103: ErrorCode.NOT_FOUND,       # NotADirectory (Explorer probing zips)
    0xC0000022: ErrorCode.ACCESS_DENIED,
    0xC0000035: ErrorCode.EXISTS,          # NameCollision
    0xC0000043: ErrorCode.SHARING_VIOLATION,
    0xC0000101: ErrorCode.DIR_NOT_EMPTY,
    0xC00000BA: ErrorCode.IS_DIRECTORY,
    0xC0000011: ErrorCode.END_OF_FILE,
}


def map_smb_error(exc):
    """Translate an smbprotocol exception into FsError (always raises)."""
    if isinstance(exc, FsError):
        raise exc
    if isinstance(exc, SMBResponseException):
        status = exc.status
        code = _SMB_STATUS_MAP.get(status)
        if code is not None:
            raise FsError(code, exc.message, ntstatus=status)
        log.error("Unmapped SMB error: %s (0x%08x)", exc.message, status)
        raise FsError(ErrorCode.UNMAPPED, exc.message, ntstatus=status)
    if isinstance(exc, SMBConnectionClosed):
        log.error("SMB connection lost: %s", exc)
        raise FsError(ErrorCode.IO_ERROR, str(exc))
    log.error("Unexpected error: %s", exc)
    raise FsError(ErrorCode.IO_ERROR, str(exc))


class FileHandle:
    __slots__ = ("path", "smb_path", "smb_open", "is_directory",
                 "file_attributes", "file_size", "allocation_size",
                 "creation_time", "last_access_time", "last_write_time",
                 "change_time", "io_lock",
                 "ra_windows", "ra_futures",
                 "writer", "wsegs", "delete_pending", "dirty")

    def __init__(self, path, smb_path, smb_open=None, is_directory=False,
                 file_attributes=0, file_size=0, allocation_size=0,
                 creation_time=0, last_access_time=0, last_write_time=0,
                 change_time=0):
        self.path = path
        self.smb_path = smb_path
        self.smb_open = smb_open
        self.is_directory = is_directory
        self.file_attributes = file_attributes
        self.file_size = file_size
        self.allocation_size = allocation_size
        self.creation_time = creation_time
        self.last_access_time = last_access_time
        self.last_write_time = last_write_time
        self.change_time = change_time
        # Serializes read/write state per handle. Held across network waits;
        # concurrency across *different* files is what matters for throughput.
        self.io_lock = threading.Lock()
        # Read-ahead state: LRU of completed windows + in-flight futures.
        # Kernel clients (macOS NFS especially) interleave their own
        # readahead with stream reads, so nearby reads arrive out of order;
        # keeping several completed windows makes that pattern all-hits.
        self.ra_windows = OrderedDict()  # window_start -> bytes (LRU)
        self.ra_futures = {}             # window_start -> Future(bytes)
        # Write-behind state: out-of-order-tolerant segment coalescer +
        # pipelined writer. Kernel clients (NFS writeback, overlapped I/O)
        # deliver writes out of order; segments absorb that and only full
        # write_size chunks go on the wire.
        self.writer = None
        self.wsegs = []  # sorted [offset, bytearray], non-overlapping
        self.delete_pending = False
        self.dirty = False

    def get_file_info(self):
        return {
            "file_attributes": self.file_attributes,
            "allocation_size": self.allocation_size,
            "file_size": self.file_size,
            "creation_time": self.creation_time,
            "last_access_time": self.last_access_time,
            "last_write_time": self.last_write_time,
            "change_time": self.change_time,
            "index_number": 0,
        }

    def has_pending_writes(self):
        return bool(self.wsegs) or (self.writer is not None
                                    and self.writer.in_flight > 0)


class FsCore:
    """The shared engine. Adapters call these methods and translate
    arguments/errors at their platform boundary."""

    def __init__(self, smb_client, subpath="", dir_cache_ttl=300,
                 readahead_windows=2, readahead_workers=8,
                 write_buffer_chunks=3, volume_label="NAS"):
        self._smb = smb_client
        self._subpath = subpath.replace("/", "\\")
        self._dir_cache_ttl = dir_cache_ttl
        self._dir_cache = {}
        self._cache_lock = threading.Lock()
        self._readahead_windows = readahead_windows
        self._write_buffer_chunks = write_buffer_chunks
        self.volume_label = volume_label
        self._vol_info = None
        self._vol_info_ts = 0
        self._executor = ThreadPoolExecutor(
            max_workers=readahead_workers, thread_name_prefix="readahead")

    # -- path helpers (paths are backslash-separated, "\\" is the root) --

    def to_smb_path(self, path):
        relative = path.lstrip("\\")
        if self._subpath:
            return f"{self._subpath}\\{relative}" if relative else self._subpath
        return relative

    def is_root(self, path):
        return path == "\\" or path == ""

    def parent_path(self, path):
        idx = path.rstrip("\\").rfind("\\")
        if idx <= 0:
            return "\\"
        return path[:idx]

    def file_name(self, path):
        return path.rstrip("\\").rsplit("\\", 1)[-1]

    # -- directory cache --

    def _get_cached_dir(self, smb_path):
        with self._cache_lock:
            entry = self._dir_cache.get(smb_path)
            if entry and (time.monotonic() - entry[0]) < self._dir_cache_ttl:
                return entry[1]
        return None

    def _set_cached_dir(self, smb_path, entries):
        with self._cache_lock:
            self._dir_cache[smb_path] = (time.monotonic(), entries)

    def invalidate_cache(self, smb_path):
        with self._cache_lock:
            self._dir_cache.pop(smb_path, None)

    def invalidate_parent_cache(self, path):
        self.invalidate_cache(self.to_smb_path(self.parent_path(path)))

    def list_dir(self, smb_path):
        """TTL-cached directory listing, entries in winfsp-style dicts
        (FILETIME timestamps, attribute bits), sorted case-insensitively."""
        cached = self._get_cached_dir(smb_path)
        if cached is not None:
            return cached
        raw = self._smb.list_directory(smb_path)
        entries = []
        for item in raw:
            name = item["file_name"]
            if name in (".", ".."):
                continue
            entries.append({
                "file_name": name,
                "file_attributes": normalize_attrs(item["file_attributes"]),
                "file_size": item["end_of_file"],
                "allocation_size": item["allocation_size"],
                "creation_time": smb_dt_to_filetime(item["creation_time"]),
                "last_access_time": smb_dt_to_filetime(item["last_access_time"]),
                "last_write_time": smb_dt_to_filetime(item["last_write_time"]),
                "change_time": smb_dt_to_filetime(item["change_time"]),
            })
        entries.sort(key=lambda e: e["file_name"].lower())
        self._set_cached_dir(smb_path, entries)
        return entries

    def lookup_cached(self, path):
        """Lookup via the parent dir cache only - no SMB round trips."""
        parent_smb = self.to_smb_path(self.parent_path(path))
        cached = self._get_cached_dir(parent_smb)
        if cached is None:
            return None
        name_lower = self.file_name(path).lower()
        for entry in cached:
            if entry["file_name"].lower() == name_lower:
                return entry
        return None

    def lookup(self, path):
        """Lookup via parent listing (fills the cache); None if missing."""
        parent_smb = self.to_smb_path(self.parent_path(path))
        entries = self.list_dir(parent_smb)
        name_lower = self.file_name(path).lower()
        for entry in entries:
            if entry["file_name"].lower() == name_lower:
                return entry
        return None

    def stat(self, path):
        """Direct SMB stat; None if the path does not exist."""
        smb_path = self.to_smb_path(path)
        try:
            st = self._smb.stat_path(smb_path)
            return {
                "file_attributes": normalize_attrs(st["file_attributes"]),
                "file_size": st["end_of_file"],
                "allocation_size": st["allocation_size"],
                "creation_time": smb_dt_to_filetime(st["creation_time"]),
                "last_access_time": smb_dt_to_filetime(st["last_access_time"]),
                "last_write_time": smb_dt_to_filetime(st["last_write_time"]),
                "change_time": smb_dt_to_filetime(st["change_time"]),
            }
        except (ObjectNameNotFound, ObjectPathNotFound):
            return None

    def lookup_or_stat(self, path):
        """Best metadata available without opening: dir cache/parent
        listing first, direct stat as fallback. None if missing."""
        info = self.lookup(path)
        if info is None:
            info = self.stat(path)
        return info

    # -- volume info --

    def volume_info(self):
        now = time.monotonic()
        if self._vol_info is None or (now - self._vol_info_ts) > 60:
            try:
                self._vol_info = self._smb.query_volume_info()
                self._vol_info_ts = now
            except Exception as e:
                log.debug("query_volume_info failed: %s", e)
                if self._vol_info is None:
                    self._vol_info = {
                        "total_size": 1 * 1024 * 1024 * 1024 * 1024,
                        "free_size": 500 * 1024 * 1024 * 1024,
                    }
        return {
            "total_size": self._vol_info["total_size"],
            "free_size": self._vol_info["free_size"],
            "volume_label": self.volume_label,
        }

    # -- open/create/close --

    def open_handle(self, path, want_write, dir_hint=False):
        """Open a handle. Cache-only lookup first; on a miss, open the SMB
        file directly (the create response carries all metadata) and fall
        back to directory semantics on STATUS_FILE_IS_A_DIRECTORY.
        dir_hint: caller believes this is a directory (cache-miss only)."""
        smb_path = self.to_smb_path(path)

        if self.is_root(path):
            return FileHandle(
                path=path, smb_path=smb_path, is_directory=True,
                file_attributes=FILE_ATTRIBUTE_DIRECTORY,
                creation_time=filetime_now(),
                last_access_time=filetime_now(),
                last_write_time=filetime_now(),
                change_time=filetime_now(),
            )

        info = self.lookup_cached(path)
        if info:
            is_dir = bool(info["file_attributes"] & FILE_ATTRIBUTE_DIRECTORY)
        else:
            is_dir = dir_hint

        smb_open = None
        if not is_dir:
            try:
                smb_open = self._smb.open_file(smb_path, read=True,
                                               write=want_write)
            except SMBResponseException as e:
                if e.status == STATUS_FILE_IS_A_DIRECTORY:
                    is_dir = True
                else:
                    log.error("open(%s) SMB open failed: %s", path, e)
                    map_smb_error(e)
            except Exception as e:
                log.error("open(%s) SMB open failed: %s", path, e)
                map_smb_error(e)

        if smb_open:
            return FileHandle(
                path=path, smb_path=smb_path, smb_open=smb_open,
                is_directory=False,
                file_attributes=normalize_attrs(smb_open.file_attributes),
                file_size=smb_open.end_of_file,
                allocation_size=smb_open.allocation_size,
                creation_time=smb_dt_to_filetime(smb_open.creation_time),
                last_access_time=smb_dt_to_filetime(smb_open.last_access_time),
                last_write_time=smb_dt_to_filetime(smb_open.last_write_time),
                change_time=smb_dt_to_filetime(smb_open.change_time),
            )
        if info:
            return FileHandle(
                path=path, smb_path=smb_path, smb_open=None,
                is_directory=is_dir,
                file_attributes=info["file_attributes"],
                file_size=info["file_size"],
                allocation_size=info["allocation_size"],
                creation_time=info["creation_time"],
                last_access_time=info["last_access_time"],
                last_write_time=info["last_write_time"],
                change_time=info["change_time"],
            )
        # Directory (or file we could not open as file): stat for real
        # metadata.
        st = self.stat(path)
        if st is None:
            raise FsError(ErrorCode.NOT_FOUND, path)
        return FileHandle(
            path=path, smb_path=smb_path,
            is_directory=bool(st["file_attributes"] & FILE_ATTRIBUTE_DIRECTORY),
            file_attributes=st["file_attributes"],
            file_size=st["file_size"],
            allocation_size=st["allocation_size"],
            creation_time=st["creation_time"],
            last_access_time=st["last_access_time"],
            last_write_time=st["last_write_time"],
            change_time=st["change_time"],
        )

    def create_handle(self, path, is_dir, file_attributes=0):
        smb_path = self.to_smb_path(path)
        try:
            smb_open = self._smb.create_file(smb_path, is_directory=is_dir)
        except Exception as e:
            log.error("create(%s) failed: %s", path, e)
            map_smb_error(e)

        now = filetime_now()
        if is_dir:
            self._smb.close_file(smb_open)
            handle = FileHandle(
                path=path, smb_path=smb_path, smb_open=None,
                is_directory=True,
                file_attributes=FILE_ATTRIBUTE_DIRECTORY,
                creation_time=now, last_access_time=now,
                last_write_time=now, change_time=now,
            )
        else:
            handle = FileHandle(
                path=path, smb_path=smb_path, smb_open=smb_open,
                is_directory=False,
                file_attributes=file_attributes or FILE_ATTRIBUTE_NORMAL,
                creation_time=now, last_access_time=now,
                last_write_time=now, change_time=now,
            )
        self.invalidate_parent_cache(path)
        return handle

    def close_handle(self, handle):
        with handle.io_lock:
            self._drop_readahead(handle, wait=True)
            if handle.smb_open is not None:
                if handle.delete_pending:
                    self._discard_writes(handle)
                else:
                    try:
                        self._drain_writes(handle)
                    except Exception as e:
                        log.error("flush on close(%s) failed: %s",
                                  handle.path, e)
                self._smb.close_file(handle.smb_open)
                handle.smb_open = None
                handle.writer = None
        if handle.delete_pending or handle.dirty:
            # A deleted or modified file makes the parent's cached listing
            # (names/sizes) stale.
            smb_path = handle.smb_path
            if handle.is_directory:
                self.invalidate_cache(smb_path)
            parent = smb_path.rsplit("\\", 1)[0] if "\\" in smb_path else ""
            self.invalidate_cache(parent)

    # -- write-behind plumbing (call with handle.io_lock held) --

    def _coalesce_insert(self, handle, offset, data):
        """Insert a write into the sorted segment list, merging any
        overlapping or adjacent segments (new data wins on overlap)."""
        segs = handle.wsegs
        # Fast path for sequential streams (the overwhelmingly common
        # case): append in place to the tail segment - O(1) amortized, no
        # realloc/copy of everything accumulated so far.
        if not segs:
            segs.append([offset, bytearray(data)])
            return
        last = segs[-1]
        last_end = last[0] + len(last[1])
        if offset == last_end:
            last[1].extend(data)
            return
        if offset > last_end:
            segs.append([offset, bytearray(data)])
            return
        new_start = offset
        new_end = offset + len(data)
        lo = bisect.bisect_left(segs, new_start, key=lambda s: s[0])
        # A predecessor can touch/overlap us.
        if lo > 0 and segs[lo - 1][0] + len(segs[lo - 1][1]) >= new_start:
            lo -= 1
        hi = lo
        while hi < len(segs) and segs[hi][0] <= new_end:
            hi += 1
        if lo == hi:
            segs.insert(lo, [offset, bytearray(data)])
            return
        span_start = min(new_start, segs[lo][0])
        span_end = max(new_end, max(s[0] + len(s[1]) for s in segs[lo:hi]))
        merged = bytearray(span_end - span_start)
        for s_off, s_data in segs[lo:hi]:
            merged[s_off - span_start:s_off - span_start + len(s_data)] = s_data
        merged[new_start - span_start:new_start - span_start + len(data)] = data
        segs[lo:hi] = [[span_start, merged]]

    def _submit_full_chunks(self, handle):
        """Send every full write_size multiple sitting in the segments;
        keep the remainders coalescing."""
        write_size = self._smb.write_size
        if handle.writer is None:
            handle.writer = self._smb.make_writer(handle.smb_open)
        segs = handle.wsegs
        i = 0
        while i < len(segs):
            s_off, s_data = segs[i]
            if len(s_data) >= write_size:
                n_full = (len(s_data) // write_size) * write_size
                handle.writer.submit(bytes(s_data[:n_full]), s_off)
                rest = s_data[n_full:]
                if rest:
                    segs[i] = [s_off + n_full, rest]
                    i += 1
                else:
                    segs.pop(i)
            else:
                i += 1

    def _buffered_bytes(self, handle):
        return sum(len(s[1]) for s in handle.wsegs)

    def _drain_writes(self, handle):
        """Push out all buffered segments and wait for all in-flight
        writes. Raises on write failure so callers can surface it."""
        if handle.smb_open is None:
            return
        if handle.wsegs:
            if handle.writer is None:
                handle.writer = self._smb.make_writer(handle.smb_open)
            segs = handle.wsegs
            handle.wsegs = []
            for s_off, s_data in segs:
                handle.writer.submit(bytes(s_data), s_off)
        if handle.writer is not None:
            handle.writer.drain()

    def _discard_writes(self, handle):
        """Drop buffered segments; still waits out in-flight requests
        (protocol responses must be collected) but ignores errors."""
        handle.wsegs = []
        if handle.writer is not None:
            try:
                handle.writer.drain()
            except Exception as e:
                log.debug("discard_writes(%s): %s", handle.path, e)

    # -- read-ahead plumbing (call with handle.io_lock held) --

    def _window_size(self):
        return self._smb.read_size

    def _fetch_window(self, handle, wstart):
        wsize = self._window_size()
        wlen = min(wsize, handle.file_size - wstart)
        if wlen <= 0:
            return b""
        return self._smb.read_file_pipelined(handle.smb_open, wstart, wlen)

    def _window_cache_cap(self):
        # Enough completed windows that a kernel client interleaving its
        # own readahead with stream reads never bounces a window out while
        # it is still being consumed.
        return self._readahead_windows + 2

    def _ensure_prefetch(self, handle, wstart):
        """Schedule a background fetch of the window at wstart if not
        already cached, in flight, or past EOF."""
        if wstart >= handle.file_size:
            return
        if wstart in handle.ra_windows:
            return
        if wstart in handle.ra_futures:
            return
        handle.ra_futures[wstart] = self._executor.submit(
            self._fetch_window, handle, wstart)

    def _get_window(self, handle, wstart):
        """Return the window's bytes: LRU cache hit, in-flight future, or
        synchronous fetch. Completed windows enter the LRU (old ones age
        out - no purging, so out-of-order nearby reads always hit)."""
        cached = handle.ra_windows.get(wstart)
        if cached is not None:
            handle.ra_windows.move_to_end(wstart)
            return cached
        fut = handle.ra_futures.pop(wstart, None)
        if fut is not None:
            data = fut.result()
        else:
            data = self._fetch_window(handle, wstart)
        handle.ra_windows[wstart] = data
        while len(handle.ra_windows) > self._window_cache_cap():
            handle.ra_windows.popitem(last=False)
        return data

    def _drop_readahead(self, handle, wait=False):
        handle.ra_windows = OrderedDict()
        futures = handle.ra_futures
        handle.ra_futures = {}
        for fut in futures.values():
            fut.cancel()
        if wait:
            # In-flight fetches reference the SMB handle; let them finish
            # before the caller closes it.
            for fut in futures.values():
                if not fut.cancelled():
                    try:
                        fut.result(timeout=60)
                    except Exception:
                        pass

    def _read_from_windows(self, handle, offset, length):
        """Assemble `length` bytes starting at offset from cached/fetched
        windows, keeping the prefetch pipeline primed."""
        wsize = self._window_size()
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            wstart = (pos // wsize) * wsize
            buf = self._get_window(handle, wstart)
            rel = pos - wstart
            if rel >= len(buf):
                break  # EOF or short read from server
            take = buf[rel:min(rel + (end - pos), len(buf))]
            out.extend(take)
            pos += len(take)
            # Keep the pipeline primed while we're consuming this window.
            if pos >= wstart + (wsize // 2):
                for i in range(1, self._readahead_windows + 1):
                    self._ensure_prefetch(handle, wstart + i * wsize)
        return bytes(out)

    # -- data plane --

    def read(self, handle, offset, length):
        """Read with async read-ahead. Raises FsError(END_OF_FILE) when
        offset is at/past EOF (adapters decide their platform semantics)."""
        if handle.smb_open is None:
            raise FsError(ErrorCode.END_OF_FILE)
        try:
            with handle.io_lock:
                if offset >= handle.file_size:
                    raise FsError(ErrorCode.END_OF_FILE)
                length = min(length, handle.file_size - offset)
                # Write-then-read consistency: anything buffered must hit
                # the server before we read.
                if handle.has_pending_writes():
                    self._drain_writes(handle)

                data = self._read_from_windows(handle, offset, length)
                if not data:
                    raise FsError(ErrorCode.END_OF_FILE)
                return data
        except FsError:
            raise
        except Exception as e:
            log.error("read(%s, offset=%d, len=%d) failed: %s",
                      handle.path, offset, length, e)
            map_smb_error(e)

    def write(self, handle, buffer, offset, write_to_end=False,
              constrained=False):
        """Buffered write feeding the pipelined writer with backpressure.
        Returns bytes accepted."""
        if handle.smb_open is None:
            raise FsError(ErrorCode.INVALID_HANDLE)
        try:
            with handle.io_lock:
                data = bytes(buffer)
                if write_to_end:
                    offset = handle.file_size
                if constrained:
                    # Constrained writes must not extend the file.
                    if offset >= handle.file_size:
                        return 0
                    if offset + len(data) > handle.file_size:
                        data = data[:handle.file_size - offset]
                length = len(data)
                if length == 0:
                    return 0

                self._coalesce_insert(handle, offset, data)
                # Feed full chunks into the pipeline, keep remainders
                # coalescing. submit() applies backpressure when the
                # window is full, pacing us at network speed.
                self._submit_full_chunks(handle)
                # Progress/memory guarantee: if reordering leaves lots of
                # partial segments behind, push the oldest ones out even
                # though they're not full chunks.
                write_size = self._smb.write_size
                max_buffered = write_size * self._write_buffer_chunks
                while (self._buffered_bytes(handle) > max_buffered
                       and handle.wsegs):
                    s_off, s_data = handle.wsegs.pop(0)
                    handle.writer.submit(bytes(s_data), s_off)

                new_end = offset + length
                if new_end > handle.file_size:
                    handle.file_size = new_end
                    handle.allocation_size = new_end
                handle.last_write_time = filetime_now()
                handle.change_time = handle.last_write_time
                handle.dirty = True
                # Any cached read data overlapping the write is stale.
                self._drop_readahead(handle)
                return length
        except FsError:
            raise
        except Exception as e:
            log.error("write(%s, offset=%d, len=%d) failed: %s",
                      handle.path, offset, len(buffer), e)
            map_smb_error(e)

    def flush(self, handle, sync_disk=True):
        """Drain buffered writes to the server. sync_disk additionally
        issues SMB FLUSH (sync to stable storage) - wanted for explicit
        Windows FlushFileBuffers, skipped for NFS COMMIT semantics where
        data-at-the-server suffices and per-commit disk syncs would stall
        the pipeline."""
        if handle.smb_open is not None:
            try:
                with handle.io_lock:
                    self._drain_writes(handle)
                # SMB FLUSH needs write access; skip it on read-only
                # handles (nothing to flush anyway).
                if sync_disk and handle.dirty:
                    self._smb.flush_file(handle.smb_open)
            except FsError:
                raise
            except Exception as e:
                log.error("flush(%s) failed: %s", handle.path, e)
                map_smb_error(e)

    def overwrite(self, handle, file_attributes=0, replace_attributes=False):
        """Truncate to zero on open-for-overwrite (Windows semantics)."""
        try:
            with handle.io_lock:
                self._discard_writes(handle)
                self._drop_readahead(handle)
                self._smb.set_end_of_file(handle.smb_open, 0)
                handle.file_size = 0
                handle.allocation_size = 0
                if replace_attributes:
                    handle.file_attributes = (
                        file_attributes or FILE_ATTRIBUTE_NORMAL)
                handle.last_write_time = filetime_now()
                handle.change_time = handle.last_write_time
                handle.dirty = True
            self.invalidate_parent_cache(handle.path)
        except FsError:
            raise
        except Exception as e:
            log.error("overwrite(%s) failed: %s", handle.path, e)
            map_smb_error(e)

    def truncate(self, handle, new_size, allocation_only=False):
        try:
            with handle.io_lock:
                # Buffered writes must land before we move EOF, otherwise a
                # later flush would re-extend the file.
                self._drain_writes(handle)
                self._drop_readahead(handle)
                if not allocation_only:
                    self._smb.set_end_of_file(handle.smb_open, new_size)
                    handle.file_size = new_size
                    handle.dirty = True
                handle.allocation_size = new_size
            if not allocation_only:
                self.invalidate_parent_cache(handle.path)
        except FsError:
            raise
        except Exception as e:
            log.error("truncate(%s, %d) failed: %s",
                      handle.path, new_size, e)
            map_smb_error(e)

    # -- namespace operations --

    def mark_delete(self, handle, path):
        """Delete-on-close (Windows cleanup semantics)."""
        handle.delete_pending = True
        try:
            if handle.smb_open is not None:
                self._smb.set_delete_on_close(handle.smb_open)
            else:
                smb_path = self.to_smb_path(path)
                if handle.is_directory:
                    self._smb.delete_directory(smb_path)
                else:
                    self._smb.delete_file(smb_path)
        except Exception as e:
            log.error("cleanup delete(%s) failed: %s", path, e)

    def delete_path(self, path, is_dir):
        """Direct delete (POSIX unlink/rmdir semantics)."""
        smb_path = self.to_smb_path(path)
        try:
            if is_dir:
                self._smb.delete_directory(smb_path)
            else:
                self._smb.delete_file(smb_path)
        except Exception as e:
            map_smb_error(e)
        self.invalidate_cache(smb_path)
        self.invalidate_parent_cache(path)

    def check_dir_empty(self, path):
        smb_path = self.to_smb_path(path)
        try:
            entries = self._smb.list_directory(smb_path)
            real = [e for e in entries if e["file_name"] not in (".", "..")]
            if real:
                raise FsError(ErrorCode.DIR_NOT_EMPTY, path)
        except FsError:
            raise
        except Exception as e:
            map_smb_error(e)

    def rename(self, handle, old_path, new_path, replace_if_exists):
        old_smb = self.to_smb_path(old_path)
        new_smb = self.to_smb_path(new_path)
        try:
            if handle is not None:
                with handle.io_lock:
                    self._drain_writes(handle)
            self._smb.rename(old_smb, new_smb,
                             replace_if_exists=replace_if_exists)
            if handle is not None:
                handle.path = new_path
                handle.smb_path = new_smb
            self.invalidate_cache(old_smb)
            self.invalidate_cache(new_smb)
            old_parent = self.to_smb_path(self.parent_path(old_path))
            new_parent = self.to_smb_path(self.parent_path(new_path))
            self.invalidate_cache(old_parent)
            if new_parent != old_parent:
                self.invalidate_cache(new_parent)
        except FsError:
            raise
        except Exception as e:
            log.error("rename(%s -> %s) failed: %s", old_path, new_path, e)
            map_smb_error(e)
