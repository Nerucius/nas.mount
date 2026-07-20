import time
import bisect
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from winfspy import (
    BaseFileSystemOperations,
    FILE_ATTRIBUTE,
    NTStatusObjectNameNotFound,
    NTStatusEndOfFile,
    NTStatusDirectoryNotEmpty,
    NTStatusError,
)
from winfspy.plumbing.security_descriptor import SecurityDescriptor
from winfspy.plumbing.win32_filetime import filetime_now, dt_to_filetime
from winfspy.plumbing import NTSTATUS

from smbprotocol.exceptions import (
    SMBResponseException,
    SMBConnectionClosed,
    ObjectNameNotFound,
    ObjectPathNotFound,
    NoMoreFiles,
)

log = logging.getLogger(__name__)

SECURITY_DESCRIPTOR = SecurityDescriptor.from_string(
    "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"
)

STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA


def _smb_dt_to_filetime(dt):
    if dt is None:
        return 0
    try:
        return dt_to_filetime(dt)
    except Exception:
        return 0


def _smb_to_winfsp_attrs(smb_attrs):
    if smb_attrs & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY:
        return smb_attrs
    if smb_attrs == 0:
        return FILE_ATTRIBUTE.FILE_ATTRIBUTE_NORMAL
    return smb_attrs


class SmbFileContext:
    __slots__ = ("path", "smb_path", "smb_open", "is_directory",
                 "file_attributes", "file_size", "allocation_size",
                 "creation_time", "last_access_time", "last_write_time",
                 "change_time", "io_lock",
                 "ra_buf", "ra_start", "ra_futures", "seq_end",
                 "writer", "co_buf", "co_off", "_delete_pending")

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
        # Read-ahead state: current window + in-flight window futures.
        self.ra_buf = None
        self.ra_start = 0
        self.ra_futures = {}  # window_start -> Future(bytes)
        self.seq_end = -1     # end offset of last read (sequential detection)
        # Write-behind state: coalescing buffer + pipelined writer.
        self.writer = None
        self.co_buf = bytearray()
        self.co_off = 0
        self._delete_pending = False

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
        return bool(self.co_buf) or (self.writer is not None
                                     and self.writer.in_flight > 0)


class SmbFileSystemOperations(BaseFileSystemOperations):

    def __init__(self, smb_client, subpath="", dir_cache_ttl=300,
                 readahead_windows=2, readahead_workers=8):
        super().__init__()
        self._smb = smb_client
        self._subpath = subpath.replace("/", "\\")
        self._dir_cache_ttl = dir_cache_ttl
        self._dir_cache = {}
        self._cache_lock = threading.Lock()
        self._readahead_windows = readahead_windows
        self._executor = ThreadPoolExecutor(
            max_workers=readahead_workers, thread_name_prefix="readahead")

    # -- path helpers --

    def _to_smb_path(self, winfsp_path):
        relative = winfsp_path.lstrip("\\")
        if self._subpath:
            return f"{self._subpath}\\{relative}" if relative else self._subpath
        return relative

    def _is_root(self, winfsp_path):
        return winfsp_path == "\\" or winfsp_path == ""

    def _parent_path(self, winfsp_path):
        idx = winfsp_path.rstrip("\\").rfind("\\")
        if idx <= 0:
            return "\\"
        return winfsp_path[:idx]

    def _file_name(self, winfsp_path):
        return winfsp_path.rstrip("\\").rsplit("\\", 1)[-1]

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

    def _invalidate_cache(self, smb_path):
        with self._cache_lock:
            self._dir_cache.pop(smb_path, None)

    def _list_dir_cached(self, smb_path):
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
                "file_attributes": _smb_to_winfsp_attrs(item["file_attributes"]),
                "file_size": item["end_of_file"],
                "allocation_size": item["allocation_size"],
                "creation_time": _smb_dt_to_filetime(item["creation_time"]),
                "last_access_time": _smb_dt_to_filetime(item["last_access_time"]),
                "last_write_time": _smb_dt_to_filetime(item["last_write_time"]),
                "change_time": _smb_dt_to_filetime(item["change_time"]),
            })
        entries.sort(key=lambda e: e["file_name"].lower())
        self._set_cached_dir(smb_path, entries)
        return entries

    def _lookup_in_parent_cache(self, winfsp_path):
        """Lookup via the parent dir cache only - no SMB round trips."""
        parent_smb = self._to_smb_path(self._parent_path(winfsp_path))
        cached = self._get_cached_dir(parent_smb)
        if cached is None:
            return None
        name_lower = self._file_name(winfsp_path).lower()
        for entry in cached:
            if entry["file_name"].lower() == name_lower:
                return entry
        return None

    def _lookup_in_parent(self, winfsp_path):
        parent = self._parent_path(winfsp_path)
        parent_smb = self._to_smb_path(parent)
        name = self._file_name(winfsp_path)
        entries = self._list_dir_cached(parent_smb)
        name_lower = name.lower()
        for entry in entries:
            if entry["file_name"].lower() == name_lower:
                return entry
        return None

    def _stat_via_smb(self, winfsp_path):
        smb_path = self._to_smb_path(winfsp_path)
        try:
            stat = self._smb.stat_path(smb_path)
            return {
                "file_attributes": _smb_to_winfsp_attrs(stat["file_attributes"]),
                "file_size": stat["end_of_file"],
                "allocation_size": stat["allocation_size"],
                "creation_time": _smb_dt_to_filetime(stat["creation_time"]),
                "last_access_time": _smb_dt_to_filetime(stat["last_access_time"]),
                "last_write_time": _smb_dt_to_filetime(stat["last_write_time"]),
                "change_time": _smb_dt_to_filetime(stat["change_time"]),
            }
        except (ObjectNameNotFound, ObjectPathNotFound):
            return None

    def _handle_smb_error(self, exc):
        if isinstance(exc, SMBResponseException):
            status = exc.status
            if status == 0xC0000034 or status == 0xC000003A:
                raise NTStatusObjectNameNotFound()
            if status == 0xC0000103:
                raise NTStatusObjectNameNotFound()
            if status == 0xC0000022:
                raise NTStatusError(NTSTATUS.STATUS_ACCESS_DENIED)
            if status == 0xC0000035:
                raise NTStatusError(NTSTATUS.STATUS_OBJECT_NAME_COLLISION)
            if status == 0xC0000043:
                raise NTStatusError(NTSTATUS.STATUS_SHARING_VIOLATION)
            if status == 0xC0000101:
                raise NTStatusDirectoryNotEmpty()
            log.error("Unmapped SMB error: %s (0x%08x)", exc.message, status)
            try:
                raise NTStatusError(NTSTATUS(status))
            except ValueError:
                raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)
        if isinstance(exc, SMBConnectionClosed):
            log.error("SMB connection lost: %s", exc)
            raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)
        log.error("Unexpected error: %s", exc)
        raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)

    # -- write-behind plumbing (call with ctx.io_lock held) --

    def _drain_writes(self, ctx):
        """Push out the coalescing buffer and wait for all in-flight
        writes. Raises on write failure so callers can surface it."""
        if ctx.smb_open is None:
            return
        if ctx.co_buf:
            data = bytes(ctx.co_buf)
            offset = ctx.co_off
            ctx.co_buf = bytearray()
            if ctx.writer is None:
                ctx.writer = self._smb.make_writer(ctx.smb_open)
            ctx.writer.submit(data, offset)
        if ctx.writer is not None:
            ctx.writer.drain()

    def _discard_writes(self, ctx):
        """Drop the coalescing buffer; still waits out in-flight requests
        (protocol responses must be collected) but ignores errors."""
        ctx.co_buf = bytearray()
        if ctx.writer is not None:
            try:
                ctx.writer.drain()
            except Exception as e:
                log.debug("discard_writes(%s): %s", ctx.path, e)

    # -- read-ahead plumbing (call with ctx.io_lock held) --

    def _window_size(self):
        return self._smb.read_size

    def _fetch_window(self, ctx, wstart):
        wsize = self._window_size()
        wlen = min(wsize, ctx.file_size - wstart)
        if wlen <= 0:
            return b""
        return self._smb.read_file_pipelined(ctx.smb_open, wstart, wlen)

    def _ensure_prefetch(self, ctx, wstart):
        """Schedule a background fetch of the window at wstart if not
        already current, in flight, or past EOF."""
        if wstart >= ctx.file_size:
            return
        if ctx.ra_buf is not None and wstart == ctx.ra_start:
            return
        if wstart in ctx.ra_futures:
            return
        ctx.ra_futures[wstart] = self._executor.submit(
            self._fetch_window, ctx, wstart)

    def _promote_window(self, ctx, wstart):
        """Make the window at wstart current, waiting on its future or
        fetching it synchronously."""
        fut = ctx.ra_futures.pop(wstart, None)
        if fut is not None:
            data = fut.result()
        else:
            data = self._fetch_window(ctx, wstart)
        ctx.ra_buf = data
        ctx.ra_start = wstart
        # Windows before the current one are stale.
        for k in [k for k in ctx.ra_futures if k <= wstart]:
            ctx.ra_futures.pop(k)
        return data

    def _drop_readahead(self, ctx, wait=False):
        ctx.ra_buf = None
        futures = ctx.ra_futures
        ctx.ra_futures = {}
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

    def _read_from_windows(self, ctx, offset, length):
        """Assemble `length` bytes starting at offset from the current
        window chain, promoting/prefetching as needed."""
        wsize = self._window_size()
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            wstart = (pos // wsize) * wsize
            if not (ctx.ra_buf is not None and ctx.ra_start == wstart):
                self._promote_window(ctx, wstart)
            buf = ctx.ra_buf
            rel = pos - wstart
            if rel >= len(buf):
                break  # EOF or short read from server
            take = buf[rel:min(rel + (end - pos), len(buf))]
            out.extend(take)
            pos += len(take)
            # Keep the pipeline primed while we're consuming this window.
            if pos >= wstart + (wsize // 2):
                for i in range(1, self._readahead_windows + 1):
                    self._ensure_prefetch(ctx, wstart + i * wsize)
        return bytes(out)

    # -- WinFsp callbacks --

    def get_volume_info(self):
        return {
            "total_size": 1 * 1024 * 1024 * 1024 * 1024,
            "free_size": 500 * 1024 * 1024 * 1024,
            "volume_label": "NAS",
        }

    def get_security_by_name(self, file_name):
        if self._is_root(file_name):
            return (
                FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
                SECURITY_DESCRIPTOR.handle,
                SECURITY_DESCRIPTOR.size,
            )
        try:
            info = self._lookup_in_parent(file_name)
            if info is None:
                info = self._stat_via_smb(file_name)
            if info is None:
                raise NTStatusObjectNameNotFound()
            return (
                info["file_attributes"],
                SECURITY_DESCRIPTOR.handle,
                SECURITY_DESCRIPTOR.size,
            )
        except NTStatusError:
            raise
        except Exception as e:
            log.debug("get_security_by_name(%s): %s", file_name, e)
            self._handle_smb_error(e)

    def open(self, file_name, create_options, granted_access):
        smb_path = self._to_smb_path(file_name)
        is_root = self._is_root(file_name)

        if is_root:
            return SmbFileContext(
                path=file_name, smb_path=smb_path, is_directory=True,
                file_attributes=FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
                creation_time=filetime_now(),
                last_access_time=filetime_now(),
                last_write_time=filetime_now(),
                change_time=filetime_now(),
            )

        # Cheap lookup first (cache only). On a miss, open the file handle
        # directly - the open response carries all metadata, so a cold open
        # costs one round trip instead of listing the whole parent.
        info = self._lookup_in_parent_cache(file_name)
        if info:
            is_dir = bool(info["file_attributes"]
                          & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY)
        else:
            is_dir = bool(create_options & 0x1)

        smb_open = None
        if not is_dir:
            want_write = bool(granted_access & 0x12B0116)
            try:
                smb_open = self._smb.open_file(smb_path, read=True,
                                               write=want_write)
            except SMBResponseException as e:
                if e.status == STATUS_FILE_IS_A_DIRECTORY:
                    is_dir = True
                else:
                    log.error("open(%s) SMB open failed: %s", file_name, e)
                    self._handle_smb_error(e)
            except Exception as e:
                log.error("open(%s) SMB open failed: %s", file_name, e)
                self._handle_smb_error(e)

        if smb_open:
            ctx = SmbFileContext(
                path=file_name, smb_path=smb_path, smb_open=smb_open,
                is_directory=False,
                file_attributes=_smb_to_winfsp_attrs(smb_open.file_attributes),
                file_size=smb_open.end_of_file,
                allocation_size=smb_open.allocation_size,
                creation_time=_smb_dt_to_filetime(smb_open.creation_time),
                last_access_time=_smb_dt_to_filetime(smb_open.last_access_time),
                last_write_time=_smb_dt_to_filetime(smb_open.last_write_time),
                change_time=_smb_dt_to_filetime(smb_open.change_time),
            )
        elif info:
            ctx = SmbFileContext(
                path=file_name, smb_path=smb_path, smb_open=None,
                is_directory=is_dir,
                file_attributes=info["file_attributes"],
                file_size=info["file_size"],
                allocation_size=info["allocation_size"],
                creation_time=info["creation_time"],
                last_access_time=info["last_access_time"],
                last_write_time=info["last_write_time"],
                change_time=info["change_time"],
            )
        else:
            # Directory (or file we could not open as file): stat for real
            # metadata; fall back to bare directory attrs.
            stat = self._stat_via_smb(file_name)
            if stat is None:
                raise NTStatusObjectNameNotFound()
            ctx = SmbFileContext(
                path=file_name, smb_path=smb_path,
                is_directory=bool(stat["file_attributes"]
                                  & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY),
                file_attributes=stat["file_attributes"],
                file_size=stat["file_size"],
                allocation_size=stat["allocation_size"],
                creation_time=stat["creation_time"],
                last_access_time=stat["last_access_time"],
                last_write_time=stat["last_write_time"],
                change_time=stat["change_time"],
            )
        return ctx

    def close(self, file_context):
        with file_context.io_lock:
            self._drop_readahead(file_context, wait=True)
            if file_context.smb_open is not None:
                if file_context._delete_pending:
                    self._discard_writes(file_context)
                else:
                    try:
                        self._drain_writes(file_context)
                    except Exception as e:
                        log.error("flush on close(%s) failed: %s",
                                  file_context.path, e)
                self._smb.close_file(file_context.smb_open)
                file_context.smb_open = None
                file_context.writer = None
        if file_context._delete_pending:
            smb_path = file_context.smb_path
            if file_context.is_directory:
                self._invalidate_cache(smb_path)
            parent = smb_path.rsplit("\\", 1)[0] if "\\" in smb_path else ""
            self._invalidate_cache(parent)

    def get_file_info(self, file_context):
        return file_context.get_file_info()

    def read(self, file_context, offset, length):
        ctx = file_context
        if ctx.smb_open is None:
            raise NTStatusEndOfFile()
        try:
            with ctx.io_lock:
                if offset >= ctx.file_size:
                    raise NTStatusEndOfFile()
                length = min(length, ctx.file_size - offset)
                # Write-then-read consistency: anything buffered must hit
                # the server before we read.
                if ctx.has_pending_writes():
                    self._drain_writes(ctx)

                wsize = self._window_size()
                sequential = (offset == ctx.seq_end
                              or (ctx.ra_buf is not None
                                  and ctx.ra_start <= offset < ctx.ra_start
                                  + len(ctx.ra_buf)))
                if not sequential:
                    # Random seek: throw away stale windows.
                    self._drop_readahead(ctx)
                data = self._read_from_windows(ctx, offset, length)
                ctx.seq_end = offset + len(data)
                if not data:
                    raise NTStatusEndOfFile()
                return data
        except NTStatusError:
            raise
        except Exception as e:
            log.error("read(%s, offset=%d, len=%d) failed: %s",
                      file_context.path, offset, length, e)
            self._handle_smb_error(e)

    def read_directory(self, file_context, marker):
        smb_path = file_context.smb_path
        try:
            children = self._list_dir_cached(smb_path)
        except Exception as e:
            log.error("read_directory(%s) failed: %s", file_context.path, e)
            self._handle_smb_error(e)

        entries = list(children)

        if not self._is_root(file_context.path):
            dot = {
                "file_name": ".",
                "file_attributes": file_context.file_attributes,
                "file_size": 0,
                "allocation_size": 0,
                "creation_time": file_context.creation_time,
                "last_access_time": file_context.last_access_time,
                "last_write_time": file_context.last_write_time,
                "change_time": file_context.change_time,
            }
            dotdot = dict(dot, file_name="..")
            entries = [dot, dotdot] + entries

        if marker is not None:
            marker_lower = marker.lower()
            idx = bisect.bisect_right(
                [e["file_name"].lower() for e in entries], marker_lower
            )
            entries = entries[idx:]

        return entries

    def create(self, file_name, create_options, granted_access, file_attributes,
               security_descriptor, allocation_size):
        smb_path = self._to_smb_path(file_name)
        is_dir = bool(create_options & 0x1)
        try:
            smb_open = self._smb.create_file(smb_path, is_directory=is_dir)
        except Exception as e:
            log.error("create(%s) failed: %s", file_name, e)
            self._handle_smb_error(e)

        now = filetime_now()
        if is_dir:
            self._smb.close_file(smb_open)
            ctx = SmbFileContext(
                path=file_name, smb_path=smb_path, smb_open=None,
                is_directory=True,
                file_attributes=FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
                creation_time=now, last_access_time=now,
                last_write_time=now, change_time=now,
            )
        else:
            ctx = SmbFileContext(
                path=file_name, smb_path=smb_path, smb_open=smb_open,
                is_directory=False,
                file_attributes=file_attributes or FILE_ATTRIBUTE.FILE_ATTRIBUTE_NORMAL,
                creation_time=now, last_access_time=now,
                last_write_time=now, change_time=now,
            )

        parent_smb = self._to_smb_path(self._parent_path(file_name))
        self._invalidate_cache(parent_smb)
        return ctx

    def write(self, file_context, buffer, offset, write_to_end_of_file,
              constrained_io):
        ctx = file_context
        if ctx.smb_open is None:
            raise NTStatusError(NTSTATUS.STATUS_INVALID_HANDLE)
        try:
            with ctx.io_lock:
                data = bytes(buffer)
                if write_to_end_of_file:
                    offset = ctx.file_size
                if constrained_io:
                    # Constrained writes must not extend the file.
                    if offset >= ctx.file_size:
                        return 0
                    if offset + len(data) > ctx.file_size:
                        data = data[:ctx.file_size - offset]
                length = len(data)
                if length == 0:
                    return 0

                if ctx.writer is None:
                    ctx.writer = self._smb.make_writer(ctx.smb_open)

                write_size = self._smb.write_size
                if ctx.co_buf and offset == ctx.co_off + len(ctx.co_buf):
                    ctx.co_buf.extend(data)
                else:
                    if ctx.co_buf:
                        # Non-sequential write: push out what we have.
                        pending = bytes(ctx.co_buf)
                        poff = ctx.co_off
                        ctx.co_buf = bytearray()
                        ctx.writer.submit(pending, poff)
                    ctx.co_buf = bytearray(data)
                    ctx.co_off = offset

                # Feed full chunks into the pipeline, keep the remainder
                # coalescing. submit() applies backpressure when the
                # window is full, pacing us at network speed.
                while len(ctx.co_buf) >= write_size:
                    chunk = bytes(ctx.co_buf[:write_size])
                    ctx.writer.submit(chunk, ctx.co_off)
                    ctx.co_buf = ctx.co_buf[write_size:]
                    ctx.co_off += write_size

                new_end = offset + length
                if new_end > ctx.file_size:
                    ctx.file_size = new_end
                    ctx.allocation_size = new_end
                ctx.last_write_time = filetime_now()
                ctx.change_time = ctx.last_write_time
                # Any cached read data overlapping the write is stale.
                self._drop_readahead(ctx)
                return length
        except NTStatusError:
            raise
        except Exception as e:
            log.error("write(%s, offset=%d, len=%d) failed: %s",
                      file_context.path, offset, len(buffer), e)
            self._handle_smb_error(e)

    def overwrite(self, file_context, file_attributes, replace_file_attributes,
                  allocation_size):
        ctx = file_context
        try:
            with ctx.io_lock:
                self._discard_writes(ctx)
                self._drop_readahead(ctx)
                self._smb.set_end_of_file(ctx.smb_open, 0)
                ctx.file_size = 0
                ctx.allocation_size = 0
                if replace_file_attributes:
                    ctx.file_attributes = (
                        file_attributes or FILE_ATTRIBUTE.FILE_ATTRIBUTE_NORMAL)
                ctx.last_write_time = filetime_now()
                ctx.change_time = ctx.last_write_time
        except Exception as e:
            log.error("overwrite(%s) failed: %s", file_context.path, e)
            self._handle_smb_error(e)

    def cleanup(self, file_context, file_name, flags):
        if flags & 0x01:
            file_context._delete_pending = True
            try:
                if file_context.smb_open is not None:
                    self._smb.set_delete_on_close(file_context.smb_open)
                else:
                    smb_path = self._to_smb_path(file_name)
                    if file_context.is_directory:
                        self._smb.delete_directory(smb_path)
                    else:
                        self._smb.delete_file(smb_path)
            except Exception as e:
                log.error("cleanup delete(%s) failed: %s", file_name, e)

    def flush(self, file_context):
        ctx = file_context
        if ctx.smb_open is not None:
            try:
                with ctx.io_lock:
                    self._drain_writes(ctx)
                self._smb.flush_file(ctx.smb_open)
            except Exception as e:
                log.error("flush(%s) failed: %s", file_context.path, e)
                self._handle_smb_error(e)

    def get_security(self, file_context):
        return SECURITY_DESCRIPTOR

    def set_security(self, file_context, security_information, modification_descriptor):
        pass

    def set_basic_info(self, file_context, file_attributes, creation_time,
                       last_access_time, last_write_time, change_time, file_info):
        if file_attributes != 0 and file_attributes != 0xFFFFFFFF:
            file_context.file_attributes = file_attributes
        if creation_time:
            file_context.creation_time = creation_time
        if last_access_time:
            file_context.last_access_time = last_access_time
        if last_write_time:
            file_context.last_write_time = last_write_time
        if change_time:
            file_context.change_time = change_time
        return file_context.get_file_info()

    def set_file_size(self, file_context, new_size, set_allocation_size):
        ctx = file_context
        try:
            with ctx.io_lock:
                # Buffered writes must land before we move EOF, otherwise a
                # later flush would re-extend the file.
                self._drain_writes(ctx)
                self._drop_readahead(ctx)
                if not set_allocation_size:
                    self._smb.set_end_of_file(ctx.smb_open, new_size)
                    ctx.file_size = new_size
                ctx.allocation_size = new_size
        except Exception as e:
            log.error("set_file_size(%s, %d) failed: %s",
                      file_context.path, new_size, e)
            self._handle_smb_error(e)

    def can_delete(self, file_context, file_name):
        if file_context.is_directory:
            smb_path = self._to_smb_path(file_name)
            try:
                entries = self._smb.list_directory(smb_path)
                real = [e for e in entries if e["file_name"] not in (".", "..")]
                if real:
                    raise NTStatusDirectoryNotEmpty()
            except NTStatusError:
                raise
            except Exception as e:
                self._handle_smb_error(e)

    def rename(self, file_context, file_name, new_file_name, replace_if_exists):
        old_smb = self._to_smb_path(file_name)
        new_smb = self._to_smb_path(new_file_name)
        try:
            with file_context.io_lock:
                self._drain_writes(file_context)
            self._smb.rename(old_smb, new_smb, replace_if_exists=replace_if_exists)
            file_context.path = new_file_name
            file_context.smb_path = new_smb
            old_parent = self._to_smb_path(self._parent_path(file_name))
            new_parent = self._to_smb_path(self._parent_path(new_file_name))
            self._invalidate_cache(old_parent)
            if new_parent != old_parent:
                self._invalidate_cache(new_parent)
        except NTStatusError:
            raise
        except Exception as e:
            log.error("rename(%s -> %s) failed: %s", file_name, new_file_name, e)
            self._handle_smb_error(e)
