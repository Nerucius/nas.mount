"""Windows adapter: WinFsp (winfspy) callbacks over the shared fs_core
engine. Everything performance-critical (read-ahead, write pipeline,
caching) lives in fs_core.FsCore; this layer translates WinFsp's callback
conventions - NTSTATUS errors, security descriptors, FILETIME timestamps
(already fs_core's native format), delete-on-close semantics."""

import bisect
import ctypes
import logging
import os
import struct
import threading
import time

from winfspy import (
    BaseFileSystemOperations,
    FILE_ATTRIBUTE,
    NTStatusObjectNameNotFound,
    NTStatusEndOfFile,
    NTStatusDirectoryNotEmpty,
    NTStatusError,
)
from winfspy.plumbing.security_descriptor import SecurityDescriptor
from winfspy.plumbing import NTSTATUS, ffi
from winfspy.plumbing.bindings import WINFSP_BIN_DIR
from winfspy.plumbing.get_winfsp_dir import get_winfsp_library_name

from fs_core import FsCore, FsError, ErrorCode

log = logging.getLogger(__name__)

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_ACTION_REMOVED = 0x00000002
NOTIFY_INFO_HEADER_SIZE = 12

SECURITY_DESCRIPTOR = SecurityDescriptor.from_string(
    "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"
)


def _trace_ldb(message, file_name, *args):
    """Keep debug tracing focused on LiteDB traffic during recovery."""
    path = getattr(file_name, "path", file_name)
    if log.isEnabledFor(logging.DEBUG) and str(path).lower().endswith(".ldb"):
        log.debug(message, path, *args)


def _raise_nt(err: FsError):
    """Translate FsError to the NTSTATUS exception WinFsp expects."""
    code = err.code
    if code == ErrorCode.NOT_FOUND:
        raise NTStatusObjectNameNotFound()
    if code == ErrorCode.END_OF_FILE:
        raise NTStatusEndOfFile()
    if code == ErrorCode.DIR_NOT_EMPTY:
        raise NTStatusDirectoryNotEmpty()
    if code == ErrorCode.ACCESS_DENIED:
        raise NTStatusError(NTSTATUS.STATUS_ACCESS_DENIED)
    if code == ErrorCode.EXISTS:
        raise NTStatusError(NTSTATUS.STATUS_OBJECT_NAME_COLLISION)
    if code == ErrorCode.SHARING_VIOLATION:
        raise NTStatusError(NTSTATUS.STATUS_SHARING_VIOLATION)
    if code == ErrorCode.INVALID_HANDLE:
        raise NTStatusError(NTSTATUS.STATUS_INVALID_HANDLE)
    if code == ErrorCode.UNMAPPED and err.ntstatus is not None:
        try:
            raise NTStatusError(NTSTATUS(err.ntstatus))
        except ValueError:
            raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)
    raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)


class SmbFileSystemOperations(BaseFileSystemOperations):

    def __init__(self, smb_client, subpath="", dir_cache_ttl=300,
                 readahead_windows=2, readahead_workers=8,
                 write_buffer_chunks=3, volume_label="NAS"):
        super().__init__()
        self._file_system_ptr = None
        self._winfsp_dll = None
        self._notify_removed_fn = None
        self._notify_lock = threading.Lock()
        self._notified_missing = {}
        self.core = FsCore(
            smb_client, subpath=subpath, dir_cache_ttl=dir_cache_ttl,
            readahead_windows=readahead_windows,
            readahead_workers=readahead_workers,
            write_buffer_chunks=write_buffer_chunks,
            volume_label=volume_label,
            on_phantom=self._notify_removed)

    def attach_file_system(self, file_system):
        """Attach winfspy's native file-system pointer for notifications.

        winfspy 0.8.4 does not expose FspFileSystemNotify, although the
        installed WinFsp DLL does. A removal notification purges Windows'
        stale positive metadata entry when SMB disproves a lazy cache hit.
        """
        dll_path = os.path.join(WINFSP_BIN_DIR, get_winfsp_library_name())
        winfsp_dll = ctypes.WinDLL(dll_path)
        notify = winfsp_dll.FspFileSystemNotify
        notify.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        notify.restype = ctypes.c_int32
        self._winfsp_dll = winfsp_dll
        self._notify_removed_fn = notify
        self._file_system_ptr = int(ffi.cast(
            "uintptr_t", file_system._file_system_ptr[0]))

    def _notify_removed(self, file_name):
        """Tell WinFsp/Windows that a cached file is actually absent."""
        if self._notify_removed_fn is None or self._file_system_ptr is None:
            return
        # This file system is case-insensitive and does not return normalized
        # open names. WinFsp therefore requires the notification name in upper
        # case (matching its own internal normalization).
        normalized = file_name.upper()
        key = normalized.lower()
        now = time.monotonic()
        with self._notify_lock:
            last = self._notified_missing.get(key)
            if last is not None and now - last < 1.0:
                return
            if len(self._notified_missing) > 4096:
                self._notified_missing.clear()
            self._notified_missing[key] = now

        encoded_name = normalized.encode("utf-16-le")
        size = NOTIFY_INFO_HEADER_SIZE + len(encoded_name)
        notify_info = ctypes.create_string_buffer(size)
        struct.pack_into(
            "<H2xII", notify_info, 0, size,
            FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_REMOVED)
        ctypes.memmove(
            ctypes.addressof(notify_info) + NOTIFY_INFO_HEADER_SIZE,
            encoded_name, len(encoded_name))
        status = self._notify_removed_fn(
            ctypes.c_void_p(self._file_system_ptr), notify_info, size)
        if status < 0:
            raise OSError(
                f"FspFileSystemNotify failed with NTSTATUS 0x{status & 0xffffffff:08x}")
        log.debug("notified Windows of removed phantom: %s", file_name)

    def _clear_missing_notification(self, file_name):
        with self._notify_lock:
            self._notified_missing.pop(file_name.upper().lower(), None)

    # -- WinFsp callbacks --

    def get_volume_info(self):
        return self.core.volume_info()

    def get_security_by_name(self, file_name):
        _trace_ldb("get_security_by_name(%s)", file_name)
        if self.core.is_root(file_name):
            return (
                FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
                SECURITY_DESCRIPTOR.handle,
                SECURITY_DESCRIPTOR.size,
            )
        try:
            info = self.core.lookup_or_stat(file_name)
            if info is None:
                _trace_ldb("get_security_by_name(%s) -> NOT_FOUND", file_name)
                raise NTStatusObjectNameNotFound()
            _trace_ldb("get_security_by_name(%s) -> exists", file_name)
            return (
                info["file_attributes"],
                SECURITY_DESCRIPTOR.handle,
                SECURITY_DESCRIPTOR.size,
            )
        except NTStatusError:
            raise
        except FsError as e:
            _raise_nt(e)
        except Exception as e:
            log.debug("get_security_by_name(%s): %s", file_name, e)
            raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)

    def open(self, file_name, create_options, granted_access):
        want_write = bool(granted_access & 0x12B0116)
        dir_hint = bool(create_options & 0x1)
        _trace_ldb(
            "open(%s, options=0x%x, access=0x%x, write=%s)",
            file_name, create_options, granted_access, want_write)
        try:
            handle = self.core.open_handle(file_name, want_write,
                                           dir_hint=dir_hint)
            _trace_ldb("open(%s) -> %s size=%d", file_name,
                       "lazy" if handle.smb_open is None else "materialized",
                       handle.file_size)
            return handle
        except FsError as e:
            _trace_ldb("open(%s) -> %s", file_name, e.code.name)
            _raise_nt(e)

    def close(self, file_context):
        _trace_ldb("close(%s)", file_context)
        self.core.close_handle(file_context)

    def get_file_info(self, file_context):
        with file_context.io_lock:
            self.core.refresh_handle_info(file_context)
            info = file_context.get_file_info()
        return info

    def read(self, file_context, offset, length):
        _trace_ldb("read(%s, offset=%d, length=%d)",
                   file_context, offset, length)
        try:
            data = self.core.read(file_context, offset, length)
            _trace_ldb("read(%s, offset=%d, length=%d) -> %d size=%d",
                       file_context, offset, length, len(data),
                       file_context.file_size)
            return data
        except FsError as e:
            _trace_ldb("read(%s) -> %s", file_context, e.code.name)
            _raise_nt(e)

    def read_directory(self, file_context, marker):
        try:
            children = self.core.list_dir(file_context.smb_path)
        except FsError as e:
            _raise_nt(e)
        except Exception as e:
            log.error("read_directory(%s) failed: %s", file_context.path, e)
            raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)

        entries = list(children)

        if not self.core.is_root(file_context.path):
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
        is_dir = bool(create_options & 0x1)
        _trace_ldb(
            "create(%s, options=0x%x, access=0x%x, allocation=%d)",
            file_name, create_options, granted_access, allocation_size)
        try:
            handle = self.core.create_handle(
                file_name, is_dir, file_attributes=file_attributes)
            self._clear_missing_notification(file_name)
            _trace_ldb("create(%s) -> success size=%d allocation=%d",
                       file_name, handle.file_size, handle.allocation_size)
            return handle
        except FsError as e:
            _trace_ldb("create(%s) -> %s", file_name, e.code.name)
            _raise_nt(e)

    def write(self, file_context, buffer, offset, write_to_end_of_file,
              constrained_io):
        _trace_ldb("write(%s, offset=%d, length=%d)",
                   file_context, offset, len(buffer))
        try:
            written = self.core.write(
                file_context, buffer, offset,
                write_to_end=write_to_end_of_file,
                constrained=constrained_io)
            return written
        except FsError as e:
            _trace_ldb("write(%s) -> %s", file_context, e.code.name)
            _raise_nt(e)

    def overwrite(self, file_context, file_attributes, replace_file_attributes,
                  allocation_size):
        _trace_ldb("overwrite(%s, allocation=%d)",
                   file_context, allocation_size)
        try:
            self.core.overwrite(file_context, file_attributes,
                                replace_file_attributes)
            _trace_ldb("overwrite(%s) -> size=%d",
                       file_context, file_context.file_size)
        except FsError as e:
            _raise_nt(e)

    def cleanup(self, file_context, file_name, flags):
        _trace_ldb("cleanup(%s, flags=0x%x)", file_name, flags)
        if flags & 0x01:
            self.core.mark_delete(file_context, file_name)

    def flush(self, file_context):
        _trace_ldb("flush(%s) size=%d", file_context,
                   file_context.file_size)
        try:
            self.core.flush(file_context)
            _trace_ldb("flush(%s) -> success size=%d", file_context,
                       file_context.file_size)
        except FsError as e:
            _raise_nt(e)

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
        _trace_ldb("set_file_size(%s, size=%d, allocation_only=%s)",
                   file_context, new_size, set_allocation_size)
        try:
            self.core.truncate(file_context, new_size,
                               allocation_only=set_allocation_size)
            _trace_ldb("set_file_size(%s) -> size=%d allocation=%d",
                       file_context, file_context.file_size,
                       file_context.allocation_size)
        except FsError as e:
            _raise_nt(e)

    def can_delete(self, file_context, file_name):
        if file_context.is_directory:
            try:
                self.core.check_dir_empty(file_name)
            except FsError as e:
                _raise_nt(e)

    def rename(self, file_context, file_name, new_file_name, replace_if_exists):
        try:
            self.core.rename(file_context, file_name, new_file_name,
                             replace_if_exists)
        except FsError as e:
            _raise_nt(e)
