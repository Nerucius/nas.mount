import time
import bisect
import logging
import threading

from winfspy import (
    BaseFileSystemOperations,
    FILE_ATTRIBUTE,
    NTStatusObjectNameNotFound,
    NTStatusEndOfFile,
    NTStatusMediaWriteProtected,
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
                 "change_time", "_buf", "_buf_start", "_buf_end")

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
        self._buf = None
        self._buf_start = 0
        self._buf_end = 0

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


class SmbFileSystemOperations(BaseFileSystemOperations):

    def __init__(self, smb_client, subpath="", dir_cache_ttl=300):
        super().__init__()
        self._smb = smb_client
        self._subpath = subpath.replace("/", "\\")
        self._dir_cache_ttl = dir_cache_ttl
        self._dir_cache = {}
        self._cache_lock = threading.Lock()

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
            if status == 0xC0000022:
                from winfspy import NTStatusAccessDenied
                raise NTStatusAccessDenied()
            log.error("SMB error: %s (0x%08x)", exc.message, status)
            raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)
        if isinstance(exc, SMBConnectionClosed):
            log.error("SMB connection lost: %s", exc)
            raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)
        raise NTStatusError(NTSTATUS.STATUS_UNEXPECTED_IO_ERROR)

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
            log.error("get_security_by_name(%s) failed: %s", file_name, e)
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

        info = self._lookup_in_parent(file_name)
        is_dir = False
        if info:
            is_dir = bool(info["file_attributes"] & FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY)
        else:
            is_dir = bool(create_options & 0x1)

        smb_open = None
        if not is_dir:
            try:
                smb_open = self._smb.open_file(smb_path, read=True)
            except Exception as e:
                log.error("open(%s) SMB open failed: %s", file_name, e)
                self._handle_smb_error(e)

        if info:
            ctx = SmbFileContext(
                path=file_name, smb_path=smb_path, smb_open=smb_open,
                is_directory=is_dir,
                file_attributes=info["file_attributes"],
                file_size=info["file_size"],
                allocation_size=info["allocation_size"],
                creation_time=info["creation_time"],
                last_access_time=info["last_access_time"],
                last_write_time=info["last_write_time"],
                change_time=info["change_time"],
            )
        elif smb_open:
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
        else:
            ctx = SmbFileContext(
                path=file_name, smb_path=smb_path, is_directory=True,
                file_attributes=FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
            )
        return ctx

    def close(self, file_context):
        file_context._buf = None
        if file_context.smb_open is not None:
            self._smb.close_file(file_context.smb_open)
            file_context.smb_open = None

    def get_file_info(self, file_context):
        return file_context.get_file_info()

    def _smb_read_chunked(self, file_context, offset, length):
        chunk_size = self._smb.read_size
        if length <= chunk_size:
            return self._smb.read_file(file_context.smb_open, offset, length)
        parts = []
        remaining = length
        pos = offset
        while remaining > 0:
            to_read = min(chunk_size, remaining)
            data = self._smb.read_file(file_context.smb_open, pos, to_read)
            if not data:
                break
            parts.append(data)
            pos += len(data)
            remaining -= len(data)
        return b"".join(parts)

    def read(self, file_context, offset, length):
        if file_context.smb_open is None:
            raise NTStatusEndOfFile()
        if offset >= file_context.file_size:
            raise NTStatusEndOfFile()
        length = min(length, file_context.file_size - offset)
        try:
            buf = file_context._buf
            buf_start = file_context._buf_start
            buf_end = file_context._buf_end
            if buf is not None and buf_start <= offset and offset + length <= buf_end:
                s = offset - buf_start
                return buf[s:s + length]

            readahead = self._smb.read_size
            fetch_len = max(length, readahead)
            fetch_len = min(fetch_len, file_context.file_size - offset)
            data = self._smb_read_chunked(file_context, offset, fetch_len)
            if len(data) > length:
                file_context._buf = data
                file_context._buf_start = offset
                file_context._buf_end = offset + len(data)
            else:
                file_context._buf = None
            return data[:length]
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

    def cleanup(self, file_context, file_name, flags):
        pass

    def flush(self, file_context):
        pass

    def get_security(self, file_context):
        return SECURITY_DESCRIPTOR

    def set_security(self, file_context, security_information, modification_descriptor):
        raise NTStatusMediaWriteProtected()

    def set_basic_info(self, file_context, file_attributes, creation_time,
                       last_access_time, last_write_time, change_time, file_info):
        return file_context.get_file_info()

    def set_file_size(self, file_context, new_size, set_allocation_size):
        raise NTStatusMediaWriteProtected()

    def can_delete(self, file_context, file_name):
        raise NTStatusMediaWriteProtected()

    def rename(self, file_context, file_name, new_file_name, replace_if_exists):
        raise NTStatusMediaWriteProtected()

    def overwrite(self, file_context, file_attributes, replace_file_attributes,
                  allocation_size):
        raise NTStatusMediaWriteProtected()

    def create(self, file_name, create_options, granted_access, file_attributes,
               security_descriptor, allocation_size):
        raise NTStatusMediaWriteProtected()
