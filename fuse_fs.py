"""Windows adapter: WinFsp (winfspy) callbacks over the shared fs_core
engine. Everything performance-critical (read-ahead, write pipeline,
caching) lives in fs_core.FsCore; this layer translates WinFsp's callback
conventions - NTSTATUS errors, security descriptors, FILETIME timestamps
(already fs_core's native format), delete-on-close semantics."""

import bisect
import logging

from winfspy import (
    BaseFileSystemOperations,
    FILE_ATTRIBUTE,
    NTStatusObjectNameNotFound,
    NTStatusEndOfFile,
    NTStatusDirectoryNotEmpty,
    NTStatusError,
)
from winfspy.plumbing.security_descriptor import SecurityDescriptor
from winfspy.plumbing import NTSTATUS

from fs_core import FsCore, FsError, ErrorCode

log = logging.getLogger(__name__)

SECURITY_DESCRIPTOR = SecurityDescriptor.from_string(
    "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"
)


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
                 readahead_windows=2, readahead_workers=8, volume_label="NAS"):
        super().__init__()
        self.core = FsCore(
            smb_client, subpath=subpath, dir_cache_ttl=dir_cache_ttl,
            readahead_windows=readahead_windows,
            readahead_workers=readahead_workers, volume_label=volume_label)

    # -- WinFsp callbacks --

    def get_volume_info(self):
        return self.core.volume_info()

    def get_security_by_name(self, file_name):
        if self.core.is_root(file_name):
            return (
                FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY,
                SECURITY_DESCRIPTOR.handle,
                SECURITY_DESCRIPTOR.size,
            )
        try:
            info = self.core.lookup_or_stat(file_name)
            if info is None:
                raise NTStatusObjectNameNotFound()
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
        try:
            return self.core.open_handle(file_name, want_write,
                                         dir_hint=dir_hint)
        except FsError as e:
            _raise_nt(e)

    def close(self, file_context):
        self.core.close_handle(file_context)

    def get_file_info(self, file_context):
        return file_context.get_file_info()

    def read(self, file_context, offset, length):
        try:
            return self.core.read(file_context, offset, length)
        except FsError as e:
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
        try:
            return self.core.create_handle(file_name, is_dir,
                                           file_attributes=file_attributes)
        except FsError as e:
            _raise_nt(e)

    def write(self, file_context, buffer, offset, write_to_end_of_file,
              constrained_io):
        try:
            return self.core.write(file_context, buffer, offset,
                                   write_to_end=write_to_end_of_file,
                                   constrained=constrained_io)
        except FsError as e:
            _raise_nt(e)

    def overwrite(self, file_context, file_attributes, replace_file_attributes,
                  allocation_size):
        try:
            self.core.overwrite(file_context, file_attributes,
                                replace_file_attributes)
        except FsError as e:
            _raise_nt(e)

    def cleanup(self, file_context, file_name, flags):
        if flags & 0x01:
            self.core.mark_delete(file_context, file_name)

    def flush(self, file_context):
        try:
            self.core.flush(file_context)
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
        try:
            self.core.truncate(file_context, new_size,
                               allocation_only=set_allocation_size)
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
