"""macOS adapter: fusepy (FUSE-T or macFUSE) operations over the shared
fs_core engine. Same read-ahead / write-pipeline machinery as Windows;
this layer translates POSIX conventions - errno errors, epoch timestamps,
slash paths, direct unlink instead of delete-on-close."""

import os
import time
import stat as stat_m
import errno
import logging
import threading

# FUSE-T ships a libfuse-2-ABI-compatible dylib; point fusepy at it before
# import unless the user already chose a library.
if "FUSE_LIBRARY_PATH" not in os.environ:
    for _cand in ("/usr/local/lib/libfuse-t.dylib",
                  "/opt/homebrew/lib/libfuse-t.dylib",
                  "/usr/local/lib/libosxfuse.2.dylib"):
        if os.path.exists(_cand):
            os.environ["FUSE_LIBRARY_PATH"] = _cand
            break

from fuse import FUSE, FuseOSError, Operations

from fs_core import (
    FsCore,
    FsError,
    ErrorCode,
    FILE_ATTRIBUTE_DIRECTORY,
    filetime_to_epoch,
)

log = logging.getLogger(__name__)

_ERRNO_MAP = {
    ErrorCode.NOT_FOUND: errno.ENOENT,
    ErrorCode.ACCESS_DENIED: errno.EACCES,
    ErrorCode.EXISTS: errno.EEXIST,
    ErrorCode.SHARING_VIOLATION: errno.EBUSY,
    ErrorCode.DIR_NOT_EMPTY: errno.ENOTEMPTY,
    ErrorCode.IS_DIRECTORY: errno.EISDIR,
    ErrorCode.INVALID_HANDLE: errno.EBADF,
    ErrorCode.IO_ERROR: errno.EIO,
    ErrorCode.UNMAPPED: errno.EIO,
}

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC | os.O_CREAT


def _raise_errno(err: FsError):
    if err.code == ErrorCode.END_OF_FILE:
        # POSIX reads past EOF return empty, they don't error; callers that
        # can't do that map it here.
        raise FuseOSError(errno.EIO)
    raise FuseOSError(_ERRNO_MAP.get(err.code, errno.EIO))


class _SinkFile:
    """In-memory stand-in for AppleDouble/.DS_Store junk files. macOS NFS
    has no xattr path, so the client writes ._* AppleDouble files; Samba
    fruit vetoes those names and cp/Finder copies fail. We pretend to
    store them and never touch the wire."""
    __slots__ = ("path", "data", "mtime")

    def __init__(self, path):
        self.path = path
        self.data = bytearray()
        self.mtime = time.time()


def _is_junk(wpath):
    name = wpath.rsplit("\\", 1)[-1]
    return name.startswith("._") or name == ".DS_Store"


class SmbMacOperations(Operations):

    MAX_SINK_FILES = 512

    def __init__(self, smb_client, subpath="", dir_cache_ttl=300,
                 readahead_windows=2, readahead_workers=8,
                 write_buffer_chunks=3, volume_label="NAS"):
        self.core = FsCore(
            smb_client, subpath=subpath, dir_cache_ttl=dir_cache_ttl,
            readahead_windows=readahead_windows,
            readahead_workers=readahead_workers,
            write_buffer_chunks=write_buffer_chunks,
            volume_label=volume_label)
        self._uid = os.getuid()
        self._gid = os.getgid()
        self._handles = {}          # fh int -> FileHandle | _SinkFile
        self._by_path = {}          # win path -> set of open fh ints
        self._table_lock = threading.Lock()
        self._next_fh = 1
        self._sink = {}             # win path -> _SinkFile
        self._sink_lock = threading.Lock()

    # -- helpers --

    def _p(self, path):
        """POSIX path -> engine (backslash) path."""
        p = path.replace("/", "\\")
        return p if p else "\\"

    def _register(self, handle):
        with self._table_lock:
            fh = self._next_fh
            self._next_fh += 1
            self._handles[fh] = handle
            self._by_path.setdefault(handle.path, set()).add(fh)
        return fh

    def _get(self, fh):
        try:
            return self._handles[fh]
        except KeyError:
            raise FuseOSError(errno.EBADF)

    def _unregister(self, fh):
        with self._table_lock:
            handle = self._handles.pop(fh, None)
            if handle is not None:
                fhs = self._by_path.get(handle.path)
                if fhs:
                    fhs.discard(fh)
                    if not fhs:
                        del self._by_path[handle.path]
        return handle

    def _open_handle_for_path(self, wpath):
        """Freshest open handle for a path (buffered writes make the
        server-side size stale)."""
        with self._table_lock:
            fhs = self._by_path.get(wpath)
            if fhs:
                return self._handles.get(max(fhs))
        return None

    def _stat_from_info(self, attrs, size, ctime_ft, mtime_ft, atime_ft):
        is_dir = bool(attrs & FILE_ATTRIBUTE_DIRECTORY)
        mode = (stat_m.S_IFDIR | 0o755) if is_dir else (stat_m.S_IFREG | 0o644)
        return {
            "st_mode": mode,
            "st_size": 0 if is_dir else size,
            "st_ctime": filetime_to_epoch(ctime_ft),
            "st_mtime": filetime_to_epoch(mtime_ft),
            "st_atime": filetime_to_epoch(atime_ft),
            "st_birthtime": filetime_to_epoch(ctime_ft),
            "st_nlink": 1,
            "st_uid": self._uid,
            "st_gid": self._gid,
        }

    def _sink_get(self, wpath):
        with self._sink_lock:
            return self._sink.get(wpath)

    def _sink_put(self, wpath):
        with self._sink_lock:
            sf = self._sink.get(wpath)
            if sf is None:
                sf = _SinkFile(wpath)
                self._sink[wpath] = sf
                while len(self._sink) > self.MAX_SINK_FILES:
                    self._sink.pop(next(iter(self._sink)))
            return sf

    def _sink_stat(self, sf):
        return {
            "st_mode": stat_m.S_IFREG | 0o644,
            "st_size": len(sf.data),
            "st_ctime": sf.mtime, "st_mtime": sf.mtime, "st_atime": sf.mtime,
            "st_birthtime": sf.mtime,
            "st_nlink": 1, "st_uid": self._uid, "st_gid": self._gid,
        }

    # -- metadata --

    def getattr(self, path, fh=None):
        wpath = self._p(path)
        if _is_junk(wpath):
            sf = self._sink_get(wpath)
            if sf is None:
                raise FuseOSError(errno.ENOENT)
            return self._sink_stat(sf)
        if fh is not None:
            handle = self._get(fh)
            return self._stat_from_info(
                handle.file_attributes, handle.file_size,
                handle.creation_time, handle.last_write_time,
                handle.last_access_time)
        if self.core.is_root(wpath):
            return self._stat_from_info(FILE_ATTRIBUTE_DIRECTORY, 0, 0, 0, 0)
        # An open handle has the freshest size (write-behind buffering).
        handle = self._open_handle_for_path(wpath)
        if handle is not None:
            return self._stat_from_info(
                handle.file_attributes, handle.file_size,
                handle.creation_time, handle.last_write_time,
                handle.last_access_time)
        try:
            info = self.core.lookup_or_stat(wpath)
        except FsError as e:
            _raise_errno(e)
        except FuseOSError:
            raise
        except Exception as e:
            log.error("getattr(%s) failed: %s", path, e)
            raise FuseOSError(errno.EIO)
        if info is None:
            raise FuseOSError(errno.ENOENT)
        return self._stat_from_info(
            info["file_attributes"], info["file_size"],
            info["creation_time"], info["last_write_time"],
            info["last_access_time"])

    def readdir(self, path, fh):
        wpath = self._p(path)
        try:
            entries = self.core.list_dir(self.core.to_smb_path(wpath))
        except FsError as e:
            _raise_errno(e)
        except FuseOSError:
            raise
        except Exception as e:
            log.error("readdir(%s) failed: %s", path, e)
            raise FuseOSError(errno.EIO)
        return [".", ".."] + [e["file_name"] for e in entries]

    def statfs(self, path):
        info = self.core.volume_info()
        bsize = 4096
        total = info["total_size"] // bsize
        free = info["free_size"] // bsize
        return {
            "f_bsize": bsize,
            "f_frsize": bsize,
            "f_blocks": total,
            "f_bfree": free,
            "f_bavail": free,
            "f_files": 1 << 20,
            "f_ffree": 1 << 19,
            "f_namemax": 255,
        }

    # -- open/create/release --

    def open(self, path, flags):
        wpath = self._p(path)
        if _is_junk(wpath):
            sf = self._sink_get(wpath)
            if sf is None:
                if not (flags & os.O_CREAT):
                    raise FuseOSError(errno.ENOENT)
                sf = self._sink_put(wpath)
            if flags & os.O_TRUNC:
                sf.data = bytearray()
            return self._register(sf)
        want_write = bool(flags & _WRITE_FLAGS)
        try:
            handle = self.core.open_handle(wpath, want_write)
            if flags & os.O_TRUNC and not handle.is_directory:
                self.core.truncate(handle, 0)
        except FsError as e:
            _raise_errno(e)
        return self._register(handle)

    def create(self, path, mode, fi=None):
        wpath = self._p(path)
        if _is_junk(wpath):
            sf = self._sink_put(wpath)
            sf.data = bytearray()
            return self._register(sf)
        try:
            handle = self.core.create_handle(wpath, is_dir=False)
        except FsError as e:
            _raise_errno(e)
        return self._register(handle)

    def release(self, path, fh):
        handle = self._unregister(fh)
        if handle is not None and not isinstance(handle, _SinkFile):
            try:
                self.core.close_handle(handle)
            except Exception as e:
                log.error("release(%s) failed: %s", path, e)
        return 0

    # -- data --

    def read(self, path, size, offset, fh):
        handle = self._get(fh)
        if isinstance(handle, _SinkFile):
            return bytes(handle.data[offset:offset + size])
        try:
            return self.core.read(handle, offset, size)
        except FsError as e:
            if e.code == ErrorCode.END_OF_FILE:
                return b""
            _raise_errno(e)

    def write(self, path, data, offset, fh):
        handle = self._get(fh)
        if isinstance(handle, _SinkFile):
            buf = handle.data
            if len(buf) < offset:
                buf.extend(b"\x00" * (offset - len(buf)))
            buf[offset:offset + len(data)] = data
            handle.mtime = time.time()
            return len(data)
        try:
            return self.core.write(handle, data, offset)
        except FsError as e:
            _raise_errno(e)

    def truncate(self, path, length, fh=None):
        wpath = self._p(path)
        if _is_junk(wpath):
            sf = self._sink_get(wpath) or self._sink_put(wpath)
            del sf.data[length:]
            if len(sf.data) < length:
                sf.data.extend(b"\x00" * (length - len(sf.data)))
            return 0
        if fh is not None:
            handle = self._get(fh)
            try:
                self.core.truncate(handle, length)
            except FsError as e:
                _raise_errno(e)
            return 0
        handle = self._open_handle_for_path(wpath)
        if handle is not None and handle.smb_open is not None:
            try:
                self.core.truncate(handle, length)
            except FsError as e:
                _raise_errno(e)
            return 0
        try:
            tmp = self.core.open_handle(wpath, want_write=True)
            try:
                self.core.truncate(tmp, length)
            finally:
                self.core.close_handle(tmp)
        except FsError as e:
            _raise_errno(e)
        return 0

    def flush(self, path, fh):
        # NFS COMMIT: data must reach the server; per-commit disk syncs
        # would stall the write pipeline every few MB.
        handle = self._get(fh)
        if isinstance(handle, _SinkFile):
            return 0
        try:
            self.core.flush(handle, sync_disk=False)
        except FsError as e:
            _raise_errno(e)
        return 0

    def fsync(self, path, datasync, fh):
        return self.flush(path, fh)

    # -- namespace --

    def unlink(self, path):
        wpath = self._p(path)
        if _is_junk(wpath):
            with self._sink_lock:
                if self._sink.pop(wpath, None) is None:
                    raise FuseOSError(errno.ENOENT)
            return 0
        try:
            self.core.delete_path(wpath, is_dir=False)
        except FsError as e:
            _raise_errno(e)
        return 0

    def rmdir(self, path):
        wpath = self._p(path)
        try:
            self.core.check_dir_empty(wpath)
            self.core.delete_path(wpath, is_dir=True)
        except FsError as e:
            _raise_errno(e)
        return 0

    def mkdir(self, path, mode):
        wpath = self._p(path)
        try:
            self.core.create_handle(wpath, is_dir=True)
        except FsError as e:
            _raise_errno(e)
        return 0

    def rename(self, old, new):
        wold, wnew = self._p(old), self._p(new)
        if _is_junk(wold) or _is_junk(wnew):
            with self._sink_lock:
                sf = self._sink.pop(wold, None)
            if _is_junk(wnew) and sf is not None:
                sf.path = wnew
                with self._sink_lock:
                    self._sink[wnew] = sf
            return 0
        handle = self._open_handle_for_path(wold)
        try:
            self.core.rename(handle, wold, wnew, replace_if_exists=True)
        except FsError as e:
            _raise_errno(e)
        return 0

    # -- permissions/attrs: pretend success, never hit the wire --

    def chmod(self, path, mode):
        return 0

    def chown(self, path, uid, gid):
        return 0

    def utimens(self, path, times=None):
        return 0

    # -- xattrs: accept and drop, never hit the wire. Refusing (ENOTSUP)
    # makes cp/Finder copies fail; quarantine flags and Finder tags are
    # meaningless on the NAS anyway. --

    def getxattr(self, path, name, position=0):
        raise FuseOSError(errno.ENODATA)

    def listxattr(self, path):
        return []

    def setxattr(self, path, name, value, options, position=0):
        return 0

    def removexattr(self, path, name):
        return 0


def mount_macos(ops, mountpoint, volume_label, foreground=True, debug=False,
                rwsize=1048576, daemon_timeout=600, location=None):
    """Mount one share; blocks until unmounted (run in a thread per mount).
    location: server name Finder shows for the mounts (default 'fuse-t');
    the name must resolve to 127.0.0.1 via /etc/hosts or FUSE-T silently
    falls back to 'localhost'."""
    os.makedirs(mountpoint, exist_ok=True)
    kwargs = {
        "foreground": foreground,
        "nothreads": False,
        "fsname": "nas-mount",
        "volname": volume_label,
        # WAN operations can be slow; don't let the kernel force-eject.
        "daemon_timeout": daemon_timeout,
        # Kill AppleDouble ._* traffic at the source.
        "noappledouble": True,
        # Bigger NFS transfer size: fewer, larger callbacks (default 32K).
        "rwsize": rwsize,
    }
    if location:
        kwargs["location"] = location
    if debug:
        kwargs["debug"] = True
    FUSE(ops, mountpoint, **kwargs)
