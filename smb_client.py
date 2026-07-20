import uuid
import time
import logging
import threading
from datetime import datetime, timezone

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import (
    Open,
    ImpersonationLevel,
    FilePipePrinterAccessMask,
    DirectoryAccessMask,
    CreateDisposition,
    CreateOptions,
    ShareAccess,
)
from smbprotocol.file_info import FileAttributes, FileInformationClass
from smbprotocol.exceptions import (
    SMBConnectionClosed,
    SMBException,
    SMBResponseException,
    NoMoreFiles,
)

log = logging.getLogger(__name__)

EPOCH_AS_FILETIME = 116444736000000000  # 1601-01-01 in 100ns ticks


def dt_to_filetime(dt: datetime) -> int:
    if dt is None:
        return 0
    return EPOCH_AS_FILETIME + int(dt.timestamp() * 10_000_000)


class SMBClient:

    def __init__(self, host, port, username, password, share_name,
                 read_size=4 * 1024 * 1024, write_size=4 * 1024 * 1024,
                 reconnect_delay=5, max_reconnect_attempts=10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.share_name = share_name
        self.read_size = read_size
        self.write_size = write_size
        self.reconnect_delay = reconnect_delay
        self.max_reconnect_attempts = max_reconnect_attempts

        self._lock = threading.Lock()
        self._connection = None
        self._session = None
        self._tree = None

    @property
    def connected(self):
        return self._tree is not None

    def connect(self, timeout=30):
        with self._lock:
            self._connect(timeout)

    def _connect(self, timeout=30):
        log.info("Connecting to %s:%d share=%s user=%s",
                 self.host, self.port, self.share_name, self.username)
        self._connection = Connection(uuid.uuid4(), self.host, self.port,
                                      require_signing=True)
        self._connection.connect(timeout=timeout)
        log.debug("SMB negotiated dialect=0x%04x max_read=%d max_write=%d signing=%s",
                  self._connection.dialect,
                  self._connection.max_read_size,
                  self._connection.max_write_size,
                  self._connection.require_signing)

        self._session = Session(self._connection, self.username, self.password,
                                require_encryption=False)
        self._session.connect()
        log.debug("Session authenticated, session_id=%s", self._session.session_id)

        unc = f"\\\\{self.host}\\{self.share_name}"
        self._tree = TreeConnect(self._session, unc)
        self._tree.connect(require_secure_negotiate=False)
        log.info("Connected to %s", unc)

    def disconnect(self):
        with self._lock:
            self._disconnect()

    def _disconnect(self):
        for name, obj in [("tree", self._tree),
                          ("session", self._session),
                          ("connection", self._connection)]:
            if obj is not None:
                try:
                    obj.disconnect()
                except Exception as e:
                    log.debug("Error disconnecting %s: %s", name, e)
        self._tree = None
        self._session = None
        self._connection = None
        log.info("Disconnected")

    def reconnect(self):
        with self._lock:
            self._reconnect()

    def _reconnect(self):
        delay = self.reconnect_delay
        for attempt in range(1, self.max_reconnect_attempts + 1):
            log.warning("Reconnect attempt %d/%d (delay %.1fs)",
                        attempt, self.max_reconnect_attempts, delay)
            self._disconnect()
            time.sleep(delay)
            try:
                self._connect()
                log.info("Reconnected on attempt %d", attempt)
                return
            except Exception as e:
                log.error("Reconnect attempt %d failed: %s", attempt, e)
                delay = min(delay * 2, 60)
        raise SMBConnectionClosed("Failed to reconnect after %d attempts"
                                  % self.max_reconnect_attempts)

    def _with_reconnect(self, fn):
        try:
            return fn()
        except (SMBConnectionClosed, OSError) as e:
            log.warning("Connection lost (%s), attempting reconnect", e)
            self._reconnect()
            raise

    def list_directory(self, path=""):
        with self._lock:
            return self._with_reconnect(lambda: self._list_directory(path))

    def _list_directory(self, path):
        dir_open = Open(self._tree, path)
        try:
            dir_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.FILE_LIST_DIRECTORY
                | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
            entries = []
            try:
                raw = dir_open.query_directory(
                    "*", FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION)
                for entry in raw:
                    name = entry["file_name"].get_value().decode("utf-16-le")
                    entries.append({
                        "file_name": name,
                        "file_attributes": entry["file_attributes"].get_value(),
                        "end_of_file": entry["end_of_file"].get_value(),
                        "allocation_size": entry["allocation_size"].get_value(),
                        "creation_time": entry["creation_time"].get_value(),
                        "last_access_time": entry["last_access_time"].get_value(),
                        "last_write_time": entry["last_write_time"].get_value(),
                        "change_time": entry["change_time"].get_value(),
                    })
            except NoMoreFiles:
                pass
            return entries
        finally:
            try:
                dir_open.close()
            except Exception:
                pass

    def stat_path(self, path):
        with self._lock:
            return self._with_reconnect(lambda: self._stat_path(path))

    def _stat_path(self, path):
        is_root = path == "" or path == "\\"
        file_open = Open(self._tree, path)
        try:
            if is_root:
                file_open.create(
                    ImpersonationLevel.Impersonation,
                    DirectoryAccessMask.FILE_READ_ATTRIBUTES,
                    FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                    ShareAccess.FILE_SHARE_READ,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_DIRECTORY_FILE,
                )
            else:
                file_open.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
                    FileAttributes.FILE_ATTRIBUTE_NORMAL,
                    ShareAccess.FILE_SHARE_READ,
                    CreateDisposition.FILE_OPEN,
                    0,
                )
            return {
                "file_attributes": file_open.file_attributes,
                "end_of_file": file_open.end_of_file,
                "allocation_size": file_open.allocation_size,
                "creation_time": file_open.creation_time,
                "last_access_time": file_open.last_access_time,
                "last_write_time": file_open.last_write_time,
                "change_time": file_open.change_time,
            }
        finally:
            try:
                file_open.close()
            except Exception:
                pass

    def open_file(self, path, read=True, write=False):
        with self._lock:
            return self._with_reconnect(
                lambda: self._open_file(path, read, write))

    def _open_file(self, path, read, write):
        file_open = Open(self._tree, path)
        access = 0
        if read:
            access |= (FilePipePrinterAccessMask.FILE_READ_DATA
                       | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES)
        if write:
            access |= (FilePipePrinterAccessMask.FILE_WRITE_DATA
                       | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES
                       | FilePipePrinterAccessMask.FILE_APPEND_DATA)
        file_open.create(
            ImpersonationLevel.Impersonation,
            access,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        return file_open

    def read_file(self, file_open, offset, length):
        with self._lock:
            return self._with_reconnect(
                lambda: file_open.read(offset, length))

    def write_file(self, file_open, data, offset=0):
        with self._lock:
            return self._with_reconnect(
                lambda: file_open.write(data, offset))

    def close_file(self, file_open):
        with self._lock:
            try:
                file_open.close()
            except Exception as e:
                log.debug("Error closing file: %s", e)

    def flush_file(self, file_open):
        with self._lock:
            return self._with_reconnect(lambda: file_open.flush())

    def create_file(self, path, is_directory=False):
        with self._lock:
            return self._with_reconnect(
                lambda: self._create_file(path, is_directory))

    def _create_file(self, path, is_directory):
        file_open = Open(self._tree, path)
        if is_directory:
            file_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.FILE_LIST_DIRECTORY
                | DirectoryAccessMask.FILE_ADD_FILE
                | DirectoryAccessMask.FILE_ADD_SUBDIRECTORY
                | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_CREATE,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
        else:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_WRITE_DATA
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
                | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_CREATE,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
        return file_open

    def delete_file(self, path):
        with self._lock:
            return self._with_reconnect(lambda: self._delete_file(path))

    def _delete_file(self, path):
        file_open = Open(self._tree, path)
        file_open.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.DELETE,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DELETE_ON_CLOSE | CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        file_open.close()
