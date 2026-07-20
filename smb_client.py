import uuid
import time
import logging
import threading
from collections import deque
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
from smbprotocol.file_info import (
    FileAttributes,
    FileInformationClass,
    FileSystemInformationClass,
    FileFsFullSizeInformation,
    FileDispositionInformation,
    FileEndOfFileInformation,
    FileRenameInformation,
)
from smbprotocol.open import (
    SMB2SetInfoRequest, SMB2SetInfoResponse,
    SMB2QueryInfoRequest, SMB2QueryInfoResponse,
)
from smbprotocol.exceptions import (
    SMBConnectionClosed,
    SMBException,
    SMBResponseException,
    NoMoreFiles,
)

log = logging.getLogger(__name__)

EPOCH_AS_FILETIME = 116444736000000000  # 1601-01-01 in 100ns ticks

STATUS_END_OF_FILE = 0xC0000011

# Directory-listing query buffer. One 1 MB page holds any directory whose
# worst-case-encoded entries fit (FILE_BOTH_DIRECTORY_INFORMATION is at most
# ~608 bytes/entry), so a listing under LIST_SAFE_ENTRIES entries returned by
# a single query is provably complete without a second round trip.
LIST_PAGE_SIZE = 1048576
LIST_SAFE_ENTRIES = 1600

# Errors that mean the TCP connection (or the SMB session on it) is gone.
CONNECTION_ERRORS = (SMBConnectionClosed, ConnectionError, BrokenPipeError,
                     TimeoutError, OSError)


def dt_to_filetime(dt: datetime) -> int:
    if dt is None:
        return 0
    return EPOCH_AS_FILETIME + int(dt.timestamp() * 10_000_000)


def _credit_charge(nbytes):
    return (nbytes + 65535) // 65536


class PipelinedWriter:
    """Sliding-window pipelined writer for one open SMB file handle.

    submit() splits data into write_size chunks and keeps up to `depth`
    write requests in flight. It blocks (backpressure) when the window is
    full, so callers are naturally paced at network speed while the
    connection never goes idle between chunks or between submit() calls.
    drain() waits for everything outstanding.

    Not thread-safe per instance: one writer belongs to one file handle and
    is driven under the owning file context's lock.
    """

    def __init__(self, client, file_open, depth):
        self._client = client
        self._file_open = file_open
        self._depth = depth
        self._pending = deque()  # (request, receive_func, nbytes)
        self.bytes_acked = 0

    @property
    def in_flight(self):
        return len(self._pending)

    def submit(self, data, offset):
        conn = self._file_open.connection
        chunk_size = min(self._client.write_size, conn.max_write_size)
        pos = 0
        n = len(data)
        while pos < n:
            end = min(pos + chunk_size, n)
            self._send_chunk(data[pos:end], offset + pos)
            pos = end

    def _send_chunk(self, chunk, offset):
        conn = self._file_open.connection
        sid = self._file_open.tree_connect.session.session_id
        tid = self._file_open.tree_connect.tree_connect_id
        charge = _credit_charge(len(chunk))

        while len(self._pending) >= self._depth:
            self._complete_one()
        # smbprotocol raises if a request exceeds available credits, so
        # drain in-flight responses (which replenish credits) until we fit.
        while self._client._available_credits() < charge and self._pending:
            self._complete_one()

        msg, recv = self._file_open.write(chunk, offset, send=False)
        request = conn.send(msg, sid, tid, credit_request=charge + 8)
        self._pending.append((request, recv, len(chunk)))

    def _complete_one(self):
        request, recv, nbytes = self._pending.popleft()
        self.bytes_acked += recv(request)

    def drain(self):
        while self._pending:
            self._complete_one()


class SMBClient:
    """Thread-safe SMB connection wrapper.

    smbprotocol's Connection is internally thread-safe (socket send lock,
    sequence/credit lock, dedicated receiver thread with per-request
    events), so SMB operations here run concurrently without a global
    lock. A state lock only serializes connect/disconnect/reconnect, and
    reconnects are single-flight: whichever thread hits the dead socket
    first rebuilds the connection, everyone else fails fast and lets the
    caller (Windows) retry.
    """

    def __init__(self, host, port, username, password, share_name,
                 read_size=4 * 1024 * 1024, write_size=4 * 1024 * 1024,
                 read_pipeline_depth=3, write_pipeline_depth=4,
                 reconnect_delay=5, max_reconnect_attempts=10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.share_name = share_name
        self.read_size = read_size
        self.write_size = write_size
        self.read_pipeline_depth = read_pipeline_depth
        self.write_pipeline_depth = write_pipeline_depth
        self.reconnect_delay = reconnect_delay
        self.max_reconnect_attempts = max_reconnect_attempts

        self._state_lock = threading.RLock()
        self._connection = None
        self._session = None
        self._tree = None

    @property
    def connected(self):
        return self._tree is not None

    def _available_credits(self):
        sw = self._connection.sequence_window
        return sw["high"] - sw["low"]

    # -- connection lifecycle --

    def connect(self, timeout=30):
        with self._state_lock:
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

        # Pre-load enough credits for full read+write pipelines. The server
        # grants credits incrementally, so echo until the pool is deep enough.
        per_op = max(self.read_size, self.write_size) // 65536
        target = per_op * (self.read_pipeline_depth + self.write_pipeline_depth) + 64
        for _ in range(6):
            if self._available_credits() >= target:
                break
            self._connection.echo(sid=self._session.session_id,
                                  credit_request=target)
        sw = self._connection.sequence_window
        log.info("Connected to %s (credits: %d available)",
                 unc, sw["high"] - sw["low"])

    def disconnect(self):
        with self._state_lock:
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
        with self._state_lock:
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
        failed_conn = self._connection
        try:
            return fn()
        except CONNECTION_ERRORS as e:
            log.warning("Connection lost (%s), checking connection", e)
            with self._state_lock:
                # Single-flight: only reconnect if nobody else already did.
                if self._connection is not failed_conn:
                    raise
                # Ops on handles from a previous connection raise the same
                # errors; don't tear down a healthy connection for them.
                try:
                    self._connection.echo(sid=self._session.session_id)
                    log.info("Connection is healthy (stale handle error)")
                except Exception:
                    self._reconnect()
            raise

    # -- reads --

    def read_file(self, file_open, offset, length):
        """Single-request read (length must be <= negotiated max read)."""
        return self._with_reconnect(lambda: file_open.read(offset, length))

    def read_file_pipelined(self, file_open, offset, length):
        """Read `length` bytes keeping read_pipeline_depth requests in
        flight so the pipe never drains between chunks."""
        return self._with_reconnect(
            lambda: self._read_pipelined(file_open, offset, length))

    def _read_pipelined(self, file_open, offset, length):
        conn = file_open.connection
        sid = file_open.tree_connect.session.session_id
        tid = file_open.tree_connect.tree_connect_id
        chunk_size = min(self.read_size, conn.max_read_size)

        pending = deque()  # (request, receive_func, expected_len)
        parts = []
        eof = False
        pos = offset
        end = offset + length
        while pos < end or pending:
            while (not eof and pos < end
                   and len(pending) < self.read_pipeline_depth):
                n = min(chunk_size, end - pos)
                charge = _credit_charge(n)
                if self._available_credits() < charge and pending:
                    break
                msg, recv = file_open.read(pos, n, send=False)
                request = conn.send(msg, sid, tid, credit_request=charge + 8)
                pending.append((request, recv, n))
                pos += n
            request, recv, expected = pending.popleft()
            try:
                data = recv(request)
            except SMBResponseException as e:
                if e.status == STATUS_END_OF_FILE:
                    eof = True
                    continue
                raise
            if not eof:
                parts.append(data)
                if len(data) < expected:
                    # Short read: stop here so the result stays contiguous.
                    # Remaining in-flight responses are drained and discarded.
                    eof = True
        return b"".join(parts)

    # -- writes --

    def make_writer(self, file_open):
        return PipelinedWriter(self, file_open, self.write_pipeline_depth)

    def write_file(self, file_open, data, offset=0):
        if not isinstance(data, bytes):
            data = bytes(data)
        return self._with_reconnect(
            lambda: self._write_file(file_open, data, offset))

    def _write_file(self, file_open, data, offset):
        writer = self.make_writer(file_open)
        writer.submit(data, offset)
        writer.drain()
        return writer.bytes_acked

    # -- metadata operations (rely on smbprotocol's internal locking) --

    def list_directory(self, path=""):
        return self._with_reconnect(lambda: self._list_directory(path))

    @staticmethod
    def _dir_entry(entry):
        return {
            "file_name": entry["file_name"].get_value().decode("utf-16-le"),
            "file_attributes": entry["file_attributes"].get_value(),
            "end_of_file": entry["end_of_file"].get_value(),
            "allocation_size": entry["allocation_size"].get_value(),
            "creation_time": entry["creation_time"].get_value(),
            "last_access_time": entry["last_access_time"].get_value(),
            "last_write_time": entry["last_write_time"].get_value(),
            "change_time": entry["change_time"].get_value(),
        }

    def _list_directory(self, path):
        # CREATE + QUERY_DIRECTORY + CLOSE as one related compound: a full
        # listing costs a single round trip. Only when the single page
        # cannot be proven complete (LIST_SAFE_ENTRIES) re-list paged.
        dir_open = Open(self._tree, path)
        create_msg, create_recv = dir_open.create(
            ImpersonationLevel.Impersonation,
            DirectoryAccessMask.FILE_LIST_DIRECTORY
            | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            ShareAccess.FILE_SHARE_READ,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DIRECTORY_FILE,
            send=False,
        )
        query_msg, query_recv = dir_open.query_directory(
            "*", FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION,
            max_output=LIST_PAGE_SIZE, send=False,
        )
        close_msg, close_recv = dir_open.close(send=False)
        requests = self._connection.send_compound(
            [create_msg, query_msg, close_msg],
            self._session.session_id, self._tree.tree_connect_id,
            related=True,
        )
        # All three responses must be consumed even when the create fails,
        # or they linger in the connection's outstanding-request table.
        create_exc = query_exc = None
        raw = []
        try:
            create_recv(requests[0])
        except Exception as e:
            create_exc = e
        try:
            raw = query_recv(requests[1])
        except NoMoreFiles:
            pass
        except Exception as e:
            query_exc = e
        try:
            close_recv(requests[2])
        except Exception:
            pass
        if create_exc is not None:
            raise create_exc
        if query_exc is not None:
            raise query_exc
        if len(raw) >= LIST_SAFE_ENTRIES:
            return self._list_directory_paged(path)
        return [self._dir_entry(e) for e in raw]

    def _list_directory_paged(self, path):
        """Huge-directory path: page through query_directory until
        NoMoreFiles (a single query returns at most one buffer's worth)."""
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
            while True:
                try:
                    raw = dir_open.query_directory(
                        "*",
                        FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION,
                        max_output=LIST_PAGE_SIZE)
                except NoMoreFiles:
                    break
                entries.extend(self._dir_entry(e) for e in raw)
            return entries
        finally:
            try:
                dir_open.close()
            except Exception:
                pass

    def stat_path(self, path):
        return self._with_reconnect(lambda: self._stat_path(path))

    def _stat_path(self, path):
        # CREATE + CLOSE as one related compound - the create response
        # carries all the metadata, so a stat (hit or miss) is one round
        # trip. CreateOptions=0 opens files and directories alike.
        file_open = Open(self._tree, path)
        create_msg, create_recv = file_open.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
            | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            0,
            send=False,
        )
        close_msg, close_recv = file_open.close(send=False)
        requests = self._connection.send_compound(
            [create_msg, close_msg],
            self._session.session_id, self._tree.tree_connect_id,
            related=True,
        )
        create_exc = None
        try:
            create_recv(requests[0])
        except Exception as e:
            create_exc = e
        try:
            close_recv(requests[1])
        except Exception:
            pass
        if create_exc is not None:
            raise create_exc
        return {
            "file_attributes": file_open.file_attributes,
            "end_of_file": file_open.end_of_file,
            "allocation_size": file_open.allocation_size,
            "creation_time": file_open.creation_time,
            "last_access_time": file_open.last_access_time,
            "last_write_time": file_open.last_write_time,
            "change_time": file_open.change_time,
        }

    def query_volume_info(self):
        return self._with_reconnect(self._query_volume_info)

    def _query_volume_info(self):
        dir_open = Open(self._tree, "")
        try:
            dir_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.FILE_READ_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
            info = FileFsFullSizeInformation()
            req = SMB2QueryInfoRequest()
            req["info_type"] = info.INFO_TYPE
            req["file_info_class"] = info.INFO_CLASS
            req["file_id"] = dir_open.file_id
            req["output_buffer_length"] = 56
            request = dir_open.connection.send(
                req, dir_open.tree_connect.session.session_id,
                dir_open.tree_connect.tree_connect_id)
            response = dir_open.connection.receive(request)
            resp = SMB2QueryInfoResponse()
            resp.unpack(response["data"].get_value())
            info.unpack(resp["buffer"].get_value())
            units_total = info["total_allocation_units"].get_value()
            units_free = info["caller_available_units"].get_value()
            sectors = info["sectors_per_unit"].get_value()
            bps = info["bytes_per_sector"].get_value()
            block = sectors * bps
            return {
                "total_size": units_total * block,
                "free_size": units_free * block,
            }
        finally:
            try:
                dir_open.close()
            except Exception:
                pass

    def open_file(self, path, read=True, write=False):
        return self._with_reconnect(
            lambda: self._open_file(path, read, write))

    @staticmethod
    def _file_access_mask(read, write):
        access = FilePipePrinterAccessMask.DELETE
        if read:
            access |= (FilePipePrinterAccessMask.FILE_READ_DATA
                       | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES)
        if write:
            access |= (FilePipePrinterAccessMask.FILE_WRITE_DATA
                       | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES
                       | FilePipePrinterAccessMask.FILE_APPEND_DATA)
        return access

    def _open_file(self, path, read, write):
        file_open = Open(self._tree, path)
        file_open.create(
            ImpersonationLevel.Impersonation,
            self._file_access_mask(read, write),
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
            | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        return file_open

    def open_and_read(self, path, length, write=False):
        return self._with_reconnect(
            lambda: self._open_and_read(path, length, write))

    def _open_and_read(self, path, length, write):
        # CREATE + READ(head) as one related compound: opening a file and
        # sniffing its header - Explorer's per-file pattern - costs a
        # single round trip instead of two.
        file_open = Open(self._tree, path)
        create_msg, create_recv = file_open.create(
            ImpersonationLevel.Impersonation,
            self._file_access_mask(True, write),
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
            | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
            send=False,
        )
        read_msg, read_recv = file_open.read(0, length, send=False)
        requests = self._connection.send_compound(
            [create_msg, read_msg],
            self._session.session_id, self._tree.tree_connect_id,
            related=True,
        )
        create_exc = read_exc = None
        try:
            create_recv(requests[0])
        except Exception as e:
            create_exc = e
        data = b""
        try:
            data = read_recv(requests[1])
        except SMBResponseException as e:
            # Reading past EOF (empty file) is fine - the open still counts.
            if e.status != STATUS_END_OF_FILE:
                read_exc = e
        except Exception as e:
            read_exc = e
        if create_exc is not None:
            raise create_exc
        if read_exc is not None:
            try:
                file_open.close()
            except Exception:
                pass
            raise read_exc
        return file_open, bytes(data)

    def set_delete_on_close(self, file_open):
        return self._with_reconnect(
            lambda: self._set_delete_on_close(file_open))

    def _set_delete_on_close(self, file_open):
        info = FileDispositionInformation()
        info["delete_pending"] = True
        self._set_info(file_open, info)

    def close_file(self, file_open):
        try:
            file_open.close()
        except Exception as e:
            log.debug("Error closing file: %s", e)

    def flush_file(self, file_open):
        return self._with_reconnect(lambda: file_open.flush())

    def create_file(self, path, is_directory=False):
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
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
        else:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_READ_DATA
                | FilePipePrinterAccessMask.FILE_WRITE_DATA
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
                | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES
                | FilePipePrinterAccessMask.DELETE,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
                | ShareAccess.FILE_SHARE_DELETE,
                CreateDisposition.FILE_CREATE,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
        return file_open

    def delete_file(self, path):
        return self._with_reconnect(lambda: self._delete_file(path))

    def _delete_file(self, path):
        file_open = Open(self._tree, path)
        file_open.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.DELETE,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            # Full share access: this open only sets delete-on-close, and a
            # background close of a read handle may still be in flight.
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
            | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DELETE_ON_CLOSE | CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        file_open.close()

    def delete_directory(self, path):
        return self._with_reconnect(lambda: self._delete_directory(path))

    def _delete_directory(self, path):
        dir_open = Open(self._tree, path)
        dir_open.create(
            ImpersonationLevel.Impersonation,
            DirectoryAccessMask.DELETE,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
            | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DELETE_ON_CLOSE | CreateOptions.FILE_DIRECTORY_FILE,
        )
        dir_open.close()

    def set_end_of_file(self, file_open, size):
        return self._with_reconnect(
            lambda: self._set_end_of_file(file_open, size))

    def _set_end_of_file(self, file_open, size):
        info = FileEndOfFileInformation()
        info["end_of_file"] = size
        self._set_info(file_open, info)

    def rename(self, old_path, new_path, replace_if_exists=False):
        return self._with_reconnect(
            lambda: self._rename(old_path, new_path, replace_if_exists))

    def _rename(self, old_path, new_path, replace_if_exists):
        file_open = Open(self._tree, old_path)
        try:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.DELETE
                | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
                | ShareAccess.FILE_SHARE_DELETE,
                CreateDisposition.FILE_OPEN,
                0,
            )
            info = FileRenameInformation()
            info["replace_if_exists"] = replace_if_exists
            info["file_name"] = new_path
            self._set_info(file_open, info)
        finally:
            try:
                file_open.close()
            except Exception:
                pass

    def _set_info(self, file_open, info):
        req = SMB2SetInfoRequest()
        req["info_type"] = info.INFO_TYPE
        req["file_info_class"] = info.INFO_CLASS
        req["file_id"] = file_open.file_id
        req["buffer"] = info
        request = file_open.connection.send(
            req, file_open.tree_connect.session.session_id,
            file_open.tree_connect.tree_connect_id)
        response = file_open.connection.receive(request)
        resp = SMB2SetInfoResponse()
        resp.unpack(response["data"].get_value())
