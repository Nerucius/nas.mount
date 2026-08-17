import ctypes
import struct
import sys
import threading
import unittest
from pathlib import Path

from smbprotocol.exceptions import ObjectNameNotFound


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fs_core import ErrorCode, FsCore, FsError  # noqa: E402
from win_fs import SmbFileSystemOperations  # noqa: E402


def file_entry(name):
    return {
        "file_name": name,
        "file_attributes": 0x80,
        "file_size": 8192,
        "allocation_size": 8192,
        "creation_time": 1,
        "last_access_time": 2,
        "last_write_time": 3,
        "change_time": 4,
    }


class FakeSmb:
    read_size = 4 * 1024 * 1024
    write_size = 4 * 1024 * 1024

    def __init__(self):
        self.created = []
        self.deleted = []
        self.fail_open_and_read = False
        self.writers = []

    def open_and_read(self, path, length, write=False):
        if self.fail_open_and_read:
            raise ObjectNameNotFound()
        raise AssertionError("unexpected successful open_and_read")

    def create_file(self, path, is_directory=False):
        self.created.append((path, is_directory))
        return object()

    def make_writer(self, file_open):
        writer = FakeWriter()
        self.writers.append(writer)
        return writer

    def delete_file(self, path):
        self.deleted.append(path)

    def read_file_pipelined(self, file_open, offset, length):
        return b"b" * length


class FakeWriter:
    def __init__(self):
        self.in_flight = 0
        self.submissions = []
        self.drains = 0

    def submit(self, data, offset):
        self.submissions.append((offset, bytes(data)))

    def drain(self):
        self.drains += 1


class FsCorePathTests(unittest.TestCase):
    def setUp(self):
        self.smb = FakeSmb()
        self.core = FsCore(self.smb, subpath="media")

    def tearDown(self):
        self.core._executor.shutdown(wait=True)

    def seed_swarm_path(self, include_database=True, core=None):
        core = core or self.core
        core._set_cached_dir(
            "media", [file_entry("StableDiffusion")])
        core._set_cached_dir(
            "media\\StableDiffusion", [file_entry("comfyUI")])
        core._set_cached_dir(
            "media\\StableDiffusion\\comfyUI", [file_entry("local")])
        core._set_cached_dir(
            "media\\StableDiffusion\\comfyUI\\local",
            [file_entry("2026-08-04")],
        )
        database_entries = (
            [file_entry("swarm_metadata.ldb")] if include_database else [])
        core._set_cached_dir(
            "media\\StableDiffusion\\comfyUI\\local\\2026-08-04",
            database_entries,
        )

    def test_server_path_restores_case_for_ascii_components(self):
        self.seed_swarm_path()

        wire_path = self.core._server_path(
            "media\\STABLEDIFFUSION\\COMFYUI\\LOCAL\\2026-08-04"
            "\\SWARM_METADATA.LDB"
        )

        self.assertEqual(
            wire_path,
            "media\\StableDiffusion\\comfyUI\\local\\2026-08-04"
            "\\swarm_metadata.ldb",
        )

    def test_mixed_case_delete_uses_server_spelling_and_shared_cache(self):
        self.seed_swarm_path()

        self.core.delete_path(
            "\\STABLEDIFFUSION\\COMFYUI\\LOCAL\\2026-08-04"
            "\\SWARM_METADATA.LDB",
            is_dir=False,
        )
        self.core.drain_deletes()

        self.assertEqual(
            self.smb.deleted,
            [
                "media\\StableDiffusion\\comfyUI\\local\\2026-08-04"
                "\\swarm_metadata.ldb"
            ],
        )
        self.assertIsNone(
            self.core.lookup_cached(
                "\\StableDiffusion\\comfyUI\\local\\2026-08-04"
                "\\swarm_metadata.ldb"
            )
        )

    def test_phantom_lazy_open_can_be_recreated_after_invalidation(self):
        self.seed_swarm_path()
        self.smb.fail_open_and_read = True
        path = (
            "\\StableDiffusion\\comfyUI\\local\\2026-08-04"
            "\\swarm_metadata.ldb"
        )
        handle = self.core.open_handle(path, want_write=True)

        with self.assertLogs("fs_core", level="ERROR"):
            with self.assertRaises(FsError) as raised:
                self.core.read(handle, 0, 8192)

        self.assertEqual(raised.exception.code, ErrorCode.NOT_FOUND)
        self.assertIsNone(self.core.lookup_cached(path.upper()))
        with self.assertRaises(FsError) as reopened:
            self.core.open_handle(path.upper(), want_write=True)
        self.assertEqual(reopened.exception.code, ErrorCode.NOT_FOUND)

        self.core.create_handle(path, is_dir=False)

        self.assertEqual(
            self.smb.created,
            [
                (
                    "media\\StableDiffusion\\comfyUI\\local\\2026-08-04"
                    "\\swarm_metadata.ldb",
                    False,
                )
            ],
        )
        self.assertIsNotNone(self.core.lookup_cached(path.upper()))

    def test_phantom_invokes_platform_cache_notification(self):
        notifications = []
        core = FsCore(
            self.smb, subpath="media", on_phantom=notifications.append)
        self.seed_swarm_path(core=core)
        self.smb.fail_open_and_read = True
        path = (
            "\\StableDiffusion\\comfyUI\\local\\2026-08-04"
            "\\swarm_metadata.ldb"
        )
        handle = core.open_handle(path, want_write=True)

        try:
            with self.assertLogs("fs_core", level="ERROR"):
                with self.assertRaises(FsError):
                    core.read(handle, 0, 8192)
        finally:
            core._executor.shutdown(wait=True)

        self.assertEqual(notifications, [path])

    def test_write_size_is_immediately_visible_to_second_handle(self):
        path = "\\checkpoint\\probe.ldb"
        writer = self.core.create_handle(path, is_dir=False)

        self.core.write(writer, b"x" * 8192, 0)
        reader = self.core.open_handle(path, want_write=False)

        self.assertEqual(writer.file_size, 8192)
        self.assertEqual(reader.file_size, 8192)
        self.assertEqual(self.smb.writers[0].submissions,
                         [(0, b"x" * 8192)])
        self.assertEqual(self.smb.writers[0].drains, 1)

    def test_existing_reader_observes_growth_from_writer_handle(self):
        path = "\\checkpoint\\probe-log.ldb"
        writer = self.core.create_handle(path, is_dir=False)
        self.core.write(writer, b"a" * 32768, 0)
        reader = self.core.open_handle(path, want_write=False)
        self.assertEqual(reader.file_size, 32768)
        reader.smb_open = object()
        reader.ra_windows[0] = b"a" * 32768

        self.core.write(writer, b"b" * 8192, 32768)

        actual = self.core.read(reader, 32768, 8192)

        self.assertEqual(actual, b"b" * 8192)
        self.assertEqual(reader.file_size, 40960)

    def test_sibling_write_invalidates_existing_reader_window(self):
        path = "\\checkpoint\\probe.ldb"
        writer = self.core.create_handle(path, is_dir=False)
        self.core.write(writer, b"a" * 8192, 0)
        reader = self.core.open_handle(path, want_write=False)
        reader.smb_open = object()
        reader.ra_windows[0] = b"a" * 8192
        reader.content_version = writer.content_version

        self.core.write(writer, b"b" * 8192, 0)
        actual = self.core.read(reader, 0, 8192)

        self.assertEqual(actual, b"b" * 8192)
        self.assertEqual(reader.content_version, writer.content_version)

    def test_first_write_is_published_before_sibling_can_read(self):
        path = "\\checkpoint\\concurrent.ldb"
        writer = self.core.create_handle(path, is_dir=False)
        reader = self.core.open_handle(path, want_write=False)
        reader.smb_open = object()
        update_started = threading.Event()
        allow_update = threading.Event()
        read_finished = threading.Event()
        failures = []
        original_update = self.core._cache_update_entry

        def blocked_update(handle):
            update_started.set()
            if not allow_update.wait(timeout=2):
                raise TimeoutError("test did not release cache publication")
            original_update(handle)

        def run_write():
            try:
                self.core.write(writer, b"x" * 8192, 0)
            except Exception as exc:
                failures.append(exc)

        def run_read():
            try:
                self.assertEqual(self.core.read(reader, 0, 8192),
                                 b"b" * 8192)
            except Exception as exc:
                failures.append(exc)
            finally:
                read_finished.set()

        self.core._cache_update_entry = blocked_update
        write_thread = threading.Thread(target=run_write)
        read_thread = threading.Thread(target=run_read)
        write_thread.start()
        self.assertTrue(update_started.wait(timeout=2))
        read_thread.start()
        self.assertFalse(read_finished.wait(timeout=0.1))
        allow_update.set()
        write_thread.join(timeout=2)
        read_thread.join(timeout=2)

        self.assertFalse(write_thread.is_alive())
        self.assertFalse(read_thread.is_alive())
        self.assertEqual(failures, [])


class WinFspNotificationTests(unittest.TestCase):
    def test_removed_notification_is_normalized_and_throttled(self):
        smb = FakeSmb()
        ops = SmbFileSystemOperations(smb)
        calls = []

        def fake_notify(file_system_ptr, notify_info, size):
            raw = ctypes.string_at(notify_info, size)
            calls.append((file_system_ptr.value, raw))
            return 0

        ops._file_system_ptr = 1234
        ops._notify_removed_fn = fake_notify
        path = "\\MixedCase\\swarm_metadata.ldb"

        try:
            ops._notify_removed(path)
            ops._notify_removed(path.upper())
            ops._clear_missing_notification(path)
            ops._notify_removed(path)
        finally:
            ops.core._executor.shutdown(wait=True)

        self.assertEqual(len(calls), 2)
        pointer, raw = calls[0]
        size, change_filter, action = struct.unpack_from("<H2xII", raw)
        self.assertEqual(pointer, 1234)
        self.assertEqual(size, len(raw))
        self.assertEqual(change_filter, 0x00000001)
        self.assertEqual(action, 0x00000002)
        self.assertEqual(raw[12:].decode("utf-16-le"), path.upper())


if __name__ == "__main__":
    unittest.main()
