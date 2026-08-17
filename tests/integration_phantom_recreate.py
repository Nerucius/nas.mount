"""Live WinFsp/SMB check for stale metadata followed by immediate recreate.

This intentionally mutates only a unique temporary directory on the configured
M: mount.  The file is created/deleted over an independent SMB connection so
the mounted filesystem cannot update its own caches proactively.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nas_mount import build_client, load_config  # noqa: E402


def main() -> int:
    config = load_config(ROOT / "config.toml")
    mapping = config["mounts"]["M"].replace("/", "\\")
    share, _, subpath = mapping.partition("\\")
    test_name = f"_nas_mount_phantom_check_{uuid.uuid4().hex}"
    remote_dir = f"{subpath}\\{test_name}" if subpath else test_name
    remote_file = f"{remote_dir}\\phantom.ldb"
    mounted_dir = Path("M:\\") / test_name
    mounted_file = mounted_dir / "phantom.ldb"
    original = b"before-out-of-band-delete"
    recreated = b"recreated-immediately"

    client = build_client(config, share)
    client.connect()
    try:
        directory_handle = client.create_file(remote_dir, is_directory=True)
        client.close_file(directory_handle)
        file_handle = client.create_file(remote_file)
        try:
            client.write_file(file_handle, original)
        finally:
            client.close_file(file_handle)
        print("PASS: created isolated file through independent SMB connection")

        names = {entry.name for entry in mounted_dir.iterdir()}
        if mounted_file.name not in names or mounted_file.stat().st_size != len(original):
            raise AssertionError("mounted directory did not expose the seeded file")
        print("PASS: primed directory and metadata caches through M:")

        client.delete_file(remote_file)
        print("PASS: deleted file out of band, leaving mounted metadata stale")

        try:
            mounted_file.read_bytes()
        except (FileNotFoundError, OSError):
            pass
        else:
            raise AssertionError("stale mounted read unexpectedly returned file data")
        print("PASS: stale lazy-open failed and invalidation path ran")

        mounted_file.write_bytes(recreated)
        if mounted_file.read_bytes() != recreated:
            raise AssertionError("mounted recreate did not round-trip exact bytes")

        verify_handle = client.open_file(remote_file)
        try:
            actual = client.read_file(verify_handle, 0, len(recreated) + 1)
        finally:
            client.close_file(verify_handle)
        if actual != recreated:
            raise AssertionError("recreated file did not reach the SMB server intact")
        print("PASS: immediate recreate succeeded through M: and verified over SMB")
        return 0
    finally:
        # Every cleanup target contains this run's random UUID.  No broad or
        # recursive deletion is performed.
        try:
            client.delete_file(remote_file)
        except Exception:
            pass
        try:
            client.delete_directory(remote_dir)
        except Exception:
            pass
        client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
