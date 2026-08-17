"""Live exact-page read verification through the mounted filesystem."""

from __future__ import annotations

import hashlib
import random
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nas_mount import build_client, load_config  # noqa: E402


PAGE_SIZE = 8192
PAGE_COUNT = 1024  # 8 MiB: crosses two configured 4 MiB read windows.


def _page(index: int) -> bytes:
    seed = hashlib.sha256(f"nas-mount-page-{index}".encode()).digest()
    unit = index.to_bytes(8, "little") + seed
    return (unit * ((PAGE_SIZE + len(unit) - 1) // len(unit)))[:PAGE_SIZE]


def main() -> int:
    config = load_config(ROOT / "config.toml")
    mapping = config["mounts"]["M"].replace("/", "\\")
    share, _, subpath = mapping.partition("\\")
    test_name = f"_nas_mount_page_check_{uuid.uuid4().hex}"
    remote_dir = f"{subpath}\\{test_name}" if subpath else test_name
    remote_file = f"{remote_dir}\\pages.ldb"
    mounted_file = Path("M:\\") / test_name / "pages.ldb"
    expected = b"".join(_page(i) for i in range(PAGE_COUNT))

    client = build_client(config, share)
    client.connect()
    try:
        directory_handle = client.create_file(remote_dir, is_directory=True)
        client.close_file(directory_handle)
        file_handle = client.create_file(remote_file)
        try:
            client.write_file(file_handle, expected)
        finally:
            client.close_file(file_handle)
        print("PASS: seeded an 8 MiB page-aligned file over independent SMB")

        order = list(range(PAGE_COUNT))
        random.Random(0x5A17).shuffle(order)
        with mounted_file.open("rb", buffering=0) as stream:
            for index in order:
                stream.seek(index * PAGE_SIZE)
                actual = stream.read(PAGE_SIZE)
                if len(actual) != PAGE_SIZE:
                    raise AssertionError(
                        f"page {index}: short read {len(actual)}/{PAGE_SIZE}")
                if actual != _page(index):
                    raise AssertionError(f"page {index}: content mismatch")
        print("PASS: 1,024 randomized exact 8 KiB reads returned complete pages")
        return 0
    finally:
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
