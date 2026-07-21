import sys
import os
import time
import tomllib
import logging
import argparse
import threading

from smb_client import SMBClient

log = logging.getLogger("nas_mount")


def load_config(path="config.toml"):
    with open(path, "rb") as f:
        return tomllib.load(f)


def build_client(config, share_name=None):
    conn = config["connection"]
    tuning = config.get("tuning", {})
    password = conn.get("password") or os.environ.get("NAS_MOUNT_PASSWORD", "")
    if share_name is None:
        share_name = list(config["mounts"].values())[0].split("/")[0]
    return SMBClient(
        host=conn["host"],
        port=conn.get("port", 445),
        username=conn["user"],
        password=password,
        share_name=share_name,
        read_size=tuning.get("read_size", 4 * 1024 * 1024),
        write_size=tuning.get("write_size", 4 * 1024 * 1024),
        read_pipeline_depth=tuning.get("read_pipeline_depth", 3),
        write_pipeline_depth=tuning.get("write_pipeline_depth", 4),
        reconnect_delay=tuning.get("reconnect_delay", 5),
        max_reconnect_attempts=tuning.get("max_reconnect_attempts", 10),
    )


def format_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_speed(bytes_per_sec):
    mb = bytes_per_sec / (1024 * 1024)
    mbps = bytes_per_sec * 8 / (1024 * 1024)
    return f"{mb:.1f} MB/s ({mbps:.0f} Mbps)"


def find_test_file(client, subpath, min_size=10 * 1024 * 1024):
    log.info("Looking for a test file >= %s in '%s'...", format_size(min_size), subpath)
    entries = client.list_directory(subpath)
    for entry in entries:
        name = entry["file_name"]
        if name in (".", ".."):
            continue
        attrs = entry["file_attributes"]
        is_dir = attrs & 0x10
        size = entry["end_of_file"]
        if not is_dir and size >= min_size:
            path = f"{subpath}\\{name}" if subpath else name
            return path, size
    for entry in entries:
        name = entry["file_name"]
        if name in (".", ".."):
            continue
        attrs = entry["file_attributes"]
        if attrs & 0x10:
            subdir = f"{subpath}\\{name}" if subpath else name
            try:
                result = find_test_file(client, subdir, min_size)
                if result:
                    return result
            except Exception:
                continue
    return None


def run_speed_test(client, file_path, file_size, read_sizes=None, test_bytes=None):
    if read_sizes is None:
        read_sizes = [64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024]
    if test_bytes is None:
        test_bytes = min(file_size, 32 * 1024 * 1024)

    print(f"\n  File: {file_path}")
    print(f"  Size: {format_size(file_size)}")
    print(f"  Reading {format_size(test_bytes)} per read-size test\n")
    print(f"  {'Read Size':>12}  {'Speed':>22}  {'Time':>8}  {'Reads':>6}")
    print(f"  {'-'*12}  {'-'*22}  {'-'*8}  {'-'*6}")

    results = []
    for read_size in read_sizes:
        file_open = client.open_file(file_path, read=True)
        try:
            offset = 0
            total_read = 0
            num_reads = 0
            start = time.perf_counter()
            while total_read < test_bytes:
                chunk = min(read_size, test_bytes - total_read)
                data = client.read_file(file_open, offset, chunk)
                got = len(data)
                if got == 0:
                    break
                total_read += got
                offset += got
                num_reads += 1
            elapsed = time.perf_counter() - start
        finally:
            client.close_file(file_open)

        if elapsed > 0:
            speed = total_read / elapsed
        else:
            speed = 0
        results.append((read_size, speed, elapsed, num_reads))
        label = format_size(read_size).rjust(12)
        print(f"  {label}  {format_speed(speed):>22}  {elapsed:>7.1f}s  {num_reads:>6}")

    # Pipelined read: single sliding-window stream, the path the mount uses.
    file_open = client.open_file(file_path, read=True)
    try:
        start = time.perf_counter()
        data = client.read_file_pipelined(file_open, 0, test_bytes)
        elapsed = time.perf_counter() - start
    finally:
        client.close_file(file_open)
    speed = len(data) / elapsed if elapsed > 0 else 0
    results.append(("pipelined", speed, elapsed, -1))
    label = f"pipelined x{client.read_pipeline_depth}".rjust(12)
    print(f"  {label}  {format_speed(speed):>22}  {elapsed:>7.1f}s  {'-':>6}")

    if len(results) >= 2:
        base_speed = results[0][1]
        best_speed = max(r[1] for r in results)
        if base_speed > 0:
            print(f"\n  Speedup vs 64KB: {best_speed / base_speed:.1f}x")
    return results


def run_write_test(client, subpath, size_mb=64):
    import os as _os
    test_name = ".nas-mount-write-bench.tmp"
    test_path = f"{subpath}\\{test_name}" if subpath else test_name
    total = size_mb * 1024 * 1024
    payload = _os.urandom(4 * 1024 * 1024)

    print(f"\n  Write benchmark: {test_path} ({size_mb} MB, pipelined x{client.write_pipeline_depth})")
    file_open = client.create_file(test_path)
    try:
        writer = client.make_writer(file_open)
        written = 0
        start = time.perf_counter()
        while written < total:
            n = min(len(payload), total - written)
            writer.submit(payload[:n], written)
            written += n
        writer.drain()
        elapsed = time.perf_counter() - start
        speed = written / elapsed if elapsed > 0 else 0
        print(f"  Wrote {format_size(written)} in {elapsed:.1f}s = {format_speed(speed)}")
    finally:
        client.close_file(file_open)
        try:
            client.delete_file(test_path)
            print("  Test file deleted.")
        except Exception as e:
            print(f"  WARNING: could not delete test file: {e}")


def run_test(config):
    client = build_client(config)

    print("=" * 60)
    print("  nas-mount SMB Connection Test")
    print("=" * 60)

    conn = config["connection"]
    print(f"\n  Host:  {conn['host']}:{conn.get('port', 445)}")
    print(f"  User:  {conn['user']}")
    print(f"  Share: {client.share_name}")

    print("\n  [1/4] Connecting...", end=" ", flush=True)
    t0 = time.perf_counter()
    client.connect()
    t_connect = time.perf_counter() - t0
    print(f"OK ({t_connect:.1f}s)")
    print(f"        Dialect: SMB {client._connection.dialect:#06x}")
    print(f"        Max read: {format_size(client._connection.max_read_size)}")
    print(f"        Max write: {format_size(client._connection.max_write_size)}")

    mounts = config.get("mounts", {})
    subpaths = {}
    for drive, share_path in mounts.items():
        parts = share_path.split("/", 1)
        subpaths[drive] = parts[1] if len(parts) > 1 else ""

    print(f"\n  [2/4] Listing configured mount paths...")
    for drive, subpath in subpaths.items():
        try:
            entries = client.list_directory(subpath)
            real_entries = [e for e in entries if e["file_name"] not in (".", "..")]
            dirs = sum(1 for e in real_entries if e["file_attributes"] & 0x10)
            files = len(real_entries) - dirs
            total_size = sum(e["end_of_file"] for e in real_entries
                            if not (e["file_attributes"] & 0x10))
            print(f"        {drive}: /{subpath} -> {dirs} dirs, {files} files"
                  f" ({format_size(total_size)})")
        except Exception as e:
            print(f"        {drive}: /{subpath} -> ERROR: {e}")

    print(f"\n  [3/4] Checking file attributes...")
    first_subpath = list(subpaths.values())[0]
    entries = client.list_directory(first_subpath)
    sample_file = None
    for entry in entries:
        if entry["file_name"] not in (".", "..") and not (entry["file_attributes"] & 0x10):
            sample_file = entry
            break
    if sample_file:
        fname = sample_file["file_name"]
        fpath = f"{first_subpath}\\{fname}" if first_subpath else fname
        stat = client.stat_path(fpath)
        print(f"        File: {fname}")
        print(f"        Size: {format_size(stat['end_of_file'])}")
        print(f"        Modified: {stat['last_write_time']}")
    else:
        print("        No files found in root for stat test")

    print(f"\n  [4/4] Speed benchmark...")
    test_file = None
    for subpath in subpaths.values():
        result = find_test_file(client, subpath)
        if result:
            test_file = result
            break
    if test_file:
        file_path, file_size = test_file
        run_speed_test(client, file_path, file_size)
    else:
        print("        No file >= 10 MB found for speed test")
        print("        Skipping benchmark")

    client.disconnect()
    print(f"\n{'=' * 60}")
    print("  Test complete.")
    print(f"{'=' * 60}")


def parse_mount_config(config):
    mounts = config.get("mounts", {})
    labels = config.get("labels", {})
    share_names = set()
    result = []
    for drive, share_path in mounts.items():
        parts = share_path.split("/", 1)
        share_name = parts[0]
        subpath = parts[1] if len(parts) > 1 else ""
        share_names.add(share_name)
        label = labels.get(drive, subpath.capitalize() if subpath else share_name)
        result.append({"drive": drive, "share_name": share_name,
                        "subpath": subpath, "label": label})
    if len(share_names) > 1:
        log.warning("Multiple share names detected: %s. Each unique share needs "
                    "its own SMB connection.", share_names)
    return result


def run_mount(config, debug=False):
    if sys.platform == "darwin":
        run_mount_macos(config, debug=debug)
        return
    from winfspy import FileSystem
    from fuse_fs import SmbFileSystemOperations

    tuning = config.get("tuning", {})
    mount_configs = parse_mount_config(config)

    clients_by_share = {}
    filesystems = []

    print("=" * 60)
    print("  nas-mount")
    print("=" * 60)

    try:
        for mc in mount_configs:
            drive = mc["drive"]
            share_name = mc["share_name"]
            subpath = mc["subpath"]
            label = f"{drive}: -> {share_name}/{subpath}" if subpath else f"{drive}: -> {share_name}"

            if share_name not in clients_by_share:
                client = build_client(config, share_name=share_name)
                print(f"\n  Connecting to share '{share_name}'...", end=" ", flush=True)
                client.connect()
                print("OK")
                clients_by_share[share_name] = client
            else:
                client = clients_by_share[share_name]

            ops = SmbFileSystemOperations(
                smb_client=client,
                subpath=subpath,
                dir_cache_ttl=tuning.get("dir_cache_ttl", 300),
                readahead_windows=tuning.get("readahead_windows", 2),
                readahead_workers=tuning.get("readahead_workers", 8),
                write_buffer_chunks=tuning.get("write_buffer_chunks", 3),
                volume_label=mc["label"],
            )

            mountpoint = f"{drive}:"
            fs = FileSystem(
                mountpoint,
                ops,
                sector_size=4096,
                sectors_per_allocation_unit=1,
                volume_creation_time=0,
                volume_serial_number=0,
                file_info_timeout=tuning.get("file_info_timeout", 5000),
                # Enumerations must not ride the long file-info cache, or
                # renames/deletes look unapplied on refresh for seconds.
                dir_info_timeout_valid=1,
                dir_info_timeout=tuning.get("dir_info_timeout", 1000),
                case_sensitive_search=0,
                case_preserved_names=1,
                unicode_on_disk=1,
                persistent_acls=0,
                read_only_volume=0,
                post_cleanup_when_modified_only=1,
                um_file_context_is_user_context2=1,
                file_system_name="nas-mount",
                debug=debug,
            )

            print(f"  Mounting {label}...", end=" ", flush=True)
            fs.start()
            print("OK")
            filesystems.append((mountpoint, fs, ops))

        print(f"\n  {len(filesystems)} mount(s) active. Press Ctrl+C to stop.")
        print("=" * 60)

        stop_event = threading.Event()
        try:
            stop_event.wait()
        except KeyboardInterrupt:
            print("\n\n  Shutting down...")

    finally:
        for mountpoint, fs, ops in filesystems:
            try:
                print(f"  Unmounting {mountpoint}...", end=" ", flush=True)
                fs.stop()
                ops.core.drain_deletes()
                print("OK")
            except Exception as e:
                print(f"FAILED ({e})")
        for client in clients_by_share.values():
            try:
                client.disconnect()
            except Exception:
                pass
        print("  Done.")


def run_mount_macos(config, debug=False):
    import subprocess
    from macos_fs import SmbMacOperations, mount_macos

    tuning = config.get("tuning", {})
    macos_cfg = config.get("macos", {})
    mount_root = os.path.expanduser(macos_cfg.get("mount_root", "~/nas"))
    overrides = macos_cfg.get("mounts", {})
    mount_configs = parse_mount_config(config)

    clients_by_share = {}
    mounted = []  # (mountpoint, thread)
    mounted_ops = []

    # Server name Finder groups the mounts under (default would be
    # "fuse-t"). FUSE-T requires the alias to resolve to 127.0.0.1; if it
    # doesn't, keep FUSE-T's default rather than degrade to "localhost".
    location = macos_cfg.get("location", "TrueNAS")
    if location:
        import socket
        try:
            resolved = socket.gethostbyname(location)
        except OSError:
            resolved = None
        if resolved != "127.0.0.1":
            print(f"  NOTE: '{location}' does not resolve to 127.0.0.1; "
                  f"mounts will show as 'fuse-t' in Finder.")
            print(f"        Fix once with: echo '127.0.0.1 {location}' "
                  f"| sudo tee -a /etc/hosts")
            location = None

    print("=" * 60)
    print("  nas-mount (macOS)")
    print("=" * 60)

    try:
        for mc in mount_configs:
            drive = mc["drive"]
            share_name = mc["share_name"]
            subpath = mc["subpath"]

            if share_name not in clients_by_share:
                client = build_client(config, share_name=share_name)
                print(f"\n  Connecting to share '{share_name}'...", end=" ", flush=True)
                client.connect()
                print("OK")
                clients_by_share[share_name] = client
            else:
                client = clients_by_share[share_name]

            ops = SmbMacOperations(
                smb_client=client,
                subpath=subpath,
                dir_cache_ttl=tuning.get("dir_cache_ttl", 300),
                readahead_windows=tuning.get("readahead_windows", 2),
                readahead_workers=tuning.get("readahead_workers", 8),
                write_buffer_chunks=tuning.get("write_buffer_chunks", 3),
                volume_label=mc["label"],
            )

            basename = (subpath.split("/")[-1] if subpath else share_name).lower()
            mountpoint = os.path.expanduser(
                overrides.get(drive, os.path.join(mount_root, basename)))

            label = f"{mountpoint} -> {share_name}/{subpath}" if subpath \
                else f"{mountpoint} -> {share_name}"
            print(f"  Mounting {label}...", flush=True)
            t = threading.Thread(
                target=mount_macos,
                args=(ops, mountpoint, mc["label"]),
                kwargs={
                    "debug": debug,
                    "rwsize": macos_cfg.get("rwsize", 1048576),
                    "daemon_timeout": macos_cfg.get("daemon_timeout", 600),
                    "location": location,
                },
                name=f"fuse-{drive}",
                daemon=True,
            )
            t.start()
            mounted.append((mountpoint, t))
            mounted_ops.append(ops)

        print(f"\n  {len(mounted)} mount(s) active. Press Ctrl+C to stop.")
        print("=" * 60)

        # FUSE threads block until their volume is unmounted. Converge on
        # shutdown whether we get KeyboardInterrupt here or libfuse's own
        # signal handler unmounts one of the volumes.
        try:
            while all(t.is_alive() for _, t in mounted):
                time.sleep(1)
            print("\n  A mount exited; shutting down the rest...")
        except KeyboardInterrupt:
            print("\n\n  Shutting down...")

    finally:
        for mountpoint, t in mounted:
            if t.is_alive():
                print(f"  Unmounting {mountpoint}...", end=" ", flush=True)
                r = subprocess.run(["umount", mountpoint],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    subprocess.run(["diskutil", "unmount", "force", mountpoint],
                                   capture_output=True, text=True)
                t.join(timeout=10)
                print("OK" if not t.is_alive() else "STUCK")
        for ops in mounted_ops:
            try:
                ops.core.drain_deletes()
            except Exception:
                pass
        for client in clients_by_share.values():
            try:
                client.disconnect()
            except Exception:
                pass
        print("  Done.")


def main():
    parser = argparse.ArgumentParser(
        description="Mount TrueNAS SMB shares as Windows drive letters")
    parser.add_argument("--config", default="config.toml",
                        help="Path to config file (default: config.toml)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--test", action="store_true",
                        help="Test SMB connection and benchmark speed (no mount)")
    parser.add_argument("--bench", metavar="PATH",
                        help="Benchmark a specific file path (relative to share root)")
    parser.add_argument("--bench-write", action="store_true",
                        help="Benchmark upload speed with a temporary file")
    parser.add_argument("--bench-size", type=int, default=32,
                        help="MB to read/write per test (default: 32)")
    parser.add_argument("--drive", metavar="LETTER",
                        help="Mount only this drive letter (default: all)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.debug:
        logging.getLogger("smbprotocol").setLevel(logging.WARNING)

    config = load_config(args.config)

    if args.test:
        run_test(config)
        return

    if args.bench:
        client = build_client(config)
        client.connect()
        stat = client.stat_path(args.bench)
        run_speed_test(client, args.bench, stat["end_of_file"],
                       test_bytes=args.bench_size * 1024 * 1024)
        client.disconnect()
        return

    if args.bench_write:
        client = build_client(config)
        client.connect()
        first_subpath = list(config["mounts"].values())[0].split("/", 1)
        subpath = first_subpath[1] if len(first_subpath) > 1 else ""
        run_write_test(client, subpath.replace("/", "\\"),
                       size_mb=args.bench_size)
        client.disconnect()
        return

    if args.drive:
        config["mounts"] = {args.drive: config["mounts"][args.drive]}

    run_mount(config, debug=args.debug)


if __name__ == "__main__":
    main()
