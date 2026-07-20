# Fast directory browsing (metadata path)

## Problem

Explorer takes several seconds to show a folder with a handful of images
(e.g. `M:\StableDiffusion\comfyUI\local\2026-03-19_annie`). Throughput is
already at line rate — browsing is **metadata-bound**: every SMB metadata
operation costs 41 ms WAN round trips, and the current code spends far more
of them than necessary.

RTT accounting today (cold navigation into a folder):

| Operation | RTTs | Why |
|---|---|---|
| `get_security_by_name` (cold path) | 3 | lists the *parent* dir: create+query+close |
| listing the target dir | 3 | create + query_directory + close |
| Explorer probes (`desktop.ini`, `Thumbs.db`, …) | 2 each, every visit | negative lookups fall through the dir cache to `stat_path` = create+close |
| every file open | 1 | SMB CREATE even when Explorer only wants attributes we already have cached |
| kernel metadata cache | — | `file_info_timeout=1000` → Windows re-asks every second |

Latent bug found while auditing: `_list_directory` calls `query_directory`
**once** — directories whose entries exceed one 64 KB page (~500 files) are
silently truncated.

## Changes

1. **`smb_client._list_directory`: compound create+query+close = 1 RTT.**
   Single related compound with a 1 MB query buffer. If the response holds
   ≥ 1600 entries (worst-case entry size 608 B ⇒ 1600 entries can never
   fill 1 MB, so fewer ⇒ guaranteed complete) fall back to the paged loop:
   create + query per page until `NoMoreFiles` + close. Fixes the
   truncation bug in the same stroke.

2. **`smb_client._stat_path`: compound create+close = 1 RTT** (was 2), for
   both hits and misses. smbprotocol pre-sets `Open.file_id` to the
   related-compound sentinel, so `create(send=False)` + `close(send=False)`
   + `send_compound(related=True)` is supported by design.

3. **`fs_core.lookup_or_stat`: a fresh parent listing is authoritative for
   negatives.** Name absent from a cached listing → NOT_FOUND with 0 RTTs
   (kills the desktop.ini/Thumbs.db probe storm). Cache miss → direct
   1-RTT stat; do NOT list the parent anymore (listing a huge parent to
   stat one child was pathological — ComfyUI output dirs have thousands of
   entries).

4. **`fs_core.open_handle`: lazy SMB open.** Cache-hit file opens return a
   handle with `smb_open=None` and remember `want_write`; `_ensure_open()`
   materializes the real SMB CREATE on first read/write/truncate/overwrite
   (under `io_lock`) and refreshes size/allocation from the create
   response. Attribute-only opens — most of what Explorer does — cost 0
   RTTs. `flush`/`close`/`mark_delete` already handle `smb_open is None`.

5. **`file_info_timeout` configurable, default 5000** (was hardcoded
   1000). The kernel absorbs repeated metadata queries for 5 s; our own
   dir cache is 300 s anyway. Surfaced in `[tuning]`.

## Accepted semantics tradeoffs (single-user NAS)

- Lazy open defers open-time errors (vanished file, access denied,
  sharing violation) to the first data operation.
- Negative caching: a file created remotely is invisible on paths with a
  fresh cached listing for up to `dir_cache_ttl` — the same staleness the
  positive cache already has.
- Metadata for cache-hit opens can be `dir_cache_ttl` old (before, every
  open refreshed it from the CREATE response). Consistent with what the
  directory listing itself shows.

## Tests

- Both integration suites (winfspy stub 21 checks, fusepy stub 19 checks)
  against the live share.
- New checks: negative lookup from fresh cache does zero SMB calls; lazy
  open leaves `smb_open=None` until first read; paged listing (forced
  small threshold) matches compound listing; compound stat returns the
  same fields as before.
- Explorer-simulation bench (stat ancestor chain + list + junk probes +
  per-file open/sniff) before vs after, cold and warm, against the real
  folder.
