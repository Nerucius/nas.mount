# Plan: Demolish the bottlenecks (2026-07-20)

## Link budget (theoretical targets)

- local-site: 1000/1000 Mbps FTTH. client-site building: 600 down / 100 up. RTT ~41 ms.
- **Reads (NAS→client)**: capped by client-site uplink = 100 Mbps ≈ **12.0 MB/s** target.
- **Writes (client→NAS)**: capped by client-site downlink = 600 Mbps ≈ **71 MB/s** target.
- BDP: reads need ~512 KB in flight; writes need ~3 MB in flight.

## Infrastructure findings (done live this session)

1. **socat on the gateway** (userspace, niced, 128 KB buffers) split TCP in two legs.
   Replaced with kernel DNAT on the same port 3445 (PREROUTING DNAT → NAS_IP:445,
   MASQUERADE, 2× FORWARD accepts). Backup: `/home/akira/iptables-backup-pre-dnat.rules`.
   Rollback = delete the 4 rules; established socat sessions were never disturbed.
2. **DNAT initially benchmarked 10× slower (1 MB/s)** — root cause was the TrueNAS endpoint,
   previously masked by socat's split TCP:
   - Samba `socket options = TCP_NODELAY IPTOS_LOWDELAY SO_RCVBUF=524288 SO_SNDBUF=524288`
     → fixed 512 KB buffers (autotune disabled) + IPTOS_LOWDELAY DSCP marking on WAN
     (commonly policed by ISPs) → collapsed ~41 KB effective window.
   - FreeBSD caps: maxsockbuf/sendbuf_max/recvbuf_max = 2 MB, sendbuf_inc = 8 KB, newreno.
3. **Fixes applied on TrueNAS (CORE, FreeBSD 13.1)** via midclt + sysctl:
   - Removed `socket options` line from smb_options aux params (default TCP_NODELAY).
   - `kern.ipc.maxsockbuf=16M, sendbuf_max=8M, recvbuf_max=8M, sendbuf_inc=64K, cc=cubic`.
   - TODO: persist as TrueNAS tunables (SYSCTL type + cc_cubic_load LOADER) once benchmarks
     confirm; retire socat and persist iptables rules on the gateway.

## Code changes (this repo)

### smb_client.py
- **Pipelined reads**: `read_file_pipelined(open, offset, length)` — split into read_size
  chunks, send all requests via `send=False` + `Connection.send()`, collect responses.
  Same pattern as writes. Keeps ≥2 requests in flight → no stop-and-go between 4 MB reads.
- **Credit budget**: echo-request more credits at connect (512+); request replenishment on
  every pipelined send (reads and writes).
- **Locking**: keep the single lock (network is the bottleneck), but never hold it across
  the full batch round-trip when avoidable; measure before micro-optimizing further.

### fuse_fs.py
- **Async read-ahead**: per-file prefetch thread/double-buffer. When a read crosses the
  midpoint of the current 4 MB window, kick off the next window in background so
  sequential readers (mpv, Explorer copies) never stall on the network.
- **Async write-behind**: hand full 16 MB buffers to a background flusher (bounded queue,
  depth 2) so the WinFsp write callback returns immediately and the network stays
  continuously busy instead of fill-drain-fill-drain.
- **Correctness fixes**:
  - `read()` must serve/flush overlapping `_wbuf` data (write-then-read consistency).
  - `overwrite()`/`set_file_size()` must discard/flush `_wbuf` coherently.
  - Respect `constrained_io` in `write()` (don't extend file).
  - Flush errors at close should not be silently swallowed (report via cleanup/flush).

### nas_mount.py / config
- New tuning knobs: `read_pipeline_depth`, `write_pipeline_depth`, `readahead_windows`.
- `--bench` gains `--bench-write` mode to measure upload path.

## Benchmark matrix (from the Mac, real WAN) — FINAL

| Path | 4 MB reads | Notes |
|------|-----------|-------|
| socat baseline | 10.6 MB/s | 85 Mbps of ~100 ceiling |
| DNAT, untuned NAS | 1.0 MB/s | collapsed window |
| DNAT, tuned NAS | 1.1 MB/s | NOT the socket options |
| iperf3 via DNAT | reads 10 Mbps / writes 581 Mbps | Samba innocent; FreeBSD WAN sender is the problem |
| iperf3 UDP via DNAT | 80 Mbps, 0% loss | path is clean; TCP dynamics only |
| iperf3 Linux sender (gateway) | 77.5 Mbps, 0 retrans | same path, same minute |
| **Verdict** | | **split TCP at gateway is architecturally right; FreeBSD 13.1 base stack (no RACK) unfixable on CORE** |

## Final results (new code, tuned socat systemd unit)

- Reads pipelined x3: **12.5 MB/s = 100 Mbps = line rate** (was 10.6)
- Writes sliding-window: **57 MB/s (458 Mbps)** raw on 192 MB transfer (was 42-51 through FUSE);
  client CPU 8-11%, depth sweeps flat beyond 4-6 → remaining gap is TCP ramp + server side
- Infra: smb-relay.service (socat, 1 MB blocks, nodelay, no nice), gateway iptables restored
  to pre-experiment state, TrueNAS socket-options removed + buffer sysctls persisted as tunables

## Later / optional
- macOS mount support (FUSE-T/macFUSE adapter around the same core).
- SMB signing off (`require_signing=False`) — CPU + sendfile enablement on NAS; measure.
- Durable handles / reconnect-reopen of stale Opens after network blips.
