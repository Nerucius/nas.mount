# Endpoint try list (home LAN + away WAN)

## Problem

The servers now share a LAN with the laptop. Direct SMB to the NAS runs at
~103 MB/s raw. The public relay (router port forward → gateway socat → NAS)
works from anywhere, including from home via NAT hairpin, but only reaches
~35 MB/s from home. `[connection]` takes a single `host`/`port`, so the
config has to pick between fast at home and working away.

## Design

`[connection] endpoints = ["<lan-ip>:445", "<public-name>:3445"]`, tried in
order on every connect and reconnect. The first that answers wins.
`host`/`port` still works as a one-element list, so the Windows box's config
keeps working unchanged.

- **Fail fast on the optional ones.** Every endpoint except the last gets
  `min(timeout, 3s)`. smbprotocol uses that timeout for both the TCP connect
  and the NEGOTIATE wait, so away from home the LAN miss costs ~3 s per
  attempt. The last endpoint gets the normal timeout (30 s at startup,
  15 s on reconnect).
- **Check the server before sending credentials.** An optional
  `server_guid` is compared with the NEGOTIATE response's ServerGuid
  before `Session.connect()` sends the NTLM response. That way a stranger's
  box at the same private IP on another network never gets an NTLMv2 hash to
  crack offline. Samba builds this GUID from the NetBIOS name ("truenas"),
  so it is stable across reboots and identical over direct, relay and
  hairpin paths. It is NOT unique: any default-named TrueNAS matches. It
  filters random devices, not a targeted attacker. `--test` prints the GUID
  so it can be pinned.
- **Errors.** With a single endpoint, the original exception propagates
  unchanged. With several, a `ConnectionError` lists each endpoint's
  failure, so `_log_attempt` shows why each one failed.
- `self.host`/`self.port` hold the endpoint in use (UNC path, logs, `--test`).

## Not doing (yet)

- **Upgrading back to the LAN while connected via WAN.** At home this only
  happens if the LAN attempt fails while the hairpin works, and both share
  the same Wi-Fi and router. The one observed startup EHOSTUNREACH did not
  reproduce on restart; it was most likely macOS's first-use Local Network
  check. Swapping a live connection needs idle detection, because open
  handles go stale. Revisit if logs show "via <wan>" while at home.
- Gateway-MAC network detection: platform-specific, and the GUID check
  covers the main risk.

## Changes

- `smb_client.py`: `SMBClient(endpoints=[(host, port), ...], server_guid=None)`.
  `_connect` loops over the endpoints; the per-endpoint body moves to
  `_connect_to`.
- `nas_mount.py`: `parse_endpoints(conn)` (accepts `endpoints` or
  `host`/`port`, default port 445). `build_client` passes `server_guid`.
  `--test` prints the endpoint list, the endpoint used and the GUID.
- `config.example.toml`, README config section, ARCHITECTURE reconnect
  section, CLAUDE.md constraint line (sanitized placeholders only).
- Local `config.toml`: endpoints = LAN IP then public name:3445, plus the
  pinned GUID.

## Verify

1. `--test` with the real config: connects via the LAN and prints the GUID.
2. `--test` with a blackhole first endpoint (`10.255.255.1:445`) + the
   public relay: falls through in ~3 s and connects via the relay.
3. `--test` with a wrong `server_guid`: refuses every endpoint and never
   authenticates.
4. Single `host`/`port` config: behaves as before.
5. Restart the launchd service: the log shows the LAN endpoint in use.
6. User, once, from a phone hotspot: the mount comes up via the relay.
