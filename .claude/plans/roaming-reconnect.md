# Roaming-friendly reconnect

## Incident (2026-08-12, laptop moved to a different network)

Network transition at 12:48 killed the socket (`OSError 49`). All 10 reconnect
attempts failed with DNS `Errno 8` (no resolver yet mid-transition); the laptop
slept between attempts 9 and 10, burning the last retry ~51 min later while
still offline. The client then gave up permanently, leaving `_session = None`.
Every subsequent FUSE callback raised `AttributeError: 'NoneType' object has no
attribute 'session'` → EIO → "all folders empty" + 36k identical log lines.
Process stayed alive, so launchd `KeepAlive` never restarted it.

## Root problems

1. **Finite retry budget** — `max_reconnect_attempts=10`, then permanent wedge
   (`smb_client.py` `_reconnect`). A roaming laptop must retry forever.
2. **Reconnect blocks the world** — `_reconnect()` sleeps holding
   `_state_lock`; every FUSE op queues behind it for the whole sequence
   (up to ~5 min). Finder beachballs instead of erroring fast.
3. **Sleep burns the budget** — backoff waits run on wall clock across laptop
   sleep; zero real attempts happen on the network that exists at wake.
4. **No clean "down" state** — after giving up, ops hit `None` internals
   (AttributeError) instead of a deliberate disconnected error; log floods.
5. **Startup requires network** — `nas_mount.py` calls `client.connect()`
   once; at login without Wi-Fi the process exits and launchd crash-loops
   every `ThrottleInterval=10s`.
6. **Slow recovery tail** — even with retries fixed, a 60s backoff means up to
   60s of dead mounts after landing on working Wi-Fi, with no way for user
   activity to hurry it up.

## Design

One state machine in `SMBClient`: **CONNECTED ⇄ DOWN**, with a single
background reconnector thread. FUSE ops never wait on reconnection.

### smb_client.py

- **State + fail-fast.** Add `self._down = threading.Event()` (or state enum)
  and `self._shutdown`. Every `_with_reconnect` op checks DOWN first and
  raises `SMBConnectionClosed("not connected")` immediately — no
  AttributeError path, no lock wait. `connected` property reflects the state.
- **Detection unchanged, handoff new.** `_with_reconnect` keeps the
  single-flight echo health check (cheap, catches stale-handle false alarms).
  When the echo fails: mark DOWN, `_disconnect()`, **start/nudge the
  reconnector thread, and raise** — never reconnect inline.
- **Reconnector thread** (daemon, one per client, started lazily on first
  drop):
  - Infinite loop: attempt `_connect()`; on success swap
    connection/session/tree under `_state_lock`, clear DOWN, log one INFO.
  - On failure: backoff `reconnect_delay` (5s) doubling to
    `reconnect_max_delay` (60s), waiting on a nudge `Event` instead of
    `time.sleep` so it's interruptible.
  - **Wake detection:** measure wall-clock around the wait; if
    `elapsed > requested + 30s`, the machine slept → reset backoff to the
    initial delay and retry immediately (network almost certainly changed).
  - **Nudge:** ops that fail-fast while DOWN set the nudge event, but only if
    the last attempt is ≥ `reconnect_delay` old (rate-gate so Finder can't
    hammer). A nudged failure does *not* reset backoff growth.
  - Loop body wrapped in blanket try/except so the thread cannot die; if the
    loop somehow exits while not shutting down, log CRITICAL and
    `os._exit(70)` so launchd `KeepAlive` restarts a clean process — a wedged
    mounter must never outlive its usefulness again.
- **Retry-forever initial connect.** `connect(wait_forever=False)` gains a
  flag: same backoff/wake logic, used by the mount path so login-without-WiFi
  waits quietly instead of crash-looping. `--test`/`--bench` keep
  fail-immediately behavior.
- **Shutdown:** `disconnect()` sets `_shutdown`, nudges the thread, joins
  briefly. Mount teardown in `nas_mount.py` already calls it.
- **Log hygiene:** transition to DOWN = one WARNING. Attempts: first at
  WARNING, then one INFO per 10 attempts, rest DEBUG. DNS `Errno 8` is
  expected mid-roam — never above INFO after the first. Reconnect success =
  one INFO with total downtime.

### fs_core.py

- `map_smb_error`: rate-limit the `SMBConnectionClosed` ERROR line (at most
  one per ~30s, with a suppressed-count when it next fires). While DOWN,
  thousands of EIO-mapped ops must not produce thousands of lines.

### nas_mount.py

- Mount paths (mac + Windows) call `client.connect(wait_forever=True)`.
- Read `reconnect_max_delay` from `[tuning]` (default 60).
- `max_reconnect_attempts` is retired: ignored if present, one startup INFO
  noting it's obsolete. (Attempts are now unbounded by design.)

### Config / docs

- `config.example.toml`: add `reconnect_max_delay = 60`, drop
  `max_reconnect_attempts`.
- CLAUDE.md "Key constraints" + ARCHITECTURE.md reconnect paragraph updated to
  describe the background reconnector.

## Non-goals

- Transparent re-open of stale file handles after reconnect (apps reopen;
  path-based ops recover on next call). Same behavior as today.
- macOS network-change notifications (SystemConfiguration) — the nudge +
  wake-reset approximates it without a new dependency.
- Log rotation for `nas-mount.log` (rate-limiting removes ~99% of the
  volume; revisit only if the log still grows).

## Semantics after the change

| Situation | Before | After |
|---|---|---|
| Network blip (seconds) | ops block up to first retry, then OK | first op errors, reconnector restores within ~5s |
| Network gone (minutes+) | ops hang ~5 min, then wedged forever | ops fail fast EIO; reconnects ≤60s after network returns, sooner with user activity |
| Laptop sleeps, wakes elsewhere | retry budget burned, wedged | wake detected → immediate fresh attempt |
| Login without Wi-Fi | crash-loop via launchd every 10s | waits quietly, mounts when network appears |
| Reconnector itself crashes | n/a (didn't exist) | process exits(70) → launchd restarts |

## Test plan (manual, on this Mac)

1. Mount; `ls` works. Toggle Wi-Fi off: one WARNING in log, `ls` returns
   I/O error in <1s (no hang). Log stays quiet (rate-limited).
2. Wi-Fi back on: reconnect within backoff; `ls` from Finder immediately
   after network-up triggers nudge → recovery in seconds. One INFO line.
3. Close lid 5+ min with Wi-Fi off, wake: log shows backoff reset + prompt
   reconnect.
4. `./mount.sh uninstall` / re-install: clean shutdown, no thread leak
   (`ps` shows no orphan python).
5. Playback test: start mpv on a movie, drop network 30s, restore — stream
   resumes (read path re-issues after reconnect; handle may need reopen —
   observe and note actual behavior).
6. Windows: not testable from this machine — `smb_client.py` is shared, so
   run the same Wi-Fi toggle test on the Windows box before calling this
   done ("fail fast and let the caller retry" comment in `_with_reconnect`
   is exactly the WinFsp contract, which the new design preserves).

## Files touched

- `src/smb_client.py` — state machine, reconnector thread, fail-fast ops,
  wait-forever connect, log tiers (~120 lines net)
- `src/fs_core.py` — rate-limited disconnect logging (~15 lines)
- `src/nas_mount.py` — wait-forever at mount, config plumbing (~10 lines)
- `config.example.toml`, `CLAUDE.md`, `ARCHITECTURE.md` — docs
