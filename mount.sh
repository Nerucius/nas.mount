#!/bin/zsh
# nas-mount: macOS auto-mount helper (launchd counterpart of mount.ps1).
# Installs a per-user LaunchAgent that mounts all configured shares at
# login and restarts the mounter if it crashes.
#
#   ./mount.sh install     write + load the LaunchAgent (starts now)
#   ./mount.sh restart     stop the mounter, relaunch it under launchd
#   ./mount.sh stop        clean unmount (stays down until restart/login)
#   ./mount.sh uninstall   unload + remove the LaunchAgent
#   ./mount.sh status      agent state and running process
#
# Everything here leaves the mounter running as a launchd job, never as a
# child of the calling shell - close the terminal and the mounts stay up.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="com.nas-mount"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PYTHON="$SCRIPT_DIR/.venv/bin/python"
LOG="$SCRIPT_DIR/nas-mount.log"
DOMAIN="gui/$(id -u)"

# SIGINT, not SIGTERM: nas_mount only unmounts the volumes and drains
# pending background deletes on KeyboardInterrupt. The [n] trick stops
# pkill from matching the caller's own command line. launchd keeps the job
# down after a clean exit (KeepAlive/SuccessfulExit=false) so nothing races
# us back up; the bootout covers a crash-relaunch inside that window, plus
# any stray manual instance that would collide on the mountpoints.
stop_running() {
    pkill -INT -f '[n]as_mount.py' 2>/dev/null || true
    for _ in {1..15}; do
        pgrep -f '[n]as_mount.py' >/dev/null || break
        sleep 1
    done
    pkill -9 -f '[n]as_mount.py' 2>/dev/null || true
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
}

# RunAtLoad starts the mounter. bootstrap can lose a race with the bootout
# above ("Operation already in progress"), hence the retry; the last try is
# unmuted so a real failure is visible.
load_agent() {
    for _ in {1..10}; do
        launchctl bootstrap "$DOMAIN" "$PLIST" 2>/dev/null && return 0
        sleep 1
    done
    launchctl bootstrap "$DOMAIN" "$PLIST"
}

require_venv() {
    if [ ! -x "$PYTHON" ]; then
        echo "no venv at $PYTHON - run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
        exit 1
    fi
}

log_size() { if [ -f "$LOG" ]; then wc -c < "$LOG" | tr -d ' '; else echo 0; fi; }

# Echo the new run's startup output (from the log offset taken before the
# restart) so the caller sees the mounts come up, then return - the job
# belongs to launchd, so there is nothing left to keep a terminal open for.
show_startup() {
    local off="$1" new=""
    for _ in {1..30}; do
        new="$(tail -c "+$((off + 1))" "$LOG" 2>/dev/null || true)"
        case "$new" in *"mount(s) active"*) break ;; esac
        sleep 1
    done
    if [ -n "$new" ]; then printf '%s\n' "$new"; fi
    echo "--- launchd agent $LABEL owns the mounts now; logs: $LOG ---"
}

case "${1:-}" in
install)
    require_venv
    # Finder shows the mounts under [macos] location; FUSE-T needs the
    # alias to resolve to loopback or it keeps its default 'fuse-t'.
    LOC=$(cd "$SCRIPT_DIR" && "$PYTHON" -c 'import tomllib; print(tomllib.load(open("config.toml","rb")).get("macos",{}).get("location","TrueNAS"))' 2>/dev/null || true)
    if [ -n "$LOC" ] && ! grep -qE "^127\.0\.0\.1[[:space:]]+$LOC\$" /etc/hosts; then
        echo "note: '$LOC' missing from /etc/hosts - Finder will show 'fuse-t' until you run:"
        echo "      echo '127.0.0.1 $LOC' | sudo tee -a /etc/hosts"
    fi
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON</string>
        <string>-u</string>
        <string>src/nas_mount.py</string>
    </array>
    <key>WorkingDirectory</key><string>$SCRIPT_DIR</string>
    <key>RunAtLoad</key><true/>
    <!-- Restart on crash, stay down on clean exit (e.g. user unmount). -->
    <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>StandardOutPath</key><string>$LOG</string>
    <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
    OFF=$(log_size)
    stop_running
    load_agent
    echo "installed: $PLIST"
    show_startup "$OFF"
    ;;
restart)
    if [ ! -f "$PLIST" ]; then
        echo "agent not installed yet - installing it"
        exec "$0" install
    fi
    require_venv
    OFF=$(log_size)
    stop_running
    load_agent
    show_startup "$OFF"
    ;;
stop)
    stop_running
    echo "stopped - stays down until './mount.sh restart' or next login"
    ;;
uninstall)
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "uninstalled"
    ;;
status)
    launchctl print "$DOMAIN/$LABEL" 2>/dev/null | grep -E "state|pid" || echo "agent not loaded"
    pgrep -fl '[n]as_mount.py' || echo "no nas_mount.py process"
    ;;
*)
    echo "usage: $0 install|restart|stop|uninstall|status"
    exit 1
    ;;
esac
