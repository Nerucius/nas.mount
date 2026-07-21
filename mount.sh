#!/bin/zsh
# nas-mount: macOS auto-mount helper (launchd counterpart of mount.ps1).
# Installs a per-user LaunchAgent that mounts all configured shares at
# login and restarts the mounter if it crashes.
#
#   ./mount.sh install     write + load the LaunchAgent (starts now)
#   ./mount.sh uninstall   unload + remove the LaunchAgent
#   ./mount.sh status      agent state and running process
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="com.nas-mount"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PYTHON="$SCRIPT_DIR/.venv/bin/python"
LOG="$SCRIPT_DIR/nas-mount.log"

case "${1:-}" in
install)
    [ -x "$PYTHON" ] || { echo "no venv at $PYTHON - run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"; exit 1; }
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
        <string>nas_mount.py</string>
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
    # Reload if already installed; stray manual instances would collide
    # on the mountpoints, so stop those first.
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    pkill -INT -f '[n]as_mount.py' 2>/dev/null || true
    sleep 2
    launchctl bootstrap "gui/$(id -u)" "$PLIST"
    echo "installed: $PLIST (logs: $LOG)"
    ;;
uninstall)
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "uninstalled"
    ;;
status)
    launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -E "state|pid" || echo "agent not loaded"
    pgrep -fl '[n]as_mount.py' || echo "no nas_mount.py process"
    ;;
*)
    echo "usage: $0 install|uninstall|status"
    exit 1
    ;;
esac
