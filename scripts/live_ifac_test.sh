#!/usr/bin/env bash
# live_ifac_test.sh — end-to-end test for the §2.1 IFAC bit-7 patch.
#
# Spins up:
#   1. A Python TCP "rnsd-like" emitter that ships one IFAC-sealed HDLC
#      frame at the moment the forwarding service connects (using the
#      verbatim upstream RNS/Transport.py:993-1024 sealing path).
#   2. The forwarding service (`go run ./cmd/fwdsvc`) configured with one
#      tcp_client interface pointed at the emitter.
#
# Then greps the service log for:
#
#   parse packet: IFAC-sealed packet rejected (ifac_flag=1, SPEC §2.1)
#
# PASS if the line is found within the wait window; FAIL otherwise (with
# both logs dumped). Exit status 0 on PASS, 1 on FAIL.
#
# Usage:  bash scripts/live_ifac_test.sh
#
# Works on macOS, Linux, and Git Bash on Windows. Requires:
#   * `python` resolving to a Python with RNS 1.2.0 installed
#   * `go` on PATH

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="${TMPDIR:-/tmp}/fwdsvc-ifac-test-$$"
mkdir -p "$TMP_DIR"

# Pick a high port unlikely to collide. Override with $PORT.
PORT="${PORT:-47123}"

LOG_FWD="$TMP_DIR/fwdsvc.log"
LOG_EMIT="$TMP_DIR/emitter.log"
CONFIG_FILE="$TMP_DIR/config.toml"

PY_PID=""
GO_PID=""

cleanup() {
    set +e
    if [[ -n "$GO_PID" ]]; then
        kill "$GO_PID" 2>/dev/null
        wait "$GO_PID" 2>/dev/null
    fi
    if [[ -n "$PY_PID" ]]; then
        kill "$PY_PID" 2>/dev/null
        wait "$PY_PID" 2>/dev/null
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

cat >"$CONFIG_FILE" <<EOF
[service]
display_name      = "ifac-live-test"
identity_path     = "$TMP_DIR/identity"
state_path        = "$TMP_DIR/state.json"
history_path      = "$TMP_DIR/history.json"
prune_after       = "4w"
prune_interval    = "1h"
announce_interval = "1h"
max_inbound_chars = 500

[[interfaces]]
type = "tcp_client"
addr = "127.0.0.1:$PORT"
timeout = "5s"

[replay]
count   = 0
max_age = "1d"
EOF

echo "=== launching IFAC TCP emitter on 127.0.0.1:$PORT ==="
python "$REPO_ROOT/scripts/gen_ifac_packet.py" --serve "$PORT" \
    >"$LOG_EMIT" 2>&1 &
PY_PID=$!

# Give the emitter time to bind. Poll the log for the "listening" marker
# rather than sleeping a flat amount.
for i in $(seq 1 30); do
    if grep -q "listening on 127.0.0.1:$PORT" "$LOG_EMIT" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! grep -q "listening on 127.0.0.1:$PORT" "$LOG_EMIT" 2>/dev/null; then
    echo "=== FAIL: emitter did not bind ==="
    echo "--- emitter log: ---"
    cat "$LOG_EMIT" 2>/dev/null || true
    exit 1
fi

echo "=== launching fwdsvc against the emitter ==="
( cd "$REPO_ROOT" && go run ./cmd/fwdsvc -config "$CONFIG_FILE" ) \
    >"$LOG_FWD" 2>&1 &
GO_PID=$!

# Wait up to ~10s for the rejection to appear.
FOUND=0
for i in $(seq 1 100); do
    if grep -q "IFAC-sealed packet rejected" "$LOG_FWD" 2>/dev/null; then
        FOUND=1
        break
    fi
    sleep 0.1
done

if [[ "$FOUND" -eq 1 ]]; then
    echo "=== PASS: service logged IFAC rejection ==="
    grep -n "IFAC-sealed packet rejected\|interface tcp_client" "$LOG_FWD" || true
    exit 0
fi

echo "=== FAIL: rejection line not found in service log ==="
echo "--- service log: ---"
cat "$LOG_FWD" 2>/dev/null || true
echo "--- emitter log: ---"
cat "$LOG_EMIT" 2>/dev/null || true
exit 1
