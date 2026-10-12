#!/usr/bin/env bash
# The persistent self-dogfood daemon: start | stop | status | health | cx ARGS...
#
#   SECURITY_DOGFOOD_ROOT  the instance root (default ~/tmp-workspaces/security-dogfood)
#   SECURITY_DOGFOOD_CORE  the cruxible checkout whose .venv runs it
#                          (default ~/tmp-workspaces/kitcore-security)
#
# The daemon runs under nohup with HOME, state root and socket inside the root;
# its log is ROOT/logs/daemon.log. The owner's settings (principal, credentials)
# are loaded from ROOT/home/.config/cruxible/keys/*/*/cruxible.env into the
# environment only; nothing here prints them. `cx` runs the CLI against it.
set -euo pipefail

ROOT="${SECURITY_DOGFOOD_ROOT:-$HOME/tmp-workspaces/security-dogfood}"
CORE="${SECURITY_DOGFOOD_CORE:-$HOME/tmp-workspaces/kitcore-security}"
CRUXIBLE="$CORE/.venv/bin/cruxible"

for name in $(env | grep '^CRUXIBLE_' | cut -d= -f1); do unset "$name"; done
export HOME="$ROOT/home" XDG_CONFIG_HOME="$ROOT/home/.config" XDG_CACHE_HOME="$ROOT/home/.cache"
export CRUXIBLE_STATE_ROOT="$ROOT/state"
export CRUXIBLE_SERVER_SOCKET="$ROOT/run/d.sock"
export CRUXIBLE_ARTIFACT_CACHE="$ROOT/home/.cache/cruxible-artifacts"
export CRUXIBLE_CLIENT_TIMEOUT_S=1200
mkdir -p "$ROOT/home" "$ROOT/state" "$ROOT/ws" "$ROOT/logs" "$ROOT/run"
chmod 700 "$ROOT/run"

settings=$(ls "$ROOT"/home/.config/cruxible/keys/*/*/cruxible.env 2>/dev/null | head -1 || true)
if [ -n "$settings" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$settings"
  set +a
  export CRUXIBLE_STATE_ROOT="$ROOT/state" CRUXIBLE_SERVER_SOCKET="$ROOT/run/d.sock"
fi

running() { "$CRUXIBLE" server status >/dev/null 2>&1; }

case "${1:-}" in
  start)
    if running; then echo "already running: $CRUXIBLE_SERVER_SOCKET"; exit 0; fi
    rm -f "$CRUXIBLE_SERVER_SOCKET"
    (cd "$ROOT" && nohup "$CRUXIBLE" server start --socket "$CRUXIBLE_SERVER_SOCKET" \
      --state-root "$CRUXIBLE_STATE_ROOT" >>"$ROOT/logs/daemon.log" 2>&1 &
     echo $! >"$ROOT/run/daemon.pid")
    for _ in $(seq 1 120); do
      if running; then echo "started: pid $(cat "$ROOT/run/daemon.pid"), $CRUXIBLE_SERVER_SOCKET"; exit 0; fi
      sleep 1
    done
    echo "daemon did not answer; see $ROOT/logs/daemon.log" >&2; exit 1 ;;
  stop)
    if running; then "$CRUXIBLE" server stop | tail -1; else echo "not running"; fi ;;
  status)
    if running; then "$CRUXIBLE" server status; else echo "not running"; exit 1; fi ;;
  health)
    if ! running; then echo "DOWN: not answering on $CRUXIBLE_SERVER_SOCKET"; exit 1; fi
    cd "$ROOT/ws"
    "$CRUXIBLE" orient 2>/dev/null | head -6
    "$CRUXIBLE" next 2>/dev/null | head -20 ;;
  cx)
    shift; cd "$ROOT/ws"; exec "$CRUXIBLE" "$@" ;;
  *)
    echo "usage: $0 start|stop|status|health|cx ARGS..." >&2; exit 2 ;;
esac
