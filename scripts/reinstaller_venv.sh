#!/usr/bin/env bash
# Reinstall the production venv from the hash lock (requirements.lock), keep the old one, probe, roll back on failure.
# Run on the host as the service owner:  scripts/reinstaller_venv.sh
# Old venv kept as .venv.ancien-<timestamp> (delete it after a week of clean running).
set -euo pipefail
REPO_DIR="${REPO_DIR:-/opt/claude-ceo/workspace/mcp-servers/eu-ai-act}"
SERVICES=(mcp-eu-ai-act arkforge-euaiact-api)
PORTS=(8090 8200)
LOCK="requirements.lock"
cd "$REPO_DIR"
git pull --ff-only   # the lock must be the one on main
[ -f "$LOCK" ] || { echo "no $LOCK in $REPO_DIR" >&2; exit 1; }
ts=$(date -u +%Y%m%dT%H%M%SZ)

relancer() { for s in "${SERVICES[@]}"; do sudo -n /usr/local/sbin/arkforge-run relance "$s"; done; }
sonder() {
  for p in "${PORTS[@]}"; do
    for _ in $(seq 12); do
      c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$p/" || true)
      [ "$c" != 000 ] && continue 2
      sleep 5
    done
    echo "port $p does not answer" >&2; return 1
  done
}
retour() {
  echo "rolling back to .venv.ancien-$ts" >&2
  rm -rf .venv && mv ".venv.ancien-$ts" .venv && relancer
}

# The running services keep the old files open until the restart.
mv .venv ".venv.ancien-$ts"
if ! { python3 -m venv .venv && .venv/bin/pip install -q --disable-pip-version-check --require-hashes -r "$LOCK"; }; then
  echo "install from $LOCK failed" >&2; retour; exit 1
fi
relancer
if ! sonder; then retour; exit 1; fi
echo "OK: venv reinstalled from $LOCK; old venv kept in .venv.ancien-$ts"
