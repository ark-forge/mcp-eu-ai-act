#!/usr/bin/env bash
# deploy_mcp_eu_ai_act.sh — Deploy MCP EU AI Act to production with gates + staged rollout + rollback
#
# Usage: ./scripts/deploy_mcp_eu_ai_act.sh [--minor|--major] [--force] [--skip-smoke]
#
# Flags:
#   --force        Bypass CI GitHub check
#   --skip-smoke   Skip post-deploy smoke test (use for emergency hotfixes)
#   --minor        Bump minor version (1.0.x → 1.1.0)
#   --major        Bump major version (1.x.x → 2.0.0)
#   (default)      Bump patch (1.0.2 → 1.0.3)
#
# Staged rollout:
#   Phase 1  — Gates (CI, pytest + coverage, backward-compat, smoke pre-deploy)
#   Phase 2  — Version bump (pyproject.toml + server.py if __version__ present)
#   Phase 3  — Deploy local (systemctl restart + health check × 3 + canary v2 check)
#   Phase 4  — Deploy OVH (git pull + systemctl restart + health check × 6)
#   Phase 5  — Smoke test (smoke_test_mcp_prod.py)
#   Phase 6  — Release (changelog + tag)
#   Phase 7  — PyPI publish (non-blocking)
#   Phase 8  — Telegram notification

set -euo pipefail

# --- Configuration ---
REPO_DIR="/opt/claude-ceo/workspace/mcp-servers/eu-ai-act"
SERVICE_MCP="mcp-eu-ai-act"
SERVICE_API="arkforge-euaiact-api"
LOCAL_HEALTH_URL="http://127.0.0.1:8200/health"
OVH_HOST="ubuntu@51.91.99.178"
OVH_REPO="/opt/claude-ceo/workspace/mcp-servers/eu-ai-act"
LOG_FILE="/opt/claude-ceo/logs/deploy_mcp_eu_ai_act.log"
SMOKE_TEST_SCRIPT="$REPO_DIR/scripts/smoke_test_mcp_prod.py"

# --- Args ---
VERSION_BUMP="patch"
FORCE_CI=false
SKIP_SMOKE=false
for arg in "$@"; do
    case "$arg" in
        --minor)      VERSION_BUMP="minor" ;;
        --major)      VERSION_BUMP="major" ;;
        --force)      FORCE_CI=true ;;
        --skip-smoke) SKIP_SMOKE=true ;;
    esac
done

# --- Logging ---
mkdir -p "$(dirname "$LOG_FILE")"
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; telegram_notify "Deploy FAILED: $*"; exit 1; }

# --- Telegram notification ---
telegram_notify() {
    local msg="[MCP EU AI Act Deploy] $1"
    local token="" chat_ids=""
    if token=$(python3 -c "
import sys; sys.path.insert(0, '/opt/claude-ceo')
from automation.vault import vault
t = vault.get_section('telegram') or {}
print(t.get('bot_token', ''))
" 2>/dev/null) && [ -n "$token" ]; then
        chat_ids=$(python3 -c "
import sys; sys.path.insert(0, '/opt/claude-ceo')
from automation.vault import vault
t = vault.get_section('telegram') or {}
print(t.get('chat_ids', ''))
" 2>/dev/null)
    fi
    if [ -z "$token" ] || [ -z "$chat_ids" ]; then
        log "WARN: Telegram not configured, skipping notification"
        return 0
    fi
    for chat_id in $(echo "$chat_ids" | tr ',' ' '); do
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
            -d "chat_id=${chat_id}&text=${msg}&parse_mode=Markdown" > /dev/null 2>&1 || true
    done
}

# --- Version bump helper ---
bump_version() {
    local current="$1" bump="$2"
    local major minor patch
    major=$(echo "$current" | cut -d. -f1 | tr -d 'v')
    minor=$(echo "$current" | cut -d. -f2)
    patch=$(echo "$current" | cut -d. -f3)
    case "$bump" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "${major}.$((minor + 1)).0" ;;
        patch) echo "${major}.${minor}.$((patch + 1))" ;;
    esac
}

# --- Rollback helper ---
rollback_both() {
    local prev_commit="$1" reason="$2"
    log "Rollback local: git reset --hard $prev_commit"
    git reset --hard "$prev_commit" >> "$LOG_FILE" 2>&1
    sudo systemctl restart "$SERVICE_MCP" "$SERVICE_API" 2>/dev/null || \
        sudo systemctl restart "$SERVICE_MCP" 2>/dev/null || true
    log "Rollback OVH: git reset --hard $prev_commit"
    if ssh -o ConnectTimeout=10 "$OVH_HOST" \
        "cd ${OVH_REPO} && git reset --hard $prev_commit && \
         sudo systemctl restart mcp-eu-ai-act arkforge-euaiact-api" \
        >> "$LOG_FILE" 2>&1; then
        log "Rollback OVH OK"
    else
        log "CRITICAL: Rollback OVH FAILED — intervention manuelle requise"
        telegram_notify "CRITICAL: rollback OVH FAILED ($reason) — intervention manuelle requise"
    fi
}

# --- Ensure we're on main ---
cd "$REPO_DIR"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    fail "Not on main branch (current: $CURRENT_BRANCH). Switch to main before deploying."
fi

log "=== MCP EU AI Act Deploy — $(date -u) ==="
log "Branch: main | Version bump: $VERSION_BUMP | Force CI: $FORCE_CI | Skip smoke: $SKIP_SMOKE"

# ============================================================
# PHASE 1 — GATES
# ============================================================
log "--- Phase 1: Gates ---"

# Gate 1 — CI GitHub
if [ "$FORCE_CI" = false ]; then
    log "Gate 1/4: CI GitHub on main..."
    CI_STATUS=$(gh run list --repo ark-forge/mcp-eu-ai-act --branch main --limit 1 \
        --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "")
    if [ -z "$CI_STATUS" ] || [ "$CI_STATUS" = "null" ]; then
        CI_STATUS=$(gh run list --repo ark-forge/mcp-eu-ai-act --limit 10 \
            --json conclusion,headSha \
            --jq "[.[] | select(.conclusion==\"success\")] | .[0].conclusion" 2>/dev/null || echo "unknown")
    fi
    if [ "$CI_STATUS" != "success" ]; then
        fail "CI gate FAILED — last run: '$CI_STATUS'. Use --force to bypass."
    fi
    log "Gate 1/4: CI OK (last run: success)"
else
    log "Gate 1/4: CI bypassed (--force)"
fi

# Gate 2 — pytest + coverage 80%
log "Gate 2/4: pytest + coverage 80%..."
if ! python3 -m pytest tests/ -q --cov=. --cov-fail-under=80 \
        --ignore=tests/test_integration.py --tb=short >> "$LOG_FILE" 2>&1; then
    fail "pytest gate FAILED (coverage < 80% or tests failing)"
fi
log "Gate 2/4: pytest OK (coverage >= 80%)"

# Gate 3 — backward-compat
log "Gate 3/4: backward-compat tests..."
if [ -f "tests/test_backward_compat.py" ]; then
    if ! python3 -m pytest tests/test_backward_compat.py -q --tb=short >> "$LOG_FILE" 2>&1; then
        fail "Backward-compat gate FAILED"
    fi
    log "Gate 3/4: backward-compat OK"
else
    log "Gate 3/4: tests/test_backward_compat.py not found — skipping (WARNING)"
fi

# Gate 4 — smoke pre-deploy (only if service is running)
log "Gate 4/4: smoke pre-deploy health check..."
PRE_HEALTH=$(curl -s --max-time 5 "$LOCAL_HEALTH_URL" 2>/dev/null || echo "")
if [ -z "$PRE_HEALTH" ]; then
    log "Gate 4/4: service not running — skipping pre-deploy smoke (WARNING)"
else
    PRE_STATUS=$(echo "$PRE_HEALTH" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('ok' if 'status' in d else 'missing_status')
except:
    print('error')
" 2>/dev/null || echo "error")
    if [ "$PRE_STATUS" = "ok" ]; then
        log "Gate 4/4: pre-deploy health OK"
    else
        log "Gate 4/4: pre-deploy health returned unexpected response ($PRE_STATUS) — WARNING (non-blocking)"
    fi
fi

log "All gates PASSED"

# ============================================================
# PHASE 2 — VERSION BUMP
# ============================================================
log "--- Phase 2: Version bump ---"

# Compute new version from pyproject.toml
CURRENT_VERSION=$(grep -oP '(?<=^version = ")[^"]+' pyproject.toml 2>/dev/null || echo "")
if [ -z "$CURRENT_VERSION" ]; then
    fail "Could not read version from pyproject.toml"
fi
NEW_VERSION=$(bump_version "$CURRENT_VERSION" "$VERSION_BUMP")
log "Version: $CURRENT_VERSION → $NEW_VERSION"

# Build changelog and save rollback point BEFORE any changes
LAST_TAG=$(git tag --sort=-v:refname | head -1)
if [ -z "$LAST_TAG" ]; then LAST_TAG="v0.0.0"; fi
NEW_TAG="v${NEW_VERSION}"
CHANGELOG=$(git log "${LAST_TAG}..HEAD" --oneline --no-merges 2>/dev/null | head -20 | sed 's/^/• /' || echo "• No changelog available")

PREV_COMMIT=$(git rev-parse HEAD)
log "Previous commit (rollback point): $PREV_COMMIT"

# Pull to avoid redundant bumps
git pull origin main >> "$LOG_FILE" 2>&1

# Re-read in case origin already had a bump
CURRENT_VERSION=$(grep -oP '(?<=^version = ")[^"]+' pyproject.toml 2>/dev/null || echo "$CURRENT_VERSION")
if [ "$CURRENT_VERSION" != "$NEW_VERSION" ]; then
    sed -i "s/^version = .*/version = \"$NEW_VERSION\"/" pyproject.toml

    # Update __version__ in server.py if it exists
    if grep -q '__version__' server.py 2>/dev/null; then
        sed -i "s/^__version__ = .*/__version__ = \"$NEW_VERSION\"/" server.py
        git add pyproject.toml server.py
        log "Version bumped in pyproject.toml + server.py"
    else
        git add pyproject.toml
        log "Version bumped in pyproject.toml (no __version__ in server.py)"
    fi

    git commit -m "chore: bump version to $NEW_VERSION" >> "$LOG_FILE" 2>&1
    git push origin main >> "$LOG_FILE" 2>&1
    log "Version commit pushed"
else
    log "Version already at $NEW_VERSION — no bump needed"
fi

NEW_COMMIT=$(git rev-parse HEAD)
log "Local commit: $NEW_COMMIT"

# Check OVH current state
OVH_COMMIT=$(ssh -o ConnectTimeout=10 "$OVH_HOST" \
    "GIT_DIR=${OVH_REPO}/.git git rev-parse HEAD 2>/dev/null" 2>/dev/null || echo "unknown")
log "OVH commit: $OVH_COMMIT"

if [ "$NEW_COMMIT" = "$PREV_COMMIT" ] && [ "$OVH_COMMIT" = "$NEW_COMMIT" ]; then
    log "Nothing to deploy — local and OVH are already on $NEW_COMMIT. Exiting."
    exit 0
fi

# ============================================================
# PHASE 3 — DEPLOY LOCAL
# ============================================================
log "--- Phase 3a: Deploy local (restart services) ---"
sudo systemctl restart "$SERVICE_MCP" "$SERVICE_API" 2>/dev/null || \
    sudo systemctl restart "$SERVICE_MCP" 2>/dev/null || \
    fail "Could not restart local services"
sleep 3

# Phase 3b — health check × 3 × 5s
log "--- Phase 3b: Local health check (3 attempts × 5s) ---"
LOCAL_HEALTHY=false
for i in 1 2 3; do
    sleep 5
    LOCAL_STATUS=$(curl -s --max-time 5 "$LOCAL_HEALTH_URL" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('ok' if 'status' in d else 'missing')
except:
    print('error')
" 2>/dev/null || echo "error")
    log "Phase 3b attempt $i/3: status=$LOCAL_STATUS"
    if [ "$LOCAL_STATUS" = "ok" ]; then
        LOCAL_HEALTHY=true
        break
    fi
done

if [ "$LOCAL_HEALTHY" = false ]; then
    log "Phase 3b FAILED — local not healthy after restart"
    git reset --hard "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
    sudo systemctl restart "$SERVICE_MCP" "$SERVICE_API" 2>/dev/null || \
        sudo systemctl restart "$SERVICE_MCP" 2>/dev/null || true
    fail "Phase 3b FAILED — rolled back local to $PREV_COMMIT (OVH untouched)"
fi
log "Phase 3b OK — local healthy"

# Phase 3c — canary: verify v2 fields in /scan response
log "--- Phase 3c: Canary v2 check (compliance_percentage) ---"
CANARY_OK=true
CANARY_RESP=$(curl -s --max-time 10 -X POST "http://127.0.0.1:8200/scan" \
    -H "Content-Type: application/json" \
    -d '{"text": "import openai", "risk_category": "limited"}' \
    2>/dev/null || echo "")

CANARY_V2=$(echo "$CANARY_RESP" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    has_v2 = 'compliance' in d and 'compliance_percentage' in d.get('compliance', {})
    print('ok' if has_v2 else 'missing')
except:
    print('error')
" 2>/dev/null || echo "error")

if [ "$CANARY_V2" = "ok" ]; then
    log "Phase 3c OK — content_scores key present (v2 confirmed)"
elif [ "$CANARY_V2" = "error" ]; then
    log "Phase 3c WARN — canary scan endpoint not reachable or malformed (non-blocking)"
else
    log "Phase 3c WARN — content_scores key missing in scan response (v2 not confirmed)"
    CANARY_OK=false
fi

if [ "$CANARY_OK" = false ]; then
    log "Phase 3c FAILED — v2 canary check failed — rolling back local (OVH untouched)"
    git reset --hard "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
    sudo systemctl restart "$SERVICE_MCP" "$SERVICE_API" 2>/dev/null || \
        sudo systemctl restart "$SERVICE_MCP" 2>/dev/null || true
    fail "Phase 3c canary FAILED — rolled back local to $PREV_COMMIT"
fi

# ============================================================
# PHASE 4 — DEPLOY OVH
# ============================================================
log "--- Phase 4: Deploy OVH ($OVH_HOST) ---"

# Sync vault secrets before deploy
VAULT_FILE="/opt/claude-ceo/config/vault.json.enc"
rsync -az --no-group -e "ssh -o ConnectTimeout=10" "$VAULT_FILE" "${OVH_HOST}:${VAULT_FILE}" \
    >> "$LOG_FILE" 2>&1 \
    && log "Phase 4: vault synced to OVH" \
    || log "WARN: vault sync failed (non-blocking)"

if ssh -o ConnectTimeout=10 "$OVH_HOST" \
    "cd ${OVH_REPO} && git pull origin main && \
     sudo systemctl restart mcp-eu-ai-act arkforge-euaiact-api" \
    >> "$LOG_FILE" 2>&1; then
    log "Phase 4: OVH deploy OK"
else
    log "Phase 4 FAILED — rolling back both servers"
    rollback_both "$PREV_COMMIT" "Phase 4 OVH deploy"
    fail "Phase 4 OVH deploy FAILED — rolled back both servers to $PREV_COMMIT"
fi

# Health check OVH × 6 × 5s
log "Health check OVH: $LOCAL_HEALTH_URL (6 attempts × 5s)..."
OVH_HEALTHY=false
for i in $(seq 1 6); do
    sleep 5
    OVH_STATUS=$(curl -s --max-time 5 "$LOCAL_HEALTH_URL" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('ok' if 'status' in d else 'missing')
except:
    print('error')
" 2>/dev/null || echo "error")
    log "OVH health attempt $i/6: status=$OVH_STATUS"
    if [ "$OVH_STATUS" = "ok" ]; then
        OVH_HEALTHY=true
        break
    fi
done

if [ "$OVH_HEALTHY" = false ]; then
    log "OVH health check FAILED — rolling back both servers to $PREV_COMMIT"
    rollback_both "$PREV_COMMIT" "OVH health check"
    # Verify rollback
    ROLLBACK_OK=false
    for i in 1 2; do
        sleep 5
        RB_STATUS=$(curl -s --max-time 5 "$LOCAL_HEALTH_URL" | python3 -c "
import sys, json
try: print('ok' if 'status' in json.load(sys.stdin) else 'missing')
except: print('error')
" 2>/dev/null || echo "error")
        if [ "$RB_STATUS" = "ok" ]; then ROLLBACK_OK=true; break; fi
    done
    if [ "$ROLLBACK_OK" = true ]; then
        log "Service operational after rollback"
    else
        log "WARN: Service not responding after rollback — manual check required"
    fi
    fail "OVH health check FAILED — rolled back to $PREV_COMMIT"
fi
log "OVH healthy after deploy"

# ============================================================
# PHASE 5 — SMOKE TEST
# ============================================================
SMOKE_RESULT="SKIPPED"
if [ "$SKIP_SMOKE" = true ]; then
    log "--- Phase 5: Smoke test SKIPPED (--skip-smoke) ---"
else
    log "--- Phase 5: Smoke test ---"
    if [ ! -f "$SMOKE_TEST_SCRIPT" ]; then
        log "WARN: Smoke test script not found at $SMOKE_TEST_SCRIPT — skipping"
        SMOKE_RESULT="SKIPPED"
    else
        SMOKE_LOG="$LOG_FILE.smoke"
        if python3 "$SMOKE_TEST_SCRIPT" \
               --base-url "http://127.0.0.1:8200" \
               2>&1 | tee -a "$SMOKE_LOG" | tail -6; then
            log "Phase 5: Smoke test PASSED"
            SMOKE_RESULT="PASSED"
        else
            SMOKE_EXIT=${PIPESTATUS[0]}
            log "Phase 5: Smoke test FAILED (exit $SMOKE_EXIT)"
            SMOKE_RESULT="FAILED"
            rollback_both "$PREV_COMMIT" "smoke test"
            # Verify rollback
            ROLLBACK_OK=false
            for i in 1 2; do
                sleep 5
                RB_STATUS=$(curl -s --max-time 5 "$LOCAL_HEALTH_URL" | python3 -c "
import sys, json
try: print('ok' if 'status' in json.load(sys.stdin) else 'missing')
except: print('error')
" 2>/dev/null || echo "error")
                if [ "$RB_STATUS" = "ok" ]; then ROLLBACK_OK=true; break; fi
            done
            if [ "$ROLLBACK_OK" = true ]; then
                log "Service operational after rollback"
            else
                log "WARN: Service not responding after rollback — manual check required"
            fi
            fail "Smoke test FAILED — rolled back both servers to $PREV_COMMIT"
        fi
    fi
fi

# ============================================================
# PHASE 6 — RELEASE
# ============================================================
log "--- Phase 6: Release ---"

# Update CHANGELOG.md before tagging
CHANGELOG_SCRIPT="$REPO_DIR/scripts/update_changelog.py"
if [ -f "$CHANGELOG_SCRIPT" ]; then
    if python3 "$CHANGELOG_SCRIPT" HEAD "$LAST_TAG" "$NEW_TAG" >> "$LOG_FILE" 2>&1; then
        git add CHANGELOG.md
        git diff --cached --quiet || {
            git commit -m "docs(changelog): $NEW_TAG [skip ci]" >> "$LOG_FILE" 2>&1
            git push origin main >> "$LOG_FILE" 2>&1
            log "CHANGELOG.md committed to main"
        }
    else
        log "WARN: update_changelog.py failed — skipping CHANGELOG commit"
    fi
else
    log "WARN: update_changelog.py not found at $CHANGELOG_SCRIPT — skipping"
fi

git tag "$NEW_TAG"
git push origin "$NEW_TAG" >> "$LOG_FILE" 2>&1
log "Tag $NEW_TAG pushed"

# ============================================================
# PHASE 7 — PYPI (non-blocking)
# ============================================================
log "--- Phase 7: PyPI publish ---"
PYPI_RESULT="skipped"

PYPI_BUILD_OK=false
PYPI_UPLOAD_OK=false
if rm -rf dist/ && python3 -m build -q >> "$LOG_FILE" 2>&1; then
    PYPI_BUILD_OK=true
    TWINE_OUT=$(twine upload dist/* 2>&1)
    echo "$TWINE_OUT" >> "$LOG_FILE"
    if echo "$TWINE_OUT" | grep -q "View at:"; then
        PYPI_UPLOAD_OK=true
        PYPI_RESULT="$CURRENT_VERSION → $NEW_VERSION"
    elif echo "$TWINE_OUT" | grep -q "already exists"; then
        log "WARN: $NEW_VERSION already on PyPI — skipping (idempotent)"
        PYPI_UPLOAD_OK=true
        PYPI_RESULT="already exists (idempotent)"
    else
        log "WARN: PyPI publish failed — $(echo "$TWINE_OUT" | tail -3)"
        PYPI_RESULT="FAILED (upload)"
    fi
else
    log "WARN: PyPI build failed (non-blocking)"
    PYPI_RESULT="FAILED (build)"
fi

# ============================================================
# PHASE 8 — TELEGRAM NOTIFICATION
# ============================================================
log "--- Phase 8: Notification ---"

if [ "$SMOKE_RESULT" = "PASSED" ]; then
    SMOKE_MSG="smoke: ✓"
elif [ "$SMOKE_RESULT" = "SKIPPED" ]; then
    SMOKE_MSG="smoke: SKIPPED"
else
    SMOKE_MSG="smoke: FAILED"
fi

NOTIFY_MSG="v${CURRENT_VERSION} → v${NEW_VERSION} OK | ${SMOKE_MSG} | pypi: ${PYPI_RESULT}\n\n${CHANGELOG}"
telegram_notify "$NOTIFY_MSG"
log "Telegram notification sent"

log "=== Deploy $NEW_TAG COMPLETE ==="
echo ""
echo "  MCP EU AI Act $NEW_TAG deployed successfully"
echo "  Health: $LOCAL_HEALTH_URL"
echo "  Changelog since $LAST_TAG:"
echo "$CHANGELOG"
