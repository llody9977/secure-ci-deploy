#!/bin/bash
# shellcheck disable=SC2086,SC2089,SC2090,SC2162
# ─── n8n Auto-Upgrade Script ─────────────────────────────────────────────────
# Called daily by cron. Checks for a new n8n release, upgrades if available,
# verifies the service is healthy, and rolls back automatically on failure.
#
# Usage: ./upgrade.sh [--force]
#   --force   Upgrade even if version matches current

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/upgrade.log"
ENV_FILE="$SCRIPT_DIR/.env"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "============================================="
log "  n8n Auto-Upgrade Check"
log "============================================="

# ─── PREFLIGHT ───────────────────────────────────────────────────────────────
if ! command -v docker &> /dev/null; then
    log "❌ Docker not found. Aborting."
    exit 1
fi

if ! command -v gh &> /dev/null || ! gh auth status &> /dev/null 2>&1; then
    log "⚠️  GitHub CLI not authenticated. Cannot check for updates. Skipping."
    exit 0
fi

if [ ! -f "$ENV_FILE" ]; then
    log "⚠️  .env not found at $SCRIPT_DIR. Skipping."
    exit 0
fi

# ─── RESOLVE VERSIONS ────────────────────────────────────────────────────────
CURRENT_VERSION=$(grep '^N8N_IMAGE_VERSION=' "$ENV_FILE" | cut -d '=' -f 2- | tr -d '[:space:]')
log "Current deployed version: $CURRENT_VERSION"

LATEST_VERSION=$(gh release list --repo llody9977/secure-ci-deploy --limit 20 --json tagName \
    | jq -r '.[].tagName' | grep -E '^n8n-[0-9]+\.[0-9]+\.[0-9]+$' \
    | sed 's/^n8n-//' | sort -V | tail -1)

if [ -z "$LATEST_VERSION" ]; then
    log "⚠️  Could not resolve latest version from GitHub. Skipping."
    exit 0
fi
log "Latest available version:  $LATEST_VERSION"

# ─── VERSION COMPARISON ──────────────────────────────────────────────────────
if [ "$LATEST_VERSION" = "$CURRENT_VERSION" ] && [ "${1:-}" != "--force" ]; then
    log "✅ Already on latest version ($CURRENT_VERSION). Nothing to do."
    exit 0
fi

log "🆕 New version available: $CURRENT_VERSION → $LATEST_VERSION"

# ─── SNAPSHOT CURRENT STATE FOR ROLLBACK ─────────────────────────────────────
PREV_IDENTIFIER=$(grep '^N8N_IMAGE_IDENTIFIER=' "$ENV_FILE" | cut -d '=' -f 2- || true)
PREV_VERSION="$CURRENT_VERSION"
log "Saving rollback state: $PREV_IDENTIFIER (version $PREV_VERSION)"

# ─── FETCH DIGEST FOR NEW VERSION ────────────────────────────────────────────
RELEASE_TAG="n8n-${LATEST_VERSION}"
RELEASE_BODY=$(gh release view "$RELEASE_TAG" --repo llody9977/secure-ci-deploy --json body -q '.body' 2>/dev/null || echo "")
NEW_DIGEST=$(echo "$RELEASE_BODY" | grep -oP 'sha256:[a-f0-9]{64}' | head -1)

if [ -n "$NEW_DIGEST" ]; then
    log "✅ Digest for $LATEST_VERSION: $NEW_DIGEST"
else
    log "⚠️  No digest found for $LATEST_VERSION. Falling back to version tag."
fi

# ─── APPLY UPGRADE ───────────────────────────────────────────────────────────
log "🚀 Upgrading to n8n $LATEST_VERSION..."

SED_CMD="sed -i"
[[ "$OSTYPE" == "darwin"* ]] && SED_CMD="sed -i ''"

$SED_CMD "s/^N8N_IMAGE_VERSION=.*/N8N_IMAGE_VERSION=$LATEST_VERSION/" "$ENV_FILE"

if [ -n "$NEW_DIGEST" ]; then
    $SED_CMD "s|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=@$NEW_DIGEST|" "$ENV_FILE"
else
    $SED_CMD "s|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=:$LATEST_VERSION|" "$ENV_FILE"
fi

cd "$SCRIPT_DIR"
docker compose pull 2>&1 | tee -a "$LOG_FILE"
docker compose up -d 2>&1 | tee -a "$LOG_FILE"

# ─── HEALTH CHECK ────────────────────────────────────────────────────────────
log "⏳ Waiting 30s for n8n to start..."
sleep 30

RETRIES=5
HEALTHY=false
for i in $(seq 1 $RETRIES); do
    STATUS=$(docker compose ps --format json | jq -r '.[] | select(.Service=="n8n") | .Health' 2>/dev/null || echo "")
    if [ "$STATUS" = "healthy" ]; then
        HEALTHY=true
        break
    fi
    log "   Health check attempt $i/$RETRIES: $STATUS"
    sleep 10
done

# ─── ROLLBACK IF UNHEALTHY ───────────────────────────────────────────────────
if [ "$HEALTHY" = false ]; then
    log ""
    log "❌ n8n failed health check after upgrade. Rolling back to $PREV_VERSION..."

    $SED_CMD "s/^N8N_IMAGE_VERSION=.*/N8N_IMAGE_VERSION=$PREV_VERSION/" "$ENV_FILE"
    if [ -n "$PREV_IDENTIFIER" ]; then
        $SED_CMD "s|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=$PREV_IDENTIFIER|" "$ENV_FILE"
    fi

    docker compose up -d 2>&1 | tee -a "$LOG_FILE"
    log "⚠️  Rollback complete. Running version: $PREV_VERSION"
    exit 1
fi

log ""
log "🎉 Upgrade successful! n8n is now running version $LATEST_VERSION."
log "============================================="
