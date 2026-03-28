#!/bin/bash
# shellcheck disable=SC2086,SC2089,SC2090,SC2162

# Exit on error
set -e

# ─── FLAGS ──────────────────────────────────────────────────────────────────
# Pass --skip-verify to bypass provenance verification (for automation)
SKIP_ATTESTATION=false
for arg in "$@"; do
  case $arg in
    --skip-verify) SKIP_ATTESTATION=true ;;
  esac
done

echo "============================================="
echo "        n8n Secure Deployment Setup         "
echo "============================================="
echo ""

# ─── PREFLIGHT CHECKS ───────────────────────────────────────────────────────
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker and Docker Compose first."
    exit 1
fi

# ─── DETECT HOST IP ─────────────────────────────────────────────────────────
DETECTED_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7}' | tr -d '\n')
[ -z "$DETECTED_IP" ] && DETECTED_IP="127.0.0.1"

echo "The HOST_IP is required for n8n Webhook integrations."
echo "Detected your Host IP as: $DETECTED_IP"
echo ""
read -p "Enter your Host IP address (or press Enter to use $DETECTED_IP): " USER_IP
FINAL_IP=${USER_IP:-$DETECTED_IP}
echo "✅ Using HOST_IP: $FINAL_IP"

# ─── CHOOSE VERSION ─────────────────────────────────────────────────────────
echo ""
echo "Available releases: https://github.com/llody9977/secure-ci-deploy/releases"
read -p "Enter the n8n version to deploy (e.g. 1.55.3, or press Enter for latest): " USER_VERSION

if [ -z "$USER_VERSION" ] || [ "$USER_VERSION" = "latest" ]; then
    if command -v gh &> /dev/null && gh auth status &> /dev/null 2>&1; then
        USER_VERSION=$(gh release list --repo llody9977/secure-ci-deploy --limit 20 --json tagName \
            | jq -r '.[].tagName' | grep -E '^n8n-[0-9]+\.[0-9]+\.[0-9]+$' \
            | sed 's/^n8n-//' | sort -V | tail -1)
        echo "Resolved latest release: $USER_VERSION"
    else
        echo "⚠️  Cannot auto-resolve latest without GitHub CLI. Please enter an explicit version."
        exit 1
    fi
fi
N8N_VERSION="$USER_VERSION"
RELEASE_TAG="n8n-${N8N_VERSION}"

# ─── RESOURCE LIMITS ────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "   Container Resource Limits (Hardening)     "
echo "============================================="
echo "These limits cap the blast radius if the container is compromised."
echo "Press Enter to accept the defaults."
echo ""

read -p "Memory limit (e.g. 512m, 1g, 2g) [default: 1g]: " INPUT_MEM
MEM_LIMIT=${INPUT_MEM:-1g}

read -p "CPU limit (e.g. 0.5, 1.0, 2.0) [default: 1.0]: " INPUT_CPU
CPU_LIMIT=${INPUT_CPU:-1.0}

read -p "Max processes (pids_limit) [default: 200]: " INPUT_PIDS
PIDS_LIMIT=${INPUT_PIDS:-200}

echo ""
echo "✅ Resource limits: memory=${MEM_LIMIT}, cpus=${CPU_LIMIT}, pids=${PIDS_LIMIT}"

# ─── FETCH DIGEST FROM GITHUB RELEASE ───────────────────────────────────────
echo ""
echo "---------------------------------------------"
echo "🔍 Fetching digest for n8n-trusted:${N8N_VERSION} from GitHub Release..."
echo "---------------------------------------------"

GHCR_DIGEST=""
if command -v gh &> /dev/null && gh auth status &> /dev/null 2>&1; then
    RELEASE_BODY=$(gh release view "$RELEASE_TAG" --repo llody9977/secure-ci-deploy --json body -q '.body' 2>/dev/null || echo "")
    GHCR_DIGEST=$(echo "$RELEASE_BODY" | grep -oP 'sha256:[a-f0-9]{64}' | head -1)
fi

if [ -z "$GHCR_DIGEST" ]; then
    echo "⚠️  Could not fetch digest from GitHub Release."
    read -p "   Enter the GHCR digest manually (sha256:...), or press Enter to use version tag: " MANUAL_DIGEST
    if [ -n "$MANUAL_DIGEST" ]; then
        # Prepend sha256: if the user provided only the hex hash
        if [[ "$MANUAL_DIGEST" =~ ^[a-fA-F0-9]{64}$ ]]; then
            GHCR_DIGEST="sha256:$MANUAL_DIGEST"
        else
            GHCR_DIGEST="$MANUAL_DIGEST"
        fi
    else
        echo "   ⚠️  Falling back to version tag (less secure — digest not pinned)."
    fi
else
    echo "✅ GHCR digest: $GHCR_DIGEST"
fi

# ─── PROVENANCE VERIFICATION ────────────────────────────────────────────────
echo ""
echo "---------------------------------------------"
echo "🔐 Verifying Cryptographic Provenance..."
echo "---------------------------------------------"

if [ "$SKIP_ATTESTATION" = true ]; then
    echo "   ⚠️  --skip-verify flag set. Skipping attestation verification."
elif ! command -v gh &> /dev/null || ! gh auth status &> /dev/null 2>&1; then
    echo ""
    echo "⚠️  Provenance verification requires the GitHub CLI (gh) and authentication."
    echo "   Install: https://github.com/cli/cli#installation"
    read -p "   Skip verification and continue anyway? (Y/n): " SKIP_CONFIRM
    SKIP_CONFIRM=${SKIP_CONFIRM:-Y}
    if [[ "$SKIP_CONFIRM" =~ ^[Nn]$ ]]; then
        echo "Aborted. Please install and authenticate the GitHub CLI first."
        exit 1
    fi
    echo "   ⚠️  Skipping provenance verification."
else
    if [ -n "$GHCR_DIGEST" ]; then
        VERIFY_SUBJECT="oci://ghcr.io/llody9977/secure-ci-deploy/n8n-trusted@${GHCR_DIGEST}"
        echo "Verifying: $VERIFY_SUBJECT"
    else
        VERIFY_SUBJECT="oci://ghcr.io/llody9977/secure-ci-deploy/n8n-trusted:${N8N_VERSION}"
        echo "⚠️  No digest available — verifying by tag (weaker guarantee)"
    fi

    if gh attestation verify "$VERIFY_SUBJECT" -o llody9977; then
        echo "✅ Provenance verified — image cryptographically bound to this pipeline."
    else
        echo ""
        echo "❌ SECURITY ALERT: Provenance verification FAILED."
        echo "   The image may have been tampered with or did not originate from the trusted pipeline."
        echo "   Deployment aborted."
        exit 1
    fi
fi

# ─── WRITE .ENV ─────────────────────────────────────────────────────────────
PREV_IDENTIFIER=""

if [ ! -f .env ]; then
    echo ""
    echo "📝 Creating .env file from template..."
    cp .env.template .env
else
    echo ""
    echo "📝 Updating existing .env file..."
    PREV_IDENTIFIER=$(grep '^N8N_IMAGE_IDENTIFIER=' .env | cut -d '=' -f 2- || true)
fi

SED_CMD="sed -i"
[[ "$OSTYPE" == "darwin"* ]] && SED_CMD="sed -i ''"

$SED_CMD "s/^HOST_IP=.*/HOST_IP=$FINAL_IP/" .env
$SED_CMD "s/^N8N_IMAGE_VERSION=.*/N8N_IMAGE_VERSION=$N8N_VERSION/" .env
$SED_CMD "s/^MEM_LIMIT=.*/MEM_LIMIT=$MEM_LIMIT/" .env
$SED_CMD "s/^CPU_LIMIT=.*/CPU_LIMIT=$CPU_LIMIT/" .env
$SED_CMD "s/^PIDS_LIMIT=.*/PIDS_LIMIT=$PIDS_LIMIT/" .env

if [ -n "$GHCR_DIGEST" ]; then
    $SED_CMD "s|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=@$GHCR_DIGEST|" .env
    echo "✅ Digest written to .env — Docker will run the exact attested image."
else
    $SED_CMD "s|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=:$N8N_VERSION|" .env
    echo "⚠️  Fallback tag written to .env — digest pinning disabled."
fi

# ─── DEPLOY ─────────────────────────────────────────────────────────────────
echo ""
echo "🚀 Deploying n8n ${N8N_VERSION}..."
echo "---------------------------------------------"

docker compose up -d

echo "---------------------------------------------"
echo "⏳ Waiting for n8n to start..."
sleep 5

if docker ps | grep -q "n8n-trusted"; then
    echo ""
    echo "🎉 SUCCESS! n8n ${N8N_VERSION} deployed."
    echo "============================================="
    echo "🔗 Access your n8n instance at:"
    echo "http://$FINAL_IP:5678"
    echo "============================================="
    echo "To view logs: docker compose logs -f"
    if [ -n "$PREV_IDENTIFIER" ]; then
        echo "To rollback:  $SED_CMD 's|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=$PREV_IDENTIFIER|' .env && docker compose up -d"
    fi
else
    echo "⚠️  The container may not have started correctly."
    echo "Run 'docker compose logs' to diagnose."
fi

# ─── AUTO-UPGRADE ────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "       🔄 Auto-Upgrade Configuration         "
echo "============================================="
read -p "Enable daily auto-upgrade? Checks for new versions every day and upgrades automatically. (y/N): " ENABLE_AUTOUPGRADE
ENABLE_AUTOUPGRADE=${ENABLE_AUTOUPGRADE:-N}

if [[ "$ENABLE_AUTOUPGRADE" =~ ^[Yy]$ ]]; then
    UPGRADE_SCRIPT="$(pwd)/upgrade.sh"
    CRON_LOG="$(pwd)/upgrade.log"

    # Make the upgrade script executable
    chmod +x "$UPGRADE_SCRIPT"

    # Remove any existing cron entry for upgrade.sh, then register a fresh one
    CRON_ENTRY="0 3 * * * $UPGRADE_SCRIPT >> $CRON_LOG 2>&1"
    ( crontab -l 2>/dev/null | grep -v "$UPGRADE_SCRIPT" ; echo "$CRON_ENTRY" ) | crontab -

    echo "✅ Daily auto-upgrade enabled. Runs at 03:00 every night."
    echo "   Upgrade log: $CRON_LOG"
    echo "   To disable: crontab -e  and remove the upgrade.sh line."
else
    echo "   Auto-upgrade not enabled. You can run ./upgrade.sh manually to upgrade."
fi
