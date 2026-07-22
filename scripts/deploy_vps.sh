#!/bin/sh -eu
# deploy_vps.sh — build GPTImage from git on the VPS and atomically flip the
# running MCP server to the new binaries, with a health-gated auto-rollback.
#
# Layout (created by the systemd/provisioning step):
#   /opt/gptimage/src         git checkout (deploy key: github.com-gptimage)
#   /opt/gptimage/releases/<sha>/bin   built gptimage_mcp + gptimage_cli
#   /opt/gptimage/current     symlink -> releases/<sha>   (ExecStart points here)
#   /etc/gptimage/gptimage.toml        config (transport="http")
#   /etc/gptimage/env                   EnvironmentFile (DB pw, OPENAI_API_KEY)
#
# Usage:  gptimage-deploy.sh [git-ref]   (default: origin/main)
# Run as root; the build + migrate run as the unprivileged `gptimage` user.

REF="${1:-origin/main}"
REPO="git@github.com-gptimage:lockewerks/GPTImage.git"
SRC=/opt/gptimage/src
REL=/opt/gptimage/releases
CONFIG=/etc/gptimage/gptimage.toml
ENVFILE=/etc/gptimage/env
HEALTH_URL="http://127.0.0.1:17718/healthz"

log() { printf '[deploy] %s\n' "$*"; }

# --- fetch -------------------------------------------------------------------
if [ ! -d "$SRC/.git" ]; then
    log "cloning $REPO"
    sudo -u gptimage git clone "$REPO" "$SRC"
fi
sudo -u gptimage git -C "$SRC" fetch --quiet origin
sudo -u gptimage git -C "$SRC" checkout --quiet --force "$REF"
SHA=$(sudo -u gptimage git -C "$SRC" rev-parse --short HEAD)
log "building $SHA"

# --- build (as the service user) --------------------------------------------
sudo -u gptimage cmake -B "$SRC/build" -S "$SRC" \
    -DCMAKE_BUILD_TYPE=Release -DGPTIMAGE_BUILD_TESTS=OFF
sudo -u gptimage cmake --build "$SRC/build" -j"$(nproc)" \
    --target gptimage_mcp gptimage_cli

install -d "$REL/$SHA/bin"
install -m 0755 "$SRC/build/src/mcp/gptimage_mcp" "$REL/$SHA/bin/"
install -m 0755 "$SRC/build/src/cli/gptimage_cli" "$REL/$SHA/bin/"
# sql/ ships alongside so the cli can find migrations from the release dir.
rm -rf "$REL/$SHA/sql"
cp -r "$SRC/sql" "$REL/$SHA/sql"
chown -R gptimage:gptimage "$REL/$SHA"

PREV=$(readlink -f /opt/gptimage/current 2>/dev/null || true)

# --- migrate (with the service env) ------------------------------------------
log "applying migrations"
# shellcheck disable=SC2046
sudo -u gptimage env $(grep -v '^#' "$ENVFILE" | xargs) \
    GPTIMAGE_CONFIG="$CONFIG" \
    GPTIMAGE_MIGRATIONS_DIR="$REL/$SHA/sql/migrations" \
    "$REL/$SHA/bin/gptimage_cli" migrate

# --- flip + restart ----------------------------------------------------------
ln -sfn "$REL/$SHA" /opt/gptimage/current
systemctl restart gptimage-mcp
sleep 2

if curl -fsS -m 5 "$HEALTH_URL" >/dev/null 2>&1; then
    log "deployed $SHA (health ok)"
    # Prune old releases, keep the last 5.
    ls -1dt "$REL"/*/ 2>/dev/null | tail -n +6 | xargs -r rm -rf
    exit 0
fi

log "HEALTHCHECK FAILED — rolling back"
if [ -n "$PREV" ] && [ "$PREV" != "$REL/$SHA" ]; then
    ln -sfn "$PREV" /opt/gptimage/current
    systemctl restart gptimage-mcp
    log "rolled back to $PREV"
fi
exit 1
