#!/bin/bash
# install_linux.sh
#
# The real deployment path is scripts/deploy_vps.sh, which builds from git and
# atomically flips the running server with a health-gated rollback. This script
# only lays down the one-time host prerequisites deploy_vps.sh expects:
#   - the gptimage system user and /opt/gptimage + /etc/gptimage + /var/log/gptimage
#   - the systemd unit (deploy/gptimage-mcp.service)
#   - the Caddy site block (deploy/Caddyfile.gptimage.snippet)
#   - the fail2ban jails (deploy/fail2ban/)
# then points you at create_role.sql and `gptimage_cli oauth keygen`.
#
# It is intentionally a checklist, not magic: review deploy/ and run the pieces
# that fit your box.

set -euo pipefail

cat <<'EOF'
GPTImage host setup (Debian/Ubuntu):

  1. useradd --system --home /opt/gptimage --shell /usr/sbin/nologin gptimage
  2. install -d -o gptimage -g gptimage /opt/gptimage /var/log/gptimage
     install -d -o root -g gptimage -m 0750 /etc/gptimage
  3. createdb -U postgres gptimage
     psql -U postgres -d gptimage -v gptimage_pw='...' -f sql/setup/create_role.sql
  4. cp config/gptimage.toml.example /etc/gptimage/gptimage.toml   # then edit
     printf 'GPTIMAGE_DB_PASSWORD=...\nOPENAI_API_KEY=...\n' > /etc/gptimage/env
     chmod 640 /etc/gptimage/env && chown root:gptimage /etc/gptimage/env
  5. gptimage_cli oauth keygen   # writes /etc/gptimage/oauth_signing_key.pem
     gptimage_cli passwd operator
  6. cp deploy/gptimage-mcp.service /etc/systemd/system/ && systemctl enable --now gptimage-mcp
  7. append deploy/Caddyfile.gptimage.snippet to your Caddyfile; reload Caddy
  8. install the deploy/fail2ban/ filters + jails; reload fail2ban
  9. thereafter, ship updates with scripts/deploy_vps.sh
EOF
