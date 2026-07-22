#!/bin/sh -eu
# backup_vps.sh — nightly logical dump of the GPTImage database on the VPS.
# Installed as a systemd timer (gptimage-backup.timer) running as postgres.
# The schema is small (auth state only), so a nightly pg_dump is the whole
# backup story; pull latest.dump off-box however you already move backups.

DIR=/var/backups/gptimage
KEEP_DAYS=14

umask 027
mkdir -p "$DIR"
TS=$(date +%F)
TMP="$DIR/gptimage-$TS.dump.tmp"
OUT="$DIR/gptimage-$TS.dump"

pg_dump -Fc -d gptimage -f "$TMP"
mv "$TMP" "$OUT"
ln -sfn "gptimage-$TS.dump" "$DIR/latest.dump"

# Prune dumps older than KEEP_DAYS.
find "$DIR" -maxdepth 1 -name 'gptimage-*.dump' -mtime +"$KEEP_DAYS" -delete

echo "backup: wrote $OUT ($(du -h "$OUT" | cut -f1))"
