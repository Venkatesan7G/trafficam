#!/bin/sh
# Runs after the package is removed.
# Your encrypted database in /var/lib/trafficam is kept on purpose, so a
# reinstall carries on learning where it left off. "apt purge trafficam"
# deletes it as well.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/trafficam
fi
exit 0
