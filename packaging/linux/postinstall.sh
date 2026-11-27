#!/bin/sh
# Runs after the package is installed or upgraded.
# trafficam is not started automatically: you choose when it starts watching.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    # On an upgrade, restart it if it was already running.
    if systemctl is-active --quiet trafficam; then
        systemctl restart trafficam || true
    else
        echo "trafficam is installed. Start it now and at every boot with:"
        echo "  sudo systemctl enable --now trafficam"
    fi
fi
exit 0
