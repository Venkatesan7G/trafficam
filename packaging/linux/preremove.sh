#!/bin/sh
# Runs before the package is removed, and before an upgrade replaces it.
set -e
# Debian passes "remove"/"upgrade"; RPM passes how many copies stay
# installed (0 = full removal, 1 = upgrade).
case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now trafficam >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
