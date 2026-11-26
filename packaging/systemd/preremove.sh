#!/bin/sh
set -eu

# Stop and disable units on package removal (not on package upgrade).
# Note: Debian purge cleanup runs in postremove.sh (`postrm purge`).
if [ "${1:-}" = "remove" ] || [ "${1:-}" = "0" ]; then
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop miraserve.service miraserve-keyd.service 2>/dev/null || true
        systemctl disable miraserve.service miraserve-keyd.service 2>/dev/null || true
    fi
fi
