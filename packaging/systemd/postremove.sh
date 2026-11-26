#!/bin/sh
set -eu

# R5-PKG-4: On Debian `dpkg --purge` (postrm receives "purge"; prerm never does) remove
# auto-generated starter credentials and the postinstall-created config file. On RPM full
# uninstall (`$1 = 0`), remove only the auto-generated starter cert/key pair.
if [ "${1:-}" = "purge" ]; then
    rm -f /etc/miraserve/certs/starter.crt /etc/miraserve/certs/starter.key
    rm -f /etc/miraserve/conf/miraserve.kdl
elif [ "${1:-}" = "0" ]; then
    rm -f /etc/miraserve/certs/starter.crt /etc/miraserve/certs/starter.key
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi
