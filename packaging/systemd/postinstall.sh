#!/bin/sh
set -eu

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/miraserve.conf
else
    if ! id -u miraserve >/dev/null 2>&1; then
        useradd --system --home-dir /var/lib/miraserve --shell /usr/sbin/nologin --user-group miraserve
    fi
    if ! id -u miraserve-keyd >/dev/null 2>&1; then
        useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --user-group miraserve-keyd
    fi
fi

# R4-SBX-1 & R5-PKG-1: Install or migrate `/etc/miraserve/conf/miraserve.kdl` without ever
# clobbering an existing operator config. Because the package ships the starter template under
# `/usr/share/miraserve/starter.kdl` (not `/etc/miraserve/conf/miraserve.kdl`), upgrades from
# the legacy `/etc/miraserve/miraserve.kdl` path copy the operator's real config BEFORE any
# starter config is installed!
if [ ! -e /etc/miraserve/conf ]; then
    install -d -m 0750 -o root -g miraserve /etc/miraserve/conf
fi
if [ ! -e /etc/miraserve/conf/miraserve.kdl ]; then
    if [ -f /etc/miraserve/miraserve.kdl ] && [ ! -L /etc/miraserve/miraserve.kdl ]; then
        echo "NOTICE: migrating legacy config /etc/miraserve/miraserve.kdl -> /etc/miraserve/conf/miraserve.kdl so Landlock allows atomic-rename SIGHUP reloads in split-daemon mode without exposing /etc/miraserve/keys." >&2
        cp -p /etc/miraserve/miraserve.kdl /etc/miraserve/conf/miraserve.kdl
    elif [ -f /usr/share/miraserve/starter.kdl ]; then
        install -m 0640 -o root -g miraserve /usr/share/miraserve/starter.kdl /etc/miraserve/conf/miraserve.kdl
    fi
elif [ -f /etc/miraserve/miraserve.kdl ] && [ ! -L /etc/miraserve/miraserve.kdl ]; then
    echo "NOTICE: both /etc/miraserve/conf/miraserve.kdl (active) and legacy /etc/miraserve/miraserve.kdl exist; keeping existing /etc/miraserve/conf/miraserve.kdl untouched." >&2
fi
if [ -f /etc/miraserve/conf/miraserve.kdl ] && [ ! -L /etc/miraserve/conf/miraserve.kdl ]; then
    chown root:miraserve /etc/miraserve/conf/miraserve.kdl
    chmod 0640 /etc/miraserve/conf/miraserve.kdl
fi

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/miraserve.conf
else
    for dir in /var/lib/miraserve /var/lib/miraserve/releases /run/miraserve; do
        if [ ! -e "$dir" ]; then
            install -d -m 0750 -o miraserve -g miraserve "$dir"
        fi
    done
    if [ ! -e /var/lib/miraserve/acme ]; then
        install -d -m 0700 -o miraserve -g miraserve /var/lib/miraserve/acme
    else
        chmod 0700 /var/lib/miraserve/acme
    fi
    if [ ! -e /run/miraserve-keyd ]; then
        install -d -m 2750 -o miraserve-keyd -g miraserve /run/miraserve-keyd
    fi
    if [ ! -e /etc/miraserve/certs ]; then
        install -d -m 0750 -o root -g miraserve /etc/miraserve/certs
    fi
    if [ ! -e /etc/miraserve/keys ]; then
        install -d -m 0700 -o miraserve-keyd -g miraserve-keyd /etc/miraserve/keys
    fi
    if [ ! -e /var/www/miraserve ]; then
        install -d -m 0755 -o root -g root /var/www/miraserve
    fi
fi

# R4-PKG-1: On upgrades from pre-separate-UID split-daemon installs, migrate `/etc/miraserve/keys`
# ownership to `miraserve-keyd:miraserve-keyd` (`0700` dir, `0600` files) and warn loudly if any
# active config still references the legacy `/run/miraserve/keyd.sock` socket path!
if [ -d /etc/miraserve/keys ] && [ ! -L /etc/miraserve/keys ]; then
    chown -R miraserve-keyd:miraserve-keyd /etc/miraserve/keys
    chmod 0700 /etc/miraserve/keys
    find /etc/miraserve/keys -type f -exec chmod 0600 {} +
fi
for cfg in /etc/miraserve/conf/miraserve.kdl /etc/miraserve/miraserve.kdl; do
    if [ -f "$cfg" ] && grep -q '/run/miraserve/keyd\.sock' "$cfg" 2>/dev/null; then
        echo "WARNING: $cfg references legacy /run/miraserve/keyd.sock; update keyd-socket to \"/run/miraserve-keyd/keyd.sock\" before restarting miraserve." >&2
    fi
done

# R3-PKG-1 & R4-PKG-2: Generate a unique per-host self-signed starter TLS certificate if EITHER
# file is missing (retrying half-written pairs), surfacing any error clearly and printing an
# install notice so the operator knows a self-signed localhost cert is served on :443.
if [ ! -f /etc/miraserve/certs/starter.crt ] || [ ! -f /etc/miraserve/certs/starter.key ]; then
    if [ -x /usr/bin/miraserve ]; then
        if /usr/bin/miraserve cert generate-dev \
            --force \
            --hosts localhost \
            --cert /etc/miraserve/certs/starter.crt \
            --key /etc/miraserve/certs/starter.key; then
            if [ -f /etc/miraserve/certs/starter.crt ] && [ ! -L /etc/miraserve/certs/starter.crt ]; then
                chown root:miraserve /etc/miraserve/certs/starter.crt
                chmod 0644 /etc/miraserve/certs/starter.crt
            fi
            if [ -f /etc/miraserve/certs/starter.key ] && [ ! -L /etc/miraserve/certs/starter.key ]; then
                chown miraserve:miraserve /etc/miraserve/certs/starter.key
                chmod 0600 /etc/miraserve/certs/starter.key
            fi
            # R5-PKG-2 defense-in-depth: guarantee `/etc/miraserve/certs` stays worker-traversable.
            if [ -d /etc/miraserve/certs ] && [ ! -L /etc/miraserve/certs ]; then
                chown root:miraserve /etc/miraserve/certs
                chmod 0750 /etc/miraserve/certs
            fi
            echo "NOTICE: MiraServe generated a self-signed starter certificate for localhost at /etc/miraserve/certs/starter.{crt,key}. Replace it or configure ACME in /etc/miraserve/conf/miraserve.kdl before serving public traffic." >&2
        else
            echo "WARNING: failed to generate starter TLS certificate at /etc/miraserve/certs/starter.{crt,key}; configure TLS certs or ACME before starting miraserve." >&2
        fi
    fi
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
