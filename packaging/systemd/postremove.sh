#!/bin/sh
set -eu

# R5-PKG-4: On Debian `dpkg --purge` (postrm receives "purge"; prerm never does) remove
# auto-generated starter credentials and the postinstall-created config file, remove empty
# configuration directories under /etc/miraserve, and note what was intentionally kept. On RPM
# full uninstall (`$1 = 0`), remove only the auto-generated starter cert/key pair.
if [ "${1:-}" = "purge" ]; then
    rm -f /etc/miraserve/certs/starter.crt /etc/miraserve/certs/starter.key
    rm -f /etc/miraserve/conf/miraserve.kdl
    for d in /etc/miraserve/conf /etc/miraserve/certs /etc/miraserve/auth /etc/miraserve/keys /etc/miraserve; do
        rmdir "$d" 2>/dev/null || true
    done
    kept=""
    if [ -d /etc/miraserve ]; then
        kept="non-empty configuration folders under /etc/miraserve"
    fi
    if [ -d /var/lib/miraserve ]; then
        kept="${kept:+$kept, }/var/lib/miraserve (certificates and ACME account)"
    fi
    if [ -d /var/log/miraserve ]; then
        kept="${kept:+$kept, }/var/log/miraserve"
    fi
    kept_accounts=""
    for acct in miraserve miraserve-keyd; do
        if id -u "$acct" >/dev/null 2>&1; then
            kept_accounts="${kept_accounts:+$kept_accounts and }$acct"
        fi
    done
    if [ -n "$kept_accounts" ]; then
        case "$kept_accounts" in
            *" and "*) kept="${kept:+$kept, }accounts $kept_accounts" ;;
            *) kept="${kept:+$kept, }account $kept_accounts" ;;
        esac
    fi
    if [ -n "$kept" ]; then
        printf 'miraserve: left on purpose: %s\n' "$kept" >&2
    fi
elif [ "${1:-}" = "0" ]; then
    rm -f /etc/miraserve/certs/starter.crt /etc/miraserve/certs/starter.key
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi
