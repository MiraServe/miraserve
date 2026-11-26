---
name: miraserve-setup
description: Install, configure and operate the MiraServe web server (static sites, reverse proxy, PHP through PHP-FPM, certificates, reloads, migration from Nginx, Apache, Caddy or OpenLiteSpeed). Use when a user asks to set up, deploy, migrate to or troubleshoot MiraServe.
---

# Setting up MiraServe

This guide is written for AI assistants that install or operate MiraServe for a user. Every command,
configuration and message in it was run against MiraServe 0.1.5 on Ubuntu 24.04 with the `.deb` package.
For anything not covered here, read the documentation at <https://miraserve.org/docs/introduction/>
(index for machines: <https://miraserve.org/llms.txt>) instead of guessing.

## Rules

1. **Never invent configuration.** MiraServe's configuration is KDL, not Nginx or Apache syntax. Only use
   directives shown here or in the documentation. `miraserve check` names the allowed directives when it
   meets an unknown one; read that list.
2. **Validate before every start or reload:** `miraserve check --fs --strict <file>`. Do not start or
   reload with a file that does not pass.
3. **Never weaken security to make an error go away.** Do not add `--no-sandbox`, do not set
   `landlock #false` or `seccomp "off"`, do not lower `min-version`, do not remove `security-headers`,
   and do not pass `--allow-insecure` to `miraserve import`, unless the user asks for exactly that after you
   explained what it disables. Explain the error instead.
4. **`.htaccess` files are not read.** Rewrite and access rules must be written into the configuration.
5. **Leave the opt-in features off** unless the user asks for them and you have read the conditions in the
   deployment guide: `file-cache`, `workers`, and `service generate --allow-openat2`.
6. **Do not cut over a live site blindly.** Keep the old server until the new one answers correctly on
   every site (test with `curl --resolve`), and ask the user before changing DNS, ports 80/443 on a
   machine that already serves traffic, or firewall rules.
7. **State what is true.** MiraServe is pre-1.0. Downloads are unsigned (verify the SHA-256 checksum).
   It has not been audited by an outside security firm. Do not promise speed.

## 1. Install

Downloads and checksums: <https://miraserve.org/download/> (same files on the GitHub release page).

| Platform | File |
|---|---|
| Debian 11+/Ubuntu 20.04+ on x86_64 (recommended for servers) | `miraserve_<version>_amd64.deb` |
| Other Linux x86_64 with glibc 2.30 or newer | `miraserve-v<version>-x86_64-unknown-linux-gnu.tar.gz` |
| macOS on Apple Silicon | `miraserve-v<version>-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 (development use only: no kernel sandbox) | `miraserve-v<version>-x86_64-pc-windows-msvc.zip` |
| Container | `miraserve/miraserve:<version>` on Docker Hub (x86_64 and arm64) |

Always verify the download against `SHA256SUMS` from the same folder before installing:

```sh
V=0.1.5
curl -fLO https://miraserve.org/dl/v$V/miraserve_${V}_amd64.deb
curl -fLO https://miraserve.org/dl/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # must print: miraserve_0.1.5_amd64.deb: OK
sudo dpkg -i miraserve_${V}_amd64.deb
```

What the package sets up:

- binary `/usr/bin/miraserve`; service `miraserve.service` (installed, **not enabled, not started**);
- service account `miraserve` (the server never runs as root), and a second account `miraserve-keyd`
  that is only used by the optional separate key-signing daemon;
- configuration `/etc/miraserve/conf/miraserve.kdl` (owner `root:miraserve`, mode `0640`);
- a self-signed starter certificate in `/etc/miraserve/certs/` so the service can start at once;
- a starter site served from `/var/www/miraserve`;
- certificate state in `/var/lib/miraserve/acme`; also `/etc/miraserve/auth`, `/etc/miraserve/keys`,
  `/var/lib/miraserve/releases`, and `/var/log/miraserve` once the service has run.

The package sets `/etc/miraserve` itself to owner `root:miraserve`, mode `0750`. If that folder already
existed and holds files other accounts read, they lose access; check before installing.

Start it and check:

```sh
sudo systemctl enable --now miraserve
systemctl is-active miraserve                 # active
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost/     # 200
curl -s  -o /dev/null -w '%{http_code}\n' http://localhost/      # 308 (redirect to HTTPS)
journalctl -u miraserve -n 30 --no-pager
```

Ports 80 and 443 (TCP) and 443 (UDP, for HTTP/3) must be free; stop or move another web server first,
with the user's agreement.

Three `WARN` lines at start-up are expected with the packaged unit and are not errors: `openat2 is
refused in this process` (the default unit's `RestrictSUIDSGID=yes` causes it), `running unprivileged
(UID ..., GID ...); OS user/group isolation verified`, and, on kernels older than Linux 6.10, `Landlock
partially enforced`.

## 2. The configuration file

One file, in KDL. Booleans are written `#true` / `#false`. Strings are quoted. Comments start with `//`.

The `server` block that the package installs, with two lines added to the `sandbox` block (keep the
block; add sites below it):

```kdl
server {
    listen ":443" protocols="h3,h2,h1"
    listen ":80" redirect-https=#true

    tls {
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "in-process"
        cert "/etc/miraserve/certs/starter.crt"
        key "/etc/miraserve/certs/starter.key"
    }

    sandbox {
        user "miraserve"
        landlock #true
        seccomp "strict"
        // Folder trees the server may read, and trees that hold FastCGI sockets. Listing them here
        // lets you add sites under them later with a reload instead of a restart (see section 5).
        read-tree "/var/www"
        socket-tree "/run/php"
    }
}
```

Adding the `read-tree` and `socket-tree` lines, or the first site outside `/var/www/miraserve`, needs
one **restart**; a reload is refused until then (section 5). The installed file also contains a starter
`site "localhost"` block; keep it for local checks or delete it.

A request whose host name matches no `site` gets `421 Misdirected Request`. Each site needs its own
`site "<host name>" { ... }` block; several names can share one block: `site "example.com" "www.example.com"`.

### Static site

```kdl
site "www.example.com" {
    security-headers "strict"
    root "/var/www/example"
}
```

For a single-page app, add a fallback route. Note that it also answers missing asset paths with
`index.html` (status 200):

```kdl
    route "/*" {
        try-files "{path}" "/index.html"
    }
```

### Application behind the reverse proxy (Node, Python, Go, anything that speaks HTTP)

```kdl
site "app.example.com" {
    security-headers "strict"
    route "/*" {
        reverse-proxy {
            upstream "http://127.0.0.1:3000"
        }
    }
}
```

- Several `upstream` lines in one `reverse-proxy` block are load-balanced.
- WebSocket upgrades are off by default; switch them on for the route that needs them with
  `allow-upgrades #true` inside `reverse-proxy`.
- Static files and proxied paths can live in one site: give the site a `root` and add routes such as
  `route "/api/*" { reverse-proxy { ... } }`.

### PHP through PHP-FPM (WordPress, Laravel and similar)

PHP runs in PHP-FPM, a separate process; MiraServe talks to it over FastCGI.

```kdl
site "blog.example.com" {
    security-headers "strict"
    root "/var/www/blog"

    route "*.php" {
        fastcgi-pass "unix:/run/php/php8.3-fpm.sock"
    }

    route "/*" {
        try-files "{path}" "{path}/" "/index.php?{query}"
    }
}
```

- Use the socket path of the PHP-FPM pool that is really installed (`ls -l /run/php/`).
- **The `miraserve` account must be allowed to open that socket.** A default Ubuntu pool creates it as
  `www-data:www-data` with mode `0660`, and the site then answers `502` with
  `FastCGI transport I/O error: Permission denied` in the journal, although `miraserve check` passes.
  Fix it in the pool file (for example `/etc/php/8.3/fpm/pool.d/www.conf`) by setting
  `listen.group = miraserve` and restarting PHP-FPM (`sudo systemctl restart php8.3-fpm`); or, if the
  pool file must not change, add the server to the socket's group
  (`sudo usermod -aG www-data miraserve`, then `sudo systemctl restart miraserve`), which also lets the
  server read other files of that group.
- For WordPress there is a `preset "wordpress-hardened"` directive; read
  <https://miraserve.org/docs/php-wordpress/> before using it.
- Files must be readable by the `miraserve` account (static files) and by the PHP-FPM pool's user (PHP).

### Other things you can configure

Redirects (`route "/old" { redirect "/new" }`), header rules, access lists, password protection, rate
limits, error pages, compression and precompressed files are described at
<https://miraserve.org/docs/sites-static/>; proxy health checks, timeouts and upstream TLS at
<https://miraserve.org/docs/reverse-proxy/>. Copy syntax from those pages, then run `miraserve check`.

## 3. Certificates

Pick one.

**Automatic certificates (ACME, for example Let's Encrypt).** Replace the `cert` and `key` lines in the
`server { tls { ... } }` block with:

```kdl
        acme {
            email "admin@example.com"
            challenge "tls-alpn-01"
        }
```

The host names must already point to this server, and port 443 must be reachable from the internet.
Use the user's real contact address. Issuance happens after start; watch `journalctl -u miraserve`.
(This guide's author validated this configuration with `miraserve check` but did not run a real
issuance; if it fails, read the journal and <https://miraserve.org/docs/tls/>.)

**Your own certificate files**, for all sites in the `server` `tls` block (as the starter does) or per site:

```kdl
site "www.example.com" {
    tls {
        cert "/etc/miraserve/certs/www.example.com.crt"
        key "/etc/miraserve/certs/www.example.com.key"
    }
    root "/var/www/example"
}
```

Put certificate files under `/etc/miraserve/certs/`. The key must be readable by the `miraserve`
account and by no other ordinary user: `chown root:miraserve` with `chmod 0640` works, and so does the
layout the package uses for its starter key (`miraserve:miraserve`, mode `0600`). `miraserve cert inspect <file>` prints names and validity.

The self-signed starter certificate is for the first start only. Browsers will not trust it; replace it
before real traffic.

## 4. Validate

Run the check as the service account, with the same options the service uses, so file permissions are
tested too:

```sh
sudo -u miraserve miraserve check --fs --strict \
    --acme-dir /var/lib/miraserve/acme /etc/miraserve/conf/miraserve.kdl
```

Success looks like:

```text
OK: '/etc/miraserve/conf/miraserve.kdl' is valid (2 listener(s), 3 site(s), 3 route(s), TLS >= 1.3, PQC: X25519MLKEM768 enabled, 0 warning(s))
```

An error shows the file, line and column with an excerpt, and the allowed alternatives; the command
ends with `FAILED: '<file>' has 1 error(s) and 0 warning(s)` and exit status 1. Abbreviated example:

```text
miraserve::E002
  × unknown directive 'gzip' inside 'site'
    ╭─[/etc/miraserve/conf/miraserve.kdl.new:59:5]
  help: allowed directives in 'site' are: preset, security-headers, http, rate-limit, tls, root, owner-dir, index, precompressed, file-cache, bot-auth, ai-publish, error-pages, access, basic-auth, headers, rewrite, route
```

`--strict` turns warnings into failures. Fix the cause; do not silence a warning unless you understand
it and the user agrees. `miraserve check --format json <file>` gives the same result as JSON.

A safe way to change the configuration: write the new file next to the active one, check it, then move
it into place, keeping the owner and mode:

```sh
sudo install -o root -g miraserve -m 0640 new.kdl /etc/miraserve/conf/miraserve.kdl.new
sudo -u miraserve miraserve check --fs --strict --acme-dir /var/lib/miraserve/acme /etc/miraserve/conf/miraserve.kdl.new
sudo mv /etc/miraserve/conf/miraserve.kdl.new /etc/miraserve/conf/miraserve.kdl
```

## 5. Apply: reload or restart

```sh
sudo systemctl reload miraserve     # no dropped connections
```

A reload re-validates the file first. If the new file is invalid, the reload fails and **the previous
configuration keeps serving**; fix the file and reload again. When a reload fails, `systemctl reload`
itself prints only `Job for miraserve.service failed.`; the reason is in
`journalctl -u miraserve -n 20`, in a line that starts `error: MiraServe PID <n> reload failed:`.

**When a reload is not enough.** On Linux the sandbox (Landlock) is fixed when the server starts. A
reload that needs a folder or socket the running server was not granted is refused; the journal line
ends with:

```text
reload failed: restart required: path(s) outside the startup Landlock policy: /var/www/new-site; restart MiraServe, or list their parent under sandbox read-tree/socket-tree so later reloads are covered
```

Then either restart (`sudo systemctl restart miraserve`, a short interruption), or, better, list the
parent folders once in the `sandbox` block (`read-tree "/var/www"`, `socket-tree "/run/php"`), restart
once, and from then on new sites under those folders need only a reload. Only list trees whose whole
content the web server may read.

**After every restart, check that the server really came up.** `systemctl restart` returns 0 even when
the server then refuses to start, and the unit keeps retrying every few seconds:

```sh
sudo systemctl restart miraserve; sleep 2
systemctl is-active miraserve        # must print: active   (not "activating" or "failed")
```

If it is not `active`, read `journalctl -u miraserve -n 20`, fix the cause, and repeat. All sites are
down while it is not active.

A folder that was deleted and created again is a different folder to the sandbox even under the same
name; replace a site's files inside the folder, or restart after replacing the folder itself.

Test each site before DNS points to the server:

```sh
curl -sk --resolve www.example.com:443:127.0.0.1 -o /dev/null -w '%{http_code}\n' https://www.example.com/
```

## 6. Sites under /home

The packaged service unit hides `/home` (`ProtectHome=yes`). A site root there passes `miraserve check`
run from a shell, but the running service cannot open it.

- A **reload** is refused and the other sites keep serving. Journal:
  `reload failed: OS sandbox error: Landlock LSM confinement failed: reload refused: sandbox grant(s) invalid in the new configuration: '/home/user/site': cannot open grant target: Permission denied (os error 13)`.
  Do not restart to get past this message.
- A **restart** takes every site down: the server refuses to start with
  `error: refusing to start: Landlock LSM confinement failed: cannot finalize sandbox grants: '/home/user/site': cannot open grant target: Permission denied (os error 13)`.

Prefer a folder outside `/home`, such as `/var/www/<site>`. If the site must stay under `/home`, allow the
service to read `/home`, with the user's agreement. Either add a drop-in:

```sh
sudo mkdir -p /etc/systemd/system/miraserve.service.d
printf '[Service]\nProtectHome=read-only\n' | sudo tee /etc/systemd/system/miraserve.service.d/home.conf
sudo systemctl daemon-reload
sudo systemctl restart miraserve; sleep 2; systemctl is-active miraserve
```

or generate a complete unit, which differs from the packaged one in that same line, and save it as
`/etc/systemd/system/miraserve.service` (it overrides the packaged unit), then run the same
`daemon-reload` and restart:

```sh
miraserve service generate --target systemd \
    --config /etc/miraserve/conf/miraserve.kdl --home-docroots | sudo tee /etc/systemd/system/miraserve.service
```

The `miraserve` account also needs permission to enter the home directory and read the files.

## 7. Migrating from Nginx, Apache, Caddy or OpenLiteSpeed

```sh
miraserve import /etc/nginx/sites-enabled/example.conf --from nginx --output draft.kdl
```

`--from` accepts `nginx`, `caddy`, `apache`, `openlitespeed` or `auto` (the default). On success the
exit status is 0. The result is a **draft**: read the "Manual review notes" it prints, compare it with
the old configuration, add the `user`, `read-tree` and `socket-tree` lines from section 2 to its
`sandbox` block, and run `miraserve check` on it. The draft keeps the old server's certificate paths;
`check --fs` fails with `E301 ... is missing or unreadable` until the certificates are where the
`miraserve` account can read them (copy them to `/etc/miraserve/certs/` and edit the paths, or switch
to ACME). Proxied routes are written with `allow-upgrades #false`; change it only for routes that need
WebSocket.

The importer refuses to guess. When it meets a rule that controls access or changes what is served and
that it cannot translate exactly, it stops with exit status 1 and writes no file:

```text
SECURITY ERROR: refused to emit open routes from nginx config (1 untranslatable security control(s)):
  ! line 7 (lua_code_cache): Server-level Nginx directive 'lua_code_cache' is not translated and is not known to be inert; site withheld because it may change what is served or who may reach it
```

That is the intended result. Tell the user which line it is, work out what that rule did, and write the
equivalent by hand from the documentation. Do not use `--allow-insecure` to get past it without the
user's explicit decision. Rules in `.htaccess` files are never imported.

## 8. Without the package

- **Binary archive:** unpack, put `miraserve` on the `PATH`, write a configuration, then
  `miraserve check <file>` and `miraserve run <file>`. For a quick local test without a certificate, add
  `--dev-tls` to both (`miraserve run site.kdl --dev-tls`); it creates a self-signed certificate.
  To run as a service, generate a unit: `miraserve service generate --target systemd --config <file>`
  (also `launchd` on macOS). Create the service account and folders the unit names.
- **Container:** `docker run --rm -p 8443:8443/tcp -p 8443:8443/udp -p 8080:8080/tcp miraserve/miraserve:0.1.5`
  serves a starter page on <https://localhost:8443/>. Its configuration is `/etc/miraserve/miraserve.kdl`
  and its site folder `/var/www/html`; mount your own over them, read-only (the author of this guide
  ran the image as shipped but did not test such mounts). Port 8080 redirects to HTTPS. The image has
  no shell or other tools inside. The sandbox needs a Linux kernel with Landlock (5.13 or newer); on a
  kernel without it the server stops at start and says so.

## 9. Troubleshooting

| Symptom | Cause and what to do |
|---|---|
| `421 Misdirected Request` | No `site` block for that host name. Add the name, check, reload. |
| `404` for a file that exists | The `miraserve` account cannot read it, a symbolic link points outside the site root, or it is a hidden or blocked file type (dotfiles such as `.env`, `*.bak`, `*.sql`, keys and similar are never served). Check permissions with `sudo -u miraserve cat <file>`. |
| `systemctl reload` fails, site still works | The new configuration was refused and the old one is still active. Read `journalctl -u miraserve -n 20`; fix and reload. |
| Reload says "restart required: path(s) outside the startup Landlock policy" | See section 5. |
| Service does not start after adding a site under `/home` | See section 6. |
| `502` on a proxied route | The application is not listening on the `upstream` address. Test it directly with `curl`. |
| `502` on PHP | PHP-FPM is not running, the socket path is wrong, or the `miraserve` account may not open the socket (journal: `FastCGI transport I/O error: Permission denied`; see the PHP part of section 2). Check `systemctl status php8.3-fpm` and `ls -l /run/php/`. |
| `systemctl restart` succeeded but nothing answers | The server refused to start and is retrying. `systemctl is-active miraserve` prints `activating`; read the journal (section 5). |
| `404` on `.php` files | The site has no `route "*.php"` with `fastcgi-pass`. MiraServe never sends PHP source; add the route. |
| Browser warns about the certificate | The self-signed starter certificate is still in use, or ACME has not issued yet. See section 3 and the journal. |
| `WARN openat2 is refused in this process` at start | Expected with the default unit. Not an error. |
| `miraserve check` passes from a root shell but the service fails | Check as the service account (section 4); the unit also hides `/home` and makes most of the system read-only. |

Logs: `journalctl -u miraserve`. Version and build features: `miraserve version`.

## 10. Before you say it is done

- `miraserve check --fs --strict` passes when run as the `miraserve` account.
- Every site answers with the expected status over HTTPS (`curl --resolve`), and HTTP redirects to HTTPS.
- The service is enabled, and after `sudo systemctl restart miraserve; sleep 2` the command
  `systemctl is-active miraserve` prints `active`.
- The starter certificate is replaced for any public host name.
- The user knows what you changed, what you could not translate, and that the old server is still
  available until they decide to remove it.

## Removing MiraServe

`sudo systemctl disable --now miraserve` and `sudo dpkg --purge miraserve` remove the program and the
service. They leave behind, on purpose or not: the folders `/etc/miraserve` (with `conf`, `certs`,
`auth`, `keys`), `/var/lib/miraserve` (certificates and ACME account), `/var/log/miraserve`, the
accounts and groups `miraserve` and `miraserve-keyd`, and any unit or drop-in you added under
`/etc/systemd/system/`. Remove those only if the user wants the certificates and configuration gone.

Security problems in MiraServe itself are reported privately to <support@miraserve.org>
(see `SECURITY.md`), not in public issues.
