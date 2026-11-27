---
name: miraserve-setup
description: Install, configure and operate the MiraServe web server (static sites, reverse proxy, PHP through PHP-FPM, certificates, reloads, migration from Nginx, Apache, Caddy or OpenLiteSpeed). Use when a user asks to set up, deploy, migrate to or troubleshoot MiraServe.
---

# Setting up MiraServe

This guide is written for AI assistants that install or operate MiraServe for a user. The walkthrough was
run against MiraServe 0.1.5 on Ubuntu 24.04 with the `.deb` package; selected 0.1.6 examples were checked
against the 0.1.6 binary, and the other 0.1.6 statements were checked against the code and packaging.
For anything not covered here, read the documentation at <https://miraserve.org/docs/introduction/>
(index for machines: <https://miraserve.org/llms.txt>) instead of guessing.

## Safety rules

1. **Tell the user and back up first.** Before any step that replaces, moves or deletes a file, or
   restarts or removes the service, tell the user what will change and copy the file to a private
   directory outside the paths being changed first (mode `0700` for anything that may hold secrets).
   Never purge or delete data without the user saying so for that data.
2. **Stop on the first failure.** Stop at the first failed command or check. Never continue an install
   after a failed checksum, and never put a configuration in place that the strict check rejected.
3. **Never print secret contents.** Never print the contents of keys, private parts of certificates,
   `.env` files, dumps or unit files that may hold secrets; test readability and show metadata instead.
4. **Keep the working server until the new one answers.** Do not stop or replace a working web server
   until the new one has answered correctly for each site.
5. **Stop and ask when the host differs.** This guide cannot cover every server: when the server differs
   from what a step assumes (another web server, a control panel, custom units, shared PHP pools, a key
   daemon), stop and ask the user.

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
V=0.1.7
curl -fLO https://miraserve.org/dl/v$V/miraserve_${V}_amd64.deb
curl -fLO https://miraserve.org/dl/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # must print: miraserve_0.1.7_amd64.deb: OK
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

These `WARN` lines may appear at start-up with the packaged unit and are not errors: `running
unprivileged (UID ..., GID ...); OS user/group isolation verified`, and, on kernels older than Linux
6.10, `Landlock partially enforced`. The notice `openat2 is refused in this process` (usually caused
by the default unit's `RestrictSUIDSGID=yes`, an outer seccomp filter, or a kernel older than Linux
5.6 behind an outer filter; a kernel older than Linux 5.6 without an outer filter prints a different
message, `openat2 is not supported by this kernel`) may also appear: it is logged at `WARN` only when
a site `file-cache` is enabled (not `"off"`) with a non-zero `server.limits.file-cache-bytes` budget,
or when `workers` is not `"shared"`; otherwise it is logged at `INFO`, and it may not appear at all
when nothing configured depends on `openat2`.

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

For a single-page app, add a fallback route. By default `try-files "{path}" "/index.html"` also answers
missing asset paths with `index.html` (status 200); add `fallback-unless-extension=#true` when missing
assets should answer 404 instead of the HTML shell. Existing assets are still matched by the earlier
`"{path}"` candidate (served on `GET`/`HEAD`, or `405` on other methods); only when evaluation reaches
the last candidate and the normalized request path (ignoring the query string, with at most one
trailing line feed removed) ends in `.` plus 1 to 8 ASCII letters or digits does the route refuse the
fallback and answer its own 404:

```kdl
site "spa.example.com" {
    security-headers "strict"
    root "/var/www/spa"

    route "/*" {
        try-files "{path}" "/index.html" fallback-unless-extension=#true
    }
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
- WebSocket upgrades are ON by default on every `reverse-proxy` route. For a backend that must never
  receive an upgraded connection, add `allow-upgrades #false` inside its `reverse-proxy` block.
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

- Use the socket path of the PHP-FPM pool that is really installed (`ls -l /run/php/`). On Linux only,
  if an exact `fastcgi-pass "unix:..."` path exists at start-up and is not a Unix socket: a plain
  wrong-type path gets no socket rule and logs a `WARN` naming the path; a directory that is also
  another configured grant keeps its previous rule and logs a `WARN`; an individually granted file
  keeps read access only and logs a `WARN`; and a directory configured as `socket-tree` keeps its rule
  with no warning. Correct the socket path and run the strict check. Reload if the corrected socket is
  covered by the start-up policy (for example it lies under a configured `socket-tree`); arrange a
  restart with the user if it needs a new grant.
- **The `miraserve` account must be allowed to reach and open that socket.** A default Ubuntu pool
  creates it as `www-data:www-data` with mode `0660`. Running `miraserve check --fs` as the `miraserve`
  account catches access problems with warning `W033` (which fails `--strict`). If left unfixed, PHP
  requests can then fail with `502` and `FastCGI transport I/O error: Permission denied` in the
  journal. `W033` has two different diagnostics with two different fixes:
  - **Message naming the socket's owner and mode** (`(owner ..., mode ...) requires read and write
    permission on the socket`): the account can reach the path, but lacks read/write permission on the
    socket itself. Fix it in the pool file (for example `/etc/php/8.3/fpm/pool.d/www.conf`) by setting
    `listen.group = miraserve` and restarting PHP-FPM (`sudo systemctl restart php8.3-fpm`); or, if the
    pool file must not change, add the server to the socket's group
    (`sudo usermod -aG www-data miraserve`, then `sudo systemctl restart miraserve`), which also lets
    the server read other files of that group.
  - **Message saying `could not be reached (type and owner unknown)`**: a parent directory cannot be
    searched by the checking account. Test search permission on each parent directory with
    `sudo -u miraserve test -x <parent> && echo ok`, use `namei -l <socket path>` to see owners and
    modes along the path, and fix the directory permission; do **not** change `listen.group` or add
    `miraserve` to a socket group for this diagnostic.
  There is no `W033` when the path does not exist or is found to be something other than a socket; a
  parent directory the account cannot search gives `W033` whatever is behind it (even under `root`).
  The informational note saying socket access was not tested under `root` appears only after the
  socket itself has been identified (with matching real and effective UID and GID).
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
to ACME). Check every proxied route in the draft for `allow-upgrades`: the importer writes
`allow-upgrades #false` on some routes and leaves the line out on others (a route without the line
allows WebSocket upgrades). Set it to what the original server did for that route.

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
- **Container:** Throw-away demo (state is lost when the container stops; for real use mount volumes as in
  `docs/DEPLOYMENT.md`): `docker run --rm -p 8443:8443/tcp -p 8443:8443/udp -p 8080:8080/tcp miraserve/miraserve:0.1.7`
  serves a starter page on <https://localhost:8443/>. Its configuration is `/etc/miraserve/miraserve.kdl`
  and its site folder `/var/www/html`; mount your own over them, read-only
  (`-v ./site.kdl:/etc/miraserve/miraserve.kdl:ro -v ./public:/var/www/html:ro`; tested with 0.1.5:
  the site is served, the sandbox is enforced, and a file changed on the host is served on the next
  request). The server runs as user 65532, so that user must be able to read the mounted files. The
  image starts with `--dev-tls`: with no certificate in your configuration it serves a self-signed
  one. Port 8080 redirects to HTTPS on port 8443, whatever host port you published. With a single
  mounted configuration file the log carries a sandbox note about exact-file access; serving is not
  affected. In Docker Compose, another service is reached by its service name:
  `reverse-proxy { upstream "http://app:8000" }` (tested with 0.1.5, also after the other container
  was recreated); the log then shows warning W005 for plain HTTP to a host that is not loopback,
  which is expected inside a private Compose network. The image has
  no shell or other tools inside. The sandbox needs a Linux kernel with Landlock (5.13 or newer); on a
  kernel without it the server stops at start and says so.

## 9. Troubleshooting

| Symptom | Cause and what to do |
|---|---|
| `421 Misdirected Request` | No `site` block for that host name. Add the name, check, reload. |
| `404` for a file that exists | Can mean: (a) `miraserve` cannot read the file or search a parent directory; (b) symlink outside `root`; (c) a dotfile (dotfiles such as `.env`, except non-dotfile paths under `/.well-known/`, are refused by default and can be allowed only by `static { dotfiles "allow" }`); or (d) an unconditionally blocked static type (`*.bak`, `*.sql`, `*.key`, `*.pem`, `*~`, PHP scripts, etc.). Check access **without printing file contents**: `sudo -u miraserve test -r <file> && echo readable`, `ls -l <file>`, and `namei -l <file>`. |
| `systemctl reload` fails, site still works | The new configuration was refused and the old one is still active. Read `journalctl -u miraserve -n 20`; fix and reload. |
| Reload says "restart required: path(s) outside the startup Landlock policy" | See section 5. |
| Service does not start after adding a site under `/home` | See section 6. |
| `502` on a proxied route | The application is not listening on the `upstream` address. Test it directly with `curl`. |
| `502` on PHP | PHP-FPM is not running, the socket path is wrong, or the `miraserve` account may not reach or open the socket. A stopped pool or a missing (or reachable non-socket) path gives `502` without `W033`; permission problems on the socket or a parent directory log `FastCGI transport I/O error: Permission denied` in the journal and are reported as `W033` by `check --fs` as `miraserve` (see the PHP part of section 2). Check `systemctl status php8.3-fpm` and `ls -l /run/php/`. |
| `warning[W033]` naming a PHP socket's owner and mode (`requires read and write permission on the socket`) | The checking account reached the socket but lacks read/write permission on it (fails `--strict`; no `W033` when the path does not exist or is found to be something other than a socket, and the `root` note appears only after the socket itself is identified with matching real and effective UID and GID). Set `listen.group = miraserve` in the PHP-FPM pool and restart PHP-FPM, or add `miraserve` to the socket's group and restart MiraServe (section 2). |
| `warning[W033]` saying a PHP socket `could not be reached (type and owner unknown)` | A parent directory cannot be searched by the checking account (gives `W033` whatever is behind it, even under `root`, before the target's type or owner is known). Test search permission on each parent directory with `sudo -u miraserve test -x <parent> && echo ok`, use `namei -l <socket path>` to see owners and modes, and fix the directory permission; do **not** change `listen.group` or add `miraserve` to a socket group for this diagnostic (section 2). |
| `WARN` naming a Unix socket path as not a socket at start | Linux only: an exact `fastcgi-pass "unix:..."` or `keyd-socket` path exists at start-up and is not a Unix socket. A plain wrong-type path gets no socket rule (`WARN`); a directory that is also another configured grant keeps its previous rule (`WARN`); an individually granted file keeps read access only (`WARN`); a directory configured as `socket-tree` keeps its rule with no warning. Correct the socket path and run the strict check. Reload if the corrected socket is covered by the start-up policy (for example it lies under a configured `socket-tree`); arrange a restart with the user if it needs a new grant (or if `keyd-socket` changed). |
| `systemctl restart` succeeded but nothing answers | The server refused to start and is retrying. `systemctl is-active miraserve` prints `activating`; read the journal (section 5). |
| `404` on `.php` files | Can mean: (a) the script is missing or unreadable inside `root` (check with `sudo -u miraserve test -r <script>` and `ls -l`, never `cat`); (b) `preset "wordpress-hardened"` deliberately returns `404` for sensitive files like `wp-config.php`; or (c) no FastCGI route matches that script (MiraServe never serves `.php` source statically). Inspect existing routes, preset, and script path first; do **not** blindly add a site-wide `route "*.php"` handler, and preserve narrow allow-lists and upload execution blocks. |
| Browser warns about the certificate | The self-signed starter certificate is still in use, or ACME has not issued yet. See section 3 and the journal. |
| `openat2 is refused in this process` at start (`INFO`, or `WARN` with enabled `file-cache` / non-`"shared"` `workers`) | Usually caused by the default unit's `RestrictSUIDSGID=yes`, an outer seccomp filter, or a kernel older than Linux 5.6 behind an outer filter; a kernel older than Linux 5.6 without an outer filter prints a different message, `openat2 is not supported by this kernel` (neither appears when nothing configured depends on `openat2`). Logged at `WARN` only when a site `file-cache` is enabled with a non-zero `file-cache-bytes` budget or `workers` is not `"shared"`, and at `INFO` otherwise; not an error unless you rely on those features. |
| `miraserve check` passes from a root shell but the service fails | Check as the service account (section 4); the unit also hides `/home` and makes most of the system read-only. |

Logs: `journalctl -u miraserve`. Version and build features: `miraserve version` (0.1.7 prints `features: precompressed, header-rule-status, service-allow-openat2, writable-set, try-files-extensionless`).

## 10. Before you say it is done

- `miraserve check --fs --strict` passes when run as the `miraserve` account.
- Every site answers with the expected status over HTTPS (`curl --resolve`), and HTTP redirects to HTTPS.
- The service is enabled, and after `sudo systemctl restart miraserve; sleep 2` the command
  `systemctl is-active miraserve` prints `active`.
- The starter certificate is replaced for any public host name.
- The user knows what you changed, what you could not translate, and that the old server is still
  available until they decide to remove it.

## Removing MiraServe

**Ask the user whether they want to remove the package and keep its files, or purge.**

`sudo dpkg --remove miraserve` removes the program; the package attempts to stop and disable both units
(`miraserve.service` and `miraserve-keyd.service`) and ignores a failure of either step, so afterwards
verify with `systemctl is-active miraserve miraserve-keyd` and by checking that nothing listens on the
ports any more before declaring the server retired. It keeps `/etc/miraserve/conf/miraserve.kdl`, the
starter certificate and key, and `/var/www/miraserve/index.html`.

`sudo dpkg --purge miraserve` additionally deletes those four files whatever they contain by then, and
backup copies next to the home page (names such as `index.html.bak`, `index.html~`,
`index.html.dpkg-old`), following a symbolic link if `index.html` is one; before a purge, copy what may
be needed to a private directory outside `/etc/miraserve`, `/var/www/miraserve`, and the directory the
home page really lives in when `index.html` is a symbolic link.

Both remove the files the package itself installed (its units under `/usr/lib/systemd/system`, its
sysusers and tmpfiles files under `/usr/lib`, and files under `/usr/share/miraserve` and
`/usr/share/doc/miraserve`), so local edits made inside those files are lost; regular local units and
drop-ins under `/etc/systemd/system` stay.

Left behind in both cases: other files under `/etc/miraserve`, `/var/lib/miraserve` (certificates, ACME
account, published releases), `/var/log/miraserve`, and the accounts and groups `miraserve` and
`miraserve-keyd`. List what is there and ask the user about each kind of data before deleting any of
it.

Security problems in MiraServe itself are reported privately to <support@miraserve.org>
(see `SECURITY.md`), not in public issues.
