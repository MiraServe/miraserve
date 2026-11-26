# Migrating to MiraServe (`miraserve import`)

MiraServe includes a built-in, fail-closed configuration migrator (`miraserve import`) for transitioning existing **Nginx**, **Caddy**, **Apache HTTP Server**, and **OpenLiteSpeed** deployments to validated MiraServe KDL.

---

## 1. Quick Migration Workflow

```bash
# 1. Auto-detect source format and generate validated KDL (never overwrites existing output without --force)
miraserve import /etc/nginx/sites-enabled/mysite.conf --from auto --output /etc/miraserve/conf/miraserve.kdl

# 2. Inspect structured JSON report (including automatic security upgrades, downgrades, and notes)
miraserve import /etc/caddy/Caddyfile --from caddy --format json

# 3. Validate the generated KDL (including filesystem paths) strictly before cutover
miraserve check --fs --strict /etc/miraserve/conf/miraserve.kdl
```

Supported `--from` values: `auto` (default), `nginx`, `caddy`, `apache`, `openlitespeed` (alias `ols`).

---

## 2. Fail-Closed Security Downgrade Protection

`miraserve import` checks for security controls in the source configuration (such as `auth_basic`, `allow`/`deny` IP ACLs, `Require`, `basicauth`/`forward_auth`, `limit_req`, ModSecurity/`crowdsec`/`coraza_waf`, client mTLS directives, untranslated browser security headers such as `Content-Security-Policy`, PHP sites lacking a `*.php` FastCGI route, blocking `return`/`RewriteRule` rules, prefix-stripping `proxy_pass`/`ProxyPass`/`handle_path`/`uri strip_prefix`, and unexpanded non-stock `include` files):

- If any detected security control cannot be translated 1:1 into MiraServe KDL, **`miraserve import` exits non-zero and refuses to write `--output`** so you never accidentally expose a previously protected route.
- When importing from a file on disk (`miraserve import /path/to/config`), Nginx `include` and Apache `Include`/`IncludeOptional` directives targeting regular files or single-directory globs confined strictly inside the configuration tree (bounded depth, file count, byte cap, and cycle checks) are **expanded and inspected** directly — including Apache `ports.conf`, `conf.d/*.conf`, and `sites-enabled/*.conf`. When reading from stdin (`-`) or when an include target is not readable inside the config tree, only canonical case-sensitive non-ACL stock parameter/TLS snippets (such as `/etc/nginx/mime.types`, `/etc/nginx/snippets/fastcgi-php.conf`, `/etc/letsencrypt/options-ssl-nginx.conf`, and `/etc/letsencrypt/options-ssl-apache.conf`) are skipped as assumed safe and recorded in the migration notes. Any other unread `include` (including `conf.d/*.conf`, `sites-enabled/*`, and unread `ports.conf` with wildcard `<VirtualHost *:port>`) fails closed.
- Passing `--allow-insecure` overrides fail-closed refusal and **emits blocked sites/routes** into the generated KDL (tagged with `// INSECURE: emitted despite <directive> (line N)` above each affected site and listed in `insecure_sites_emitted` in `--format json`). Any location-scoped blocker that overlaps an emitted catch-all route or static `root` fallback marks the entire site insecure. Use `--allow-insecure` strictly for offline inspection and re-implement all listed controls before deploying.
- `--output` never overwrites an existing file unless `--force` is explicitly provided.

---

## 3. Source-Specific Migration Notes

### 3.1 Nginx (`nginx.conf` / `sites-enabled/*.conf`)

```bash
miraserve import /etc/nginx/sites-enabled/wordpress.conf --from nginx -o wordpress.kdl
```

| Nginx Directive | MiraServe Equivalent |
| :--- | :--- |
| `listen 443 ssl http2;` | `listen ":443" protocols="h3,h2,h1"` (dual-stack IPv4+IPv6 + TLS 1.3 + PQC `X25519MLKEM768`) |
| `listen 127.0.0.1:8080;` | `listen "127.0.0.1:8080"` (loopback bind preserved; never widened to `0.0.0.0`) |
| `server_name example.com;` | `site "example.com" { ... }` |
| `root /var/www/site;` | `root "/var/www/site"` (confined via `cap-std` / `openat2 RESOLVE_BENEATH`) |
| `try_files $uri $uri/ /index.php?$args;` | `try-files "{path}" "{path}/" "/index.php?{query}"` |
| `fastcgi_pass unix:/run/php/php8.3-fpm.sock;` | `fastcgi-pass "unix:/run/php/php8.3-fpm.sock"` |
| `proxy_pass http://127.0.0.1:3000;` | `reverse-proxy { upstream "http://127.0.0.1:3000" }` (note: prefix-stripping `proxy_pass http://host/;` triggers a security downgrade because MiraServe forwards the original path unchanged) |
| `ssl_protocols TLSv1.2 TLSv1.3;` | Upgraded to TLS 1.3 only by default (add `compat-tls-1-2 #true` only if legacy TLS 1.2 clients remain) |

**WordPress sites:** Add `preset "wordpress-hardened"` inside `site { ... }` to automatically block dotfiles, `wp-config.php`, `xmlrpc.php`, PHP execution under `wp-content/uploads/`, and apply GCRA rate limits to `wp-login.php`.

### 3.2 Caddy (`Caddyfile`)

```bash
miraserve import /etc/caddy/Caddyfile --from caddy -o miraserve.kdl
```

- Site labels map to `site "<host>" { ... }` blocks.
- `root * /srv/www` + `file_server` map to `root "/srv/www"`.
- `reverse_proxy` maps to `reverse-proxy { upstream "..." }` with active health checks and optional `streaming-flush "immediate"` for SSE/LLM streams.
- `php_fastcgi unix//run/php/php8.3-fpm.sock` maps to `route "*.php" { fastcgi-pass "unix:/run/php/php8.3-fpm.sock" }` + `try-files`.
- Automatic HTTPS transitions cleanly to MiraServe's ACME v2 block (`tls { acme { email "..." challenge "tls-alpn-01" short-lived #true } }`) for routable contact emails.

### 3.3 Apache HTTP Server (`<VirtualHost>` / `apache2.conf` / `httpd.conf`)

```bash
miraserve import /etc/apache2/sites-enabled/000-default.conf --from apache -o miraserve.kdl
```

- `ServerName` / `ServerAlias` map to `site` blocks; `DocumentRoot` maps to `root`. Non-routable `ServerAdmin` placeholders (such as `webmaster@localhost` or `root@localhost`) are skipped rather than emitting invalid ACME config.
- `ProxyPass` maps to `reverse-proxy` routes; `SetHandler "proxy:unix:...|fcgi://..."` maps to `fastcgi-pass`.
- `<VirtualHost *:port>` resolves strictly against matching `Listen` directives so loopback-bound `Listen 127.0.0.1:8080` sites are never silently widened onto public ports.
- `.htaccess` files are **not** interpreted at runtime (by design — eliminates per-request filesystem traversal and hidden policy overrides). Move any required rewrite or access rules explicitly into KDL routes and presets.
- `mod_php` (in-process PHP) is intentionally unsupported; switch to isolated `php-fpm` over a Unix socket (`fastcgi-pass "unix:/run/php/php8.3-fpm.sock"`).
- **Default static script refusal:** Even without a `fastcgi-pass` route, MiraServe's static server refuses `.php`, `.phtml`, `.phar`, `.phps`, `.php5`, `.php7`, `.php8`, `.pht`, `.phpt`, and `.inc` (plus `.gz`/`.br`/`.zst` compressed copies and multi-hop symlinks to them) with `404` so misconfigured sites never leak PHP source. This safety floor cannot be turned off on static routes.

### 3.4 OpenLiteSpeed (`vhconf.conf` / `httpd_config.conf`)

```bash
miraserve import /usr/local/lsws/conf/vhosts/Example/vhconf.conf --from openlitespeed -o miraserve.kdl
```

- `docRoot`, `extprocessor` (`type proxy` / `type fcgi`), and `context` blocks map to MiraServe `root`, `reverse-proxy`, and `fastcgi-pass` routes. Unused top-level `realm` definitions (such as default `SampleProtectedArea`) are noted and skipped without blocking an otherwise clean vhost.
- **LSAPI (`type lsapi` / `lsphp`) is NOT emitted as `fastcgi-pass`** because LiteSpeed LSAPI uses a different wire protocol than FastCGI. `miraserve import` records a security downgrade when an `lsapi` processor is present; replace it with a real `php-fpm` FastCGI pool (`fastcgi-pass "unix:/run/php/php8.3-fpm.sock"`) before cutover.

---

## 4. Cutover Checklist

1. Run `miraserve check --fs --strict /etc/miraserve/conf/miraserve.kdl` and resolve all errors/warnings.
2. Test side-by-side on alternate ports (`:8443` / `:8080`) using `miraserve run miraserve.kdl --dev-tls`.
3. Verify IPv4 and IPv6 reachability (`curl -4 -I https://...` and `curl -6 -I https://...`) plus HTTP/3 (`curl --http3-only -I https://...`).
4. Stop the legacy server, bind `:443` and `:80` via `systemctl enable --now miraserve.service`, and confirm `Alt-Svc: h3=":443"` and `X25519MLKEM768` TLS 1.3 negotiation.
