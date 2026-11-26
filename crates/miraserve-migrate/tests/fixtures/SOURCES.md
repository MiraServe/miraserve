# Upstream Importer Test Fixtures

Every file in this directory is a **byte-for-byte unmodified copy** of an official upstream distribution or project configuration file. Do **not** edit any fixture file to make a test pass; fix the importer instead.

| Fixture file | Upstream source & package / tag version | SHA-256 |
| :--- | :--- | :--- |
| `caddy_stock_Caddyfile` | Caddy `v2.11.9` — `https://raw.githubusercontent.com/caddyserver/dist/v2.11.9/config/Caddyfile` | `66177d46fa761acb07208065db9b0274cb1b12c02ac43b9bfc9857b698b1ccfe` |
| `certbot_apache_certbot.conf` | Certbot `v2.11.0` — `https://raw.githubusercontent.com/certbot/certbot/v2.11.0/certbot-apache/certbot_apache/_internal/tests/testdata/debian_apache_2_4/multiple_vhosts/apache2/sites-available/certbot.conf` | `38c7e82f442a3602e846df1f3317a8b043eb736d14cb7fe6fb36998891393c22` |
| `certbot_apache_default-ssl.conf` | Certbot `v2.11.0` — `https://raw.githubusercontent.com/certbot/certbot/v2.11.0/certbot-apache/certbot_apache/_internal/tests/testdata/debian_apache_2_4/multiple_vhosts/apache2/sites-available/default-ssl.conf` | `6219320303c0ff8553b8f077e7776cdfdf0e1d2e623097ec9b6366f8a6c04e6c` |
| `certbot_nginx_both.com.conf` | Certbot `v2.11.0` — `https://raw.githubusercontent.com/certbot/certbot/v2.11.0/certbot-nginx/certbot_nginx/_internal/tests/testdata/etc_nginx/sites-enabled/both.com` | `7211522340163e4b70615de294cb432c7f16cd23e11fab735ae349495fd40c5f` |
| `certbot_nginx_sslon.com.conf` | Certbot `v2.11.0` — `https://raw.githubusercontent.com/certbot/certbot/v2.11.0/certbot-nginx/certbot_nginx/_internal/tests/testdata/etc_nginx/sites-enabled/sslon.com` | `f9b25bb37c8541363fab67dd01bae1d6e00a932c6847448bc65bc32e602b5d2b` |
| `debian12_apache2.conf` | Debian 12 (Bookworm) `apache2 2.4.71-1~deb12u1` — `/etc/apache2/apache2.conf` | `96e05361253da0d9be1ec6c7c9003cbbb261ba65b659bd6e40ca0eac43093c43` |
| `debian12_apache_000-default.conf` | Debian 12 (Bookworm) `apache2 2.4.71-1~deb12u1` — `/etc/apache2/sites-available/000-default.conf` | `39fe841a64538ee980ae4ef011bdf6ae7124f63bf44afd65553cf3e0618e952c` |
| `debian12_apache_ports.conf` | Debian 12 (Bookworm) `apache2 2.4.71-1~deb12u1` — `/etc/apache2/ports.conf` | `ca3f42f4f226ca53efba66a162f224375b78ff4be50ed146d303753b53fee76f` |
| `debian12_nginx.conf` | Debian 12 (Bookworm) `nginx-common 1.22.1-9+deb12u10` — `/etc/nginx/nginx.conf` | `48c6a4ec1e1fd28ccf968490f07e34a1d7f755793b2108a3ed8670b1ee2a0aa2` |
| `debian12_nginx_default.conf` | Debian 12 (Bookworm) `nginx-common 1.22.1-9+deb12u10` — `/etc/nginx/sites-available/default` | `ce0901350a021608139b5639cf4ccd7717bef8c3a9e4f79031eb46386b67b03f` |
| `ols_Example_vhconf.conf` | OpenLiteSpeed `v1.9.4` — `https://raw.githubusercontent.com/litespeedtech/openlitespeed/v1.9.4/dist/conf/vhosts/Example/vhconf.conf` | `e6c35622b32c42a404c13e23b24e99737f44c0215a2f88e352c1d71c45f5a6de` |
| `ols_httpd_config.conf.in` | OpenLiteSpeed `v1.9.4` — `https://raw.githubusercontent.com/litespeedtech/openlitespeed/v1.9.4/dist/conf/httpd_config.conf.in` | `f1befdd64e68a0ff2f2f7ff37ec05e40e8f0f4cbcb28b9bac56053ba8b48982c` |
| `rhel9_httpd.conf` | Rocky Linux 9 `httpd-2.4.62-13.el9_8.9` — `/etc/httpd/conf/httpd.conf` | `55b3dd635b5a56ebee1fe890d7372ec25c215cef0c0f3dd8f2bc5ae6e323da12` |
| `rhel9_ssl.conf` | Rocky Linux 9 `mod_ssl-2.4.62-13.el9_8.9` — `/etc/httpd/conf.d/ssl.conf` | `c12f09eda85f55cc678d02b74d448b3768d3492c79fe7c93130b36da3c525e11` |
| `wordpress_org_nginx_single_site.conf` | WordPress.org Developer Handbook — `https://developer.wordpress.org/advanced-administration/server/web-server/nginx/` (Single-Site Nginx Recipe) | `8820a84bae65cfd99714a2e5bda2d6abc2792c43715113df4eef0ea100845f65` |
