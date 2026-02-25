# Content Overwrite Payloads

Payloads for testing **content overwrite vulnerabilities** — scenarios where an application allows an uploaded file to overwrite a sensitive server-side file. These are used to verify that applications properly restrict upload destinations, sanitize path components, and prevent writes to sensitive locations.

---

## Attack Surface

Content overwrite attacks occur when:
- An application writes uploaded files to a predictable or controllable path
- Path traversal in filenames is not sanitised (see `../File Name Injection/`)
- The application runs as a privileged user (e.g. `root`, `www-data` with broad write access)
- Extracted archives (zip, tar) write files outside the intended directory

---

## Payload Index

### Apache `.htaccess` Overwrites

| File | What It Tests |
|---|---|
| `.htaccess_rce` | Execute PHP inside non-PHP files (`.jpg`, `.png`, etc.) — enables webshell upload bypass |
| `.htaccess_webshell` | Treat `.jpg` uploads as PHP scripts |
| `.htaccess_cgi_shell` | Enable CGI execution on arbitrary extensions |
| `.htaccess_autoindex` | Enable directory listing to enumerate uploaded/server files |
| `.htaccess_disable_auth` | Strip HTTP Basic Auth from a protected directory |
| `.htaccess_expose_config` | Serve `.env`, `.key`, `.sql`, config files as plain text |
| `.htaccess_rewrite_phishing` | Redirect all traffic from the target origin to an attacker-controlled URL |
| `.htaccess_ssrf_proxy` | Turn the server into an open proxy via `mod_rewrite` |

> **Target path:** `/var/www/html/.htaccess` or any `.htaccess`-enabled directory.

---

### System / OS Files

| File | Target Path | What It Tests |
|---|---|---|
| `etc_passwd_addroot` | `/etc/passwd` | Inject a second root-level account |
| `etc_passwd_nopasswd_root` | `/etc/passwd` | Clear the root password hash |
| `etc_shadow_clearpwd` | `/etc/shadow` | Remove password hashes to allow passwordless login |
| `etc_sudoers_allaccess` | `/etc/sudoers` | Grant all users passwordless `sudo` |
| `etc_hosts_poisoned` | `/etc/hosts` | DNS poisoning — redirect update/patch domains to attacker |
| `etc_environment_overwrite` | `/etc/environment` | Inject malicious `PATH`, `LD_PRELOAD`, `PYTHONPATH` |
| `etc_cron_backdoor` | `/etc/cron.d/` | Schedule a reverse shell via cron |
| `etc_crontab_backdoor` | `/etc/crontab` | Schedule curl-based payload delivery as root |
| `core_pattern_exploit` | `/proc/sys/kernel/core_pattern` | Redirect kernel core dumps to execute an attacker binary |
| `ld_so_preload_overwrite` | `/etc/ld.so.preload` | Inject a malicious shared library into every process |
| `ssh_authorized_keys` | `~/.ssh/authorized_keys` | Add attacker SSH public key for persistent access |
| `ssh_config_overwrite` | `~/.ssh/config` | Log SSH targets and proxy connections via attacker host |

---

### Web Application Config Files

| File | Target Path | What It Tests |
|---|---|---|
| `dotenv_overwrite.env` | `.env` | Redirect DB connections and leak `SECRET_KEY` |
| `django_settings_overwrite.py` | `settings.py` | Disable security, expose `DEBUG`, redirect DB to attacker |
| `wp_config_overwrite.php` | `wp-config.php` | Redirect WordPress DB to attacker host |
| `rails_database_yml_overwrite.yml` | `config/database.yml` | Redirect Rails DB to attacker host |
| `php_ini_overwrite.ini` | `php.ini` / `.user.ini` | Disable `open_basedir`, enable `allow_url_include`, clear `disable_functions` |
| `nginx_conf_overwrite.conf` | `nginx.conf` | Serve entire filesystem (`root /`), disable auth |
| `httpd_conf_overwrite.conf` | `httpd.conf` | Enable PHP execution on image files |
| `web_xml_overwrite.xml` | `WEB-INF/web.xml` | Remove Java EE security constraints |
| `robots_txt_expose_all.txt` | `robots.txt` | Instruct crawlers to index `/admin`, `/api`, `/.env` |

---

### Package Manager Hook Abuse

| File | Target Path | What It Tests |
|---|---|---|
| `package.json` | `package.json` | Execute arbitrary commands via `npm install` lifecycle hook (`prepare`) |
| `composer.json` | `composer.json` | Execute arbitrary commands via `composer install` hook (`pre-command-run`) |

> These test whether a CI/CD pipeline or developer machine will execute attacker code on dependency install after an overwrite.

---

## Usage Notes

- **Combine with path traversal**: These payloads are most effective when paired with filename path traversal (e.g. `../../etc/passwd`) to reach the target path.
- **Check write permissions**: Successful overwrite depends on the server process having write access to the target. Test with lower-privilege targets first (e.g. `.htaccess`, `robots.txt`).
- **Zip/tar extraction**: Many of these payloads can be packaged inside a zip with path-traversal filenames (zip slip) for extraction-based delivery.
- **CI/CD targets**: `package.json` and `composer.json` overwrites are specifically effective against build pipelines that automatically run dependency installs.

---

## Related Sections

- [`../File Name Injection/`](../File%20Name%20Injection/) — Path traversal filenames to reach target overwrite paths
- [`../Webshells/`](../Webshells/) — Follow-up payloads after using `.htaccess_rce` or `php_ini_overwrite.ini` to enable execution
