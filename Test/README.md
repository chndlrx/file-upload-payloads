# Test Files

Benign test files — one per extension — for **mapping what file types an upload endpoint accepts or rejects**. Every file contains only the text `test` (or minimal valid markup for HTML/SVG). No malicious content. Upload these first to enumerate the allowed extension surface before reaching for targeted payloads.

---

## Purpose

Before testing with active payloads, use these files to answer:

1. Which extensions does the endpoint **accept** (HTTP 200 / success response)?
2. Which extensions does the endpoint **reject** (error, blocked, or renamed)?
3. How are accepted files **served back** — what `Content-Type` header is returned?
4. Does the server **rename or strip** the extension on storage?
5. Does a double-extension or encoded filename bypass the allowlist check?

Mapping the allowed surface first prevents wasting active payloads against an endpoint that rejects `.php` outright, and identifies unexpected wins (e.g. `.phtml` accepted when `.php` is blocked).

> **Also fuzz with the extension wordlist.** The files in this directory cover common extensions but the full list is broader. Run [`../Fuzzing/extensions.txt`](../Fuzzing/extensions.txt) (279 entries) against the upload endpoint to catch any extension this directory doesn't have a file for. Even extensions that appear safe are worth validating — server configuration, framework routing, and CDN rules can cause surprising behaviour for extensions you wouldn't expect to matter.

---

## File Inventory

### 286 files across 279 extensions

All files: `test.<ext>` with content `test`.
Exceptions: `test.html` contains `<html><body>test</body></html>`, `test.svg` contains a minimal SVG element.

---

### Server-Side Execution Extensions

Accepted files in these categories may be executable on the server if stored in a web-accessible location.

#### PHP

| File | Notes |
|---|---|
| `test.php` | Standard PHP — blocked by most hardened configs but the baseline to check |
| `test.php2` – `test.php8` | Version-specific aliases — some Apache/PHP configs map these to the PHP handler |
| `test.phtml` | PHP HTML template — frequently missed by blocklists that only check `.php` |
| `test.phps` | PHP source display — served as highlighted source by some configs; still leaks code |
| `test.php-s` | Apache handler alias — accepted by some module configs |
| `test.php_bak` | Backup extension — may be executed if the server maps `php_bak` or served as plain text, leaking source |

#### ASP / ASP.NET

| File | Notes |
|---|---|
| `test.asp` | Classic ASP |
| `test.aspx` | ASP.NET Web Forms page |
| `test.ascx` | ASP.NET User Control — executable in the right handler context |
| `test.ashx` | ASP.NET HTTP Handler |
| `test.asmx` | ASP.NET Web Service |
| `test.axd` | ASP.NET HTTP handler route |
| `test.cshtml` | Razor (C#) — executed by the Razor view engine |
| `test.vbhtml` | Razor (VB.NET) |

#### JSP / Java

| File | Notes |
|---|---|
| `test.jsp` | JavaServer Pages |
| `test.jspx` | XML-syntax JSP |
| `test.jspf` | JSP fragment — included by other JSPs; may be executed directly |
| `test.jspa` | JSP alias used by some frameworks (Atlassian Confluence) |

#### ColdFusion

| File | Notes |
|---|---|
| `test.cfm` | ColdFusion Markup |
| `test.cfml` | ColdFusion Markup (explicit extension) |
| `test.cfc` | ColdFusion Component — invokable as a service endpoint |

#### Server-Side Includes

| File | Notes |
|---|---|
| `test.shtml` | Apache SSI — executes `<!--#exec-->` directives |
| `test.shtm` | SSI variant |
| `test.stm` | SSI variant |

#### Other Interpreted Languages

| File | Notes |
|---|---|
| `test.pl` | Perl CGI |
| `test.py` | Python WSGI / CGI |
| `test.rb` | Ruby (Rack / CGI) |
| `test.sh` | Shell script — executable via CGI on misconfigured servers |
| `test.lua` | Lua (OpenResty / nginx) |
| `test.tcl` | Tcl CGI |

---

### Windows Script / Execution Extensions

Accepted uploads in these formats may execute if downloaded and opened, or if the server is Windows-based.

| File | Type |
|---|---|
| `test.bat`, `test.cmd` | Windows batch scripts |
| `test.ps1`, `test.ps1xml`, `test.ps2`, `test.psd1`, `test.psm1` | PowerShell script / module formats |
| `test.vbs`, `test.vbe` | VBScript (`.vbe` is encoded VBScript) |
| `test.wsf`, `test.wsh` | Windows Script File / Host |
| `test.hta` | HTML Application — runs with elevated trust in IE/MSHTML |
| `test.scr` | Windows screensaver — PE executable by another name |
| `test.pif` | Program Information File — executes associated binary |
| `test.cpl` | Control Panel applet — DLL loaded by `control.exe` |
| `test.inf` | Setup Information File — can trigger installs |
| `test.reg` | Registry file — imports on double-click |
| `test.scf` | Shell Command File — UNC path triggers NTLM auth |
| `test.gadget` | Windows Sidebar gadget |
| `test.application` | ClickOnce deployment manifest |

---

### Double-Extension & Bypass Variants

Test whether the upload allowlist checks only the **last** extension or the **full filename**.

| File | Bypass Technique |
|---|---|
| `test.php.jpg` | Last-extension check: `.jpg` passes, but some servers execute `.php` component |
| `test.php.txt` | Same as above with `.txt` as the masking extension |
| `test.asp.jpg` | ASP double-extension |
| `test.jsp.png` | JSP double-extension |
| `test.sh.gif` | Shell script disguised as GIF |
| `test.exe.jpg` | PE executable with image extension |
| `test.php%00.jpg` | **Null-byte truncation** — C-string parsers stop at `\x00`, treating the filename as `test.php`; the `.jpg` is only seen by the validation layer |

---

### Template Engine Extensions

These may be processed by a template engine if uploaded to a templates directory or rendered server-side.

| File | Engine |
|---|---|
| `test.j2`, `test.jinja` | Jinja2 (Python) |
| `test.liquid` | Liquid (Ruby / Shopify) |
| `test.mustache` | Mustache (multi-language) |
| `test.handlebars`, `test.hbs` | Handlebars (Node.js) |
| `test.haml` | Haml (Ruby) |
| `test.pug`, `test.jade` | Pug/Jade (Node.js) |
| `test.slim` | Slim (Ruby) |
| `test.njk` | Nunjucks (Node.js) |
| `test.astro` | Astro (Node.js) |
| `test.svelte` | Svelte (Node.js) |

---

### Office / Document Formats with Macro Support

| File | Risk |
|---|---|
| `test.docm`, `test.dotm` | Word macro-enabled document / template |
| `test.xlsm`, `test.xlam`, `test.xltm` | Excel macro-enabled workbook / add-in / template |
| `test.pptm`, `test.sldm`, `test.potm`, `test.ppam` | PowerPoint macro-enabled formats |

---

### Archive & Package Formats

Useful for zip slip / tar bomb / path traversal testing and for checking whether the server extracts archives.

| File | Notes |
|---|---|
| `test.zip` | Standard zip |
| `test.tar`, `test.tar.gz`, `test.tar.bz2` | Tar archives |
| `test.7z` | 7-Zip archive |
| `test.jar` | Java archive (ZIP format) — deployable on Java servers |
| `test.war` | Web Application Archive — auto-deployed by Tomcat/JBoss/WildFly if dropped in `webapps/` |
| `test.ear` | Enterprise Archive |
| `test.apk` | Android package (ZIP format) |
| `test.ipa` | iOS app package (ZIP format) |
| `test.phar` | PHP archive — executable by PHP as a script |
| `test.vsix` | Visual Studio extension (ZIP format) |
| `test.nuspec` | NuGet package spec |

---

### Web & Markup

| File | Notes |
|---|---|
| `test.html` | Rendered by browser if served without `Content-Disposition: attachment` |
| `test.svg` | Renders JS if served as `image/svg+xml` inline |
| `test.xhtml` | XHTML — treated as HTML by most browsers |
| `test.xml`, `test.xsl`, `test.xslt`, `test.dtd` | XML / transform formats |
| `test.htaccess` | Apache config override — see [`../Content Overwrite/`](../Content%20Overwrite/) |
| `test.wsdl`, `test.wadl` | Web service description — may trigger SSRF if fetched |
| `test.swf` | Flash (legacy) — executes in IE+Flash Player |

---

### Config & Credential Extensions

Test whether the endpoint accepts files that could overwrite sensitive configuration.

| File | Notes |
|---|---|
| `test.env` | `.env` — environment variable file |
| `test.cfg`, `test.conf`, `test.ini`, `test.properties`, `test.toml`, `test.yaml` | Generic config formats |
| `test.key`, `test.pem`, `test.crt`, `test.pub` | TLS/SSH key material |
| `test.htaccess` | Apache directory config |

---

### Database Files

| File | Notes |
|---|---|
| `test.sql` | SQL dump |
| `test.sqlite`, `test.sqlite3`, `test.db` | SQLite databases |
| `test.mdb`, `test.accdb` | Microsoft Access databases |
| `test.dbf` | dBase / FoxPro |

---

## Workflow

1. **Bulk upload** all files in this directory (or iterate via Burp Intruder with the list below).
2. **Record the response** for each — note status code, response body, and any error message.
3. **Request each accepted file back** and record the `Content-Type` response header.
4. **Flag unexpected accepts** — particularly any server-side execution extension, macro-enabled Office format, archive, or template engine extension.
5. **Follow up** with the extension wordlist to cover any gaps:
   ```
   ../Fuzzing/extensions.txt
   ```
6. **Use targeted payloads** from the relevant subdirectory for any extension confirmed as accepted.

---

## Quick Reference: High-Value Finds

| Finding | Follow-up payload directory |
|---|---|
| `.php` / `.phtml` / `.php5` etc. accepted | [`../Webshells/`](../Webshells/) |
| `.asp` / `.aspx` / `.cshtml` accepted | [`../Webshells/`](../Webshells/) |
| `.jsp` / `.jspx` accepted | [`../Webshells/`](../Webshells/) |
| `.svg` served inline (`image/svg+xml`) | [`../SSRF/`](../SSRF/), [`../XSS/`](../XSS/) |
| `.html` rendered in browser | [`../XSS/`](../XSS/), [`../Open Redirect/`](../Open%20Redirect/) |
| `.pdf` opened in viewer | [`../Open Redirect/`](../Open%20Redirect/) |
| `.csv` / `.xlsx` downloaded and opened | [`../Formula Injection/`](../Formula%20Injection/) |
| `.jinja` / `.j2` / `.hbs` etc. accepted | [`../SSTI/`](../SSTI/) |
| `.zip` / `.tar` extracted server-side | [`../DoS/`](../DoS/) |
| `.htaccess` accepted | [`../Content Overwrite/`](../Content%20Overwrite/) |
| `.docm` / `.xlsm` etc. accepted | [`../EICAR/`](../EICAR/) |
