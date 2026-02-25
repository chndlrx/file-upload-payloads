# Fuzzing

Wordlists for discovering what file extensions and content types a target application accepts or rejects during file upload.

| File | Entries | Use |
|------|---------|-----|
| `extensions_20.txt` | 20 | Starter list — high-impact extensions |
| `extensions.txt` | 279 | Full extension list |
| `content_type_20.txt` | 20 | Starter list — common MIME types |
| `content_type.txt` | 2386 | Full content type list |

---

## Methodology

### 1. Reconnaissance first

Before fuzzing, observe normal upload behavior. Note what the application accepts, what errors it returns, and whether validation appears to happen client-side, server-side, or both. This shapes how aggressively you need to fuzz.

### 2. Identify the filter type

How the application filters uploads determines the most efficient approach:

- **Allow list** — only explicitly permitted types are accepted. Fuzzing is well-suited here: send a broad range of extensions and content types to map the exact allow list, then focus on bypass techniques within those boundaries.
- **Deny list** — only certain types are blocked. You can often skip broad fuzzing entirely and go straight to testing bypass techniques (double extensions, case variations, MIME spoofing) against the specific blocked types.

### 3. Start small

Use the 20-item starter lists (`extensions_20.txt`, `content_type_20.txt`) before reaching for the full lists. They cover the most impactful and commonly misconfigured types and give you a quick read on how the application behaves — whether validation is strict, lenient, or inconsistent — without generating unnecessary noise.

Only escalate to the full lists if the starter lists don't reveal enough about what's allowed.

### 4. Fuzz extensions and content types independently

These two controls are often enforced separately, and a mismatch between them is where vulnerabilities tend to surface:

- An application may block `.php` by extension but accept `application/x-httpd-php` as a content type
- It may accept `.svg` but reject `image/svg+xml`, or vice versa
- Mismatches between the two can indicate the server is trusting one over the other

Test each dimension on its own, then combine mismatched pairs to probe for inconsistencies.

### 5. Know when to go manual

Automated fuzzing is useful for mapping the attack surface, but manual testing is often more effective once you know what the application accepts. Sending thousands of requests is rarely necessary and risks triggering rate limiting, alerting a WAF, or filling up server logs. If you have a feel for the filter behavior, targeted manual probes will usually get you further faster.

---

## What to look for

- **Inconsistent responses** — the same file type accepted in one context and rejected in another (e.g., different upload endpoints, or varying by file size)
- **Extension/content type mismatches** — the server trusts one and ignores the other
- **Client-side-only validation** — restrictions enforced in the browser that disappear when the request is sent directly
- **Partial matches** — filters that check only a prefix or suffix of the filename (e.g., `file.php.jpg` or `file.jpg.php`)
- **MIME sniffing** — the server or browser infers the file type from content rather than the declared type

---

## Next steps

Once you have a map of accepted types, move to the relevant attack category:

- Accepted `.php`, `.jsp`, `.asp`, `.aspx`, or similar → [`Web Shells/`](../Web%20Shells/)
- Accepted `.svg`, `.html`, `.pdf`, `.xml` → [`XSS/`](../XSS/)
- Accepted `.xml`, `.docx`, `.xlsx`, `.svg` → [`XXE/`](../XXE/)
- Accepted `.svg` → [`SSRF/`](../SSRF/)
- Accepted `.html`, `.pdf`, `.svg` → [`Open Redirect/`](../Open%20Redirect/)
- Accepted `.csv`, `.xlsx` → [`Formula Injection/`](../Formula%20Injection/)
- Accepted `.zip`, `.tar`, `.gz` → [`DoS/`](../DoS/)
- Accepted config file names (`.htaccess`, `php.ini`) → [`Content Overwrite/`](../Content%20Overwrite/)
