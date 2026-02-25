# Open Redirect Payloads

Payloads for testing **open redirect vulnerabilities via file upload**. These test whether an application serves uploaded files in a context where redirect-triggering content executes — HTML rendered in-browser, SVG served with `image/svg+xml`, PDFs opened in a viewer, or files processed server-side.

The redirect target in all payloads is `https://example.com`. Replace with your collaborator/OOB URL when testing.

---

## Attack Surface

Open redirect via upload occurs when:
- Uploaded HTML/SVG/XHTML is served directly from the application's origin and rendered by the browser
- Uploaded PDFs are opened in Adobe Acrobat Reader or a browser's built-in PDF viewer with JavaScript enabled
- The application uses a PDF processing library that evaluates actions without sandboxing
- A Service Worker script is accepted and registered on the application's origin

---

## Payload Index

### HTML Redirects

| File | Mechanism | Trigger |
|---|---|---|
| `redirect_meta.html` | `<meta http-equiv="refresh" content="0; url=...">` | Passive — fires on page load with no user interaction |
| `redirect_location_href.html` | `window.location.href = target` | JS on load; reads `?redirect=`, `?url=`, or `?next=` |
| `redirect_location_replace.html` | `location.replace(target)` | JS on load; reads `?redirect=` |
| `redirect_location_assign.html` | `location.assign(target)` | JS on load; reads `?redirect=` |
| `redirect_window_location.html` | `window.location = target` | JS on load; reads `?url=` |
| `redirect_anchor_href.html` | `<a id="...">` href set from `?url=` | Requires click; tests client-side DOM manipulation |
| `redirect_form_action.html` | `<form action="...">` built from `?action=` | Requires form submit; tests form action injection |
| `redirect_electron.html` | `shell.openExternal(target)` + `window.location.href` | Electron renderer context; tests `electronAPI` bridge and direct navigation |
| `redirect_wasm.html` | WebAssembly import calling `window.location.href` | Tests redirect originating from WASM memory/exports passed to a JS import function |

> `redirect_meta.html` is the most reliable for passive testing — no JavaScript required, fires immediately, and is not blocked by CSP unless `meta` refresh is explicitly restricted.

---

### Non-HTML Web File Redirects

| File | Format | Mechanism |
|---|---|---|
| `redirect.svg` | SVG | `onload="redirect()"` handler sets `window.location.href`; also contains an `xlink:href` anchor. Fires if the SVG is served as `image/svg+xml` and rendered directly (not via `<img>` tag). |
| `redirect.xhtml` | XHTML | `<meta http-equiv="refresh">` + `window.location.href` in `<script>`. Tests whether the application treats `.xhtml` as executable markup. |
| `redirect.xml` | XML | `<?xml-stylesheet type="text/xsl" href="redirect.xsl"?>` processing instruction. Tests XSL transform execution on XML files. |
| `redirect_sw.js` | Service Worker | Three vectors: (1) `fetch` event returns `302 Location: <attacker>`, (2) `clients.navigate(target)` via `postMessage`, (3) `clients.openWindow(target)` on notification click. Effective if the JS file can be registered as a SW on the application's origin. |

---

### PDF Redirects — JavaScript Actions

PDF JavaScript runs in the Acrobat/Reader JS sandbox and has access to `app.launchURL()`, which opens a URL in the default browser.

#### Trigger Events

| File | PDF Action | Trigger |
|---|---|---|
| `redirect_js_openaction.pdf` | `/OpenAction /S /JavaScript` | Fires `app.launchURL()` immediately on document open |
| `redirect_aa_pageopen.pdf` | `/AA /O` (Additional Action — Page Open) | Fires when the page is rendered/scrolled into view |
| `redirect_aa_pageclose.pdf` | `/AA /C` (Additional Action — Page Close) | Fires when navigating away from the page |
| `redirect_docaa_willclose.pdf` | Catalog `/AA /WC` (Will Close) | Fires just before the document is closed |
| `redirect_beforeprint_aa.pdf` | Catalog `/AA /WP` (Will Print) | Fires when the user attempts to print the document |
| `redirect_annot_aa_mouseenter.pdf` | Annotation `/AA /E` (Mouse Enter) | Fires when the cursor enters the annotation bounding box |
| `redirect_widget_focus.pdf` | Widget `/AA /Fo` (Field Focus) | Fires when a form field receives focus (user clicks into it) |
| `redirect_multipage_page2open.pdf` | `/AA /O` on Page 2 | Fires when page 2 is opened — tests whether scanners check all pages |
| `redirect_trans_js.pdf` | `/Trans` (page transition) + `/AA /O` JS | Combines a visual wipe transition with a JS redirect on page open |
| `redirect_names_javascript.pdf` | `/Names /JavaScript` tree | Registers a global named JS action that runs on open |
| `redirect_chained_actions.pdf` | Three-step `/Next` chain: JS → JS → URI | Tests whether validators follow and evaluate chained action chains |

#### JS Obfuscation Variants

These all use `/OpenAction /S /JavaScript` but obfuscate the payload to evade static analysis:

| File | Obfuscation Technique |
|---|---|
| `redirect_js_hex_string.pdf` | `String.fromCharCode(104,116,116,112,115,...)` — URL built from character codes |
| `redirect_js_eval.pdf` | `eval()` with hex-encoded URL string |
| `redirect_ascii85_js.pdf` | JS stream encoded with `/Filter /ASCII85Decode` |
| `redirect_flate_compressed_js.pdf` | JS stream compressed with `/Filter /FlateDecode` (zlib) |
| `redirect_multifilter_js.pdf` | JS stream with multiple chained stream filters |

---

### PDF Redirects — Non-JavaScript Actions

These redirect without any JavaScript using native PDF action types.

| File | Action Type | Notes |
|---|---|---|
| `redirect_openaction_uri.pdf` | `/OpenAction /S /URI` | Direct URI open on document load — no JS, no click required in some readers |
| `redirect_uri_action.pdf` | `/S /URI` annotation | Clickable link annotation pointing to external URL |
| `redirect_hyperlink.pdf` | `/S /URI` hyperlink | Standard hyperlink annotation |
| `redirect_outline_uri.pdf` | `/Outlines /A /S /URI` | Bookmark/outline item with URI action — fires on bookmark click |
| `redirect_named_action.pdf` | `/S /Named /N /NextPage` chained to `/S /URI` | Uses a named navigation action chained to a URI redirect |
| `redirect_gotor.pdf` | `/S /GoToR` (Go To Remote) | Opens a remote PDF at an external URL — tested as a cross-document navigation redirect |
| `redirect_submitform.pdf` | `/S /SubmitForm` | AcroForm submit action POSTs form data to `https://example.com/collect` |
| `redirect_importdata_action.pdf` | `/S /ImportData` | Imports FDF data from an external URL — outbound HTTP request |
| `redirect_launch_action.pdf` | `/S /Launch` | Legacy launch action pointing to an external URL |

---

### PDF Redirects — Media & Rich Content

| File | Vector | Notes |
|---|---|---|
| `redirect_movie_action.pdf` | `/Subtype /Movie` with `/F /FS /URL` | Legacy movie annotation with media source at external URL |
| `redirect_sound_action.pdf` | `/S /Sound` with `/F` external URL | Sound annotation loading audio from external URL |
| `redirect_rendition_action.pdf` | `/S /Rendition` with `/MR /MCD /D /FS /URL` | Media rendition clip pointing to `https://example.com/media.mp4` |
| `redirect_richmedia_annot.pdf` | `/Subtype /RichMedia` + JS activation | RichMedia (Flash/U3D) annotation with `app.launchURL()` in activation JS |
| `redirect_xfa.pdf` | XFA (XML Forms Architecture) | JS in XFA event handlers — tests XFA-capable reader behaviour |
| `redirect_embedded_html.pdf` | Embedded HTML with `<meta http-equiv="refresh">` | HTML object embedded in PDF stream — tests HTML extraction and rendering |

---

### PDF Redirects — Structural & Parser Bypass

| File | Technique | What It Tests |
|---|---|---|
| `redirect_incremental_update.pdf` | Appended second revision adds `/OpenAction` | Validators that only parse the first PDF revision miss the appended action |
| `redirect_encrypted.pdf` | `/Encrypt` with `/S /URI` action | Tests whether security scanners can inspect encrypted PDF actions |
| `redirect_xref_stream.pdf` | `/OpenAction` JS in a PDF using `/XRef` stream (PDF 1.5+ compressed format) | Tests parsers that only handle traditional `xref` tables |
| `redirect_xmp_metadata.pdf` | URL embedded in XMP metadata stream | Tests whether metadata parsers process embedded URLs |
| `redirect_multi_link.pdf` | Multiple `/S /URI` entries with URL bypass variants | See bypass table below |

#### URL Bypass Variants (`redirect_multi_link.pdf`)

| Variant | Technique |
|---|---|
| `https://example.com` | Baseline |
| `http://example.com` | HTTP fallback |
| `https:////example.com` | Double slash — confuses parsers that split on `://` |
| `https://trusted.com@example.com` | Userinfo `@` trick — host is `example.com`, not `trusted.com` |
| `https:\\\\example.com` | Backslash — some Windows URL parsers normalise to forward slash |
| `https://example.com\x00.trusted.com` | Null byte — truncates the host in some C-string parsers |
| `https://\x09example.com` | Tab character — bypasses naive prefix checks |

---

## Trigger Summary

| Trigger Type | Files |
|---|---|
| **Passive (no interaction)** | `redirect_meta.html`, `redirect_location_*.html`, `redirect_window_location.html`, `redirect_js_openaction.pdf`, `redirect_openaction_uri.pdf`, `redirect_aa_pageopen.pdf`, `redirect_names_javascript.pdf` |
| **On specific user action** | `redirect_anchor_href.html`, `redirect_form_action.html`, `redirect_annot_aa_mouseenter.pdf`, `redirect_widget_focus.pdf`, `redirect_beforeprint_aa.pdf`, `redirect_outline_uri.pdf`, `redirect_submitform.pdf` |
| **On close/navigate away** | `redirect_aa_pageclose.pdf`, `redirect_docaa_willclose.pdf` |
| **Parser/scan evasion** | `redirect_incremental_update.pdf`, `redirect_encrypted.pdf`, `redirect_xref_stream.pdf`, `redirect_ascii85_js.pdf`, `redirect_flate_compressed_js.pdf`, `redirect_multifilter_js.pdf`, `redirect_js_eval.pdf`, `redirect_js_hex_string.pdf` |

---

## What to Test For

| Control | Passes if… |
|---|---|
| Uploaded HTML served with `Content-Disposition: attachment` | Browser downloads file rather than rendering it |
| SVG served as `image/svg+xml` restricted to `<img>` context | `onload` JS and `<script>` blocks do not execute |
| PDF JavaScript disabled | Viewer/library does not execute `/S /JavaScript` actions |
| PDF URI actions blocked | `/S /URI` and `/OpenAction /S /URI` are not followed without user confirmation |
| Non-JS PDF actions restricted | `/GoToR`, `/SubmitForm`, `/ImportData`, `/Launch`, `/Rendition` are blocked or prompted |
| Service Worker upload rejected | `.js` uploads cannot be registered as a Service Worker on the app origin |
| Content-Security-Policy enforced | `script-src` and `navigate-to` directives prevent redirect execution in HTML |
| All PDF revisions scanned | Incremental update appending an `/OpenAction` is detected |

---

## Related Sections

- [`../XSS/`](../XSS/) — Uploaded HTML/SVG that executes script rather than redirecting
- [`../SSRF/`](../SSRF/) — PDF `/ImportData`, `/Rendition`, and `/GoToR` actions making server-side requests
