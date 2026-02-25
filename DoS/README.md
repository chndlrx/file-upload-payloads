# DoS Payloads

Payloads for testing **Denial of Service vulnerabilities** in file upload handlers and document parsers. These test whether an application enforces limits on decompression ratio, recursion depth, parse complexity, and disk/memory usage before processing uploaded content.

---

## Attack Surface

DoS via file upload occurs when an application:
- Decompresses archives without checking the output size (decompression bomb)
- Parses recursive or deeply nested data structures without depth limits (parser bomb)
- Passes uploaded content to a document processing library that expands it in memory
- Extracts archives to disk without checking total extracted size or path depth

---

## Payload Index

### Zip Bombs

| File | Compressed | Uncompressed | Technique |
|---|---|---|---|
| `zipbomb_1gb.zip` | 1.0 MB | **1.0 GB** | Flat — single file of zeroes |
| `zipbomb_10gb.zip` | 10 MB | **10.0 GB** | Flat — single file of zeroes |
| `zipbomb_nested_42style.zip` | 21 KB | ~1 GB+ (recursive) | Nested — 42.zip-style recursive layers |
| `zipbomb_nested_5layer.zip` | 11 KB | ~512 MB (recursive) | Nested — 5 layers of zips-in-zips |
| `zipbomb_overlapping_1k.zip` | 67 KB | **9.8 GB** | Overlapping entries — 1,000 files sharing compressed data |
| `zipbomb_overlapping_10k.zip` | 667 KB | **976.6 GB** | Overlapping entries — 10,000 files sharing compressed data |
| `zipbomb_selfreference.zip` | 314 B | N/A | Self-referential — contains itself (`self.zip`) |
| `zipbomb_zip64_petabyte.zip` | **255 B** | Petabyte-scale (zip64 header) | Zip64 extended info manipulation — advertises massive size |
| `zipbomb_polyglot.pdf` | 10 MB | ~1 GB+ | Polyglot — valid PDF header + valid zip bomb |
| `zipbomb_polyglot.png` | 10 MB | ~1 GB+ | Polyglot — valid PNG header + valid zip bomb |
| `zipslip_bomb.zip` | 2.5 MB | **2.4 GB** | Zip Slip — path traversal entries writing to `../../tmp/` and `../../../etc/cron.d/` |

**Techniques:**
- **Flat**: A single large file of repeated bytes compresses extremely well. Tests naive size checks.
- **Overlapping entries**: Many central directory entries point to the same compressed data block, multiplying the apparent decompressed size. Evades checks on entry count.
- **Nested**: Zips containing zips — each layer multiplies size. Triggers recursion in extractors that auto-open nested archives.
- **Zip64**: The zip64 extended information header allows reporting a file size far larger than 4 GB. Tests whether size is validated before decompression begins.
- **Polyglot**: The file passes MIME/magic-byte validation as a PDF or PNG while also being a valid zip archive.

---

### Tar Bombs

| File | Format | Entries | Uncompressed | Notes |
|---|---|---|---|---|
| `tarbomb.tar.gz` | gzip | 100 files | **4.88 GB** | 100 × 50 MB files |
| `tarbomb.tar.bz2` | bzip2 | 100 files | **4.88 GB** | Same contents, bzip2-compressed |
| `tarbomb.tar.xz` | xz | 50 files | **4.88 GB** | 50 × 100 MB files |
| `tarbomb_deeppath.tar.gz` | gzip | 10 files | **~1 GB** | Each file nested 200 directories deep — exhausts path-length limits and inode counts |

---

### Gzip / Bzip2 Bombs

| File | Compressed | Target Uncompressed | Notes |
|---|---|---|---|
| `bomb.gz` | 1.0 MB | ~1 GB | Standard gzip bomb |
| `bomb_10gb.gz` | 10 MB | **~10 GB** | Large gzip bomb |
| `bomb.bz2` | **785 B** | ~1 GB | Extremely efficient — bzip2 achieves ~1,300,000:1 ratio |
| `bomb_10gb.bz2` | **7.5 KB** | **~10 GB** | ~1,400,000:1 compression ratio |

> `bomb.bz2` at 785 bytes is the most efficient payload in this collection. Bzip2's BWT algorithm compresses runs of identical bytes far better than deflate.

---

### XML Parser Bombs

| File | Size | Technique | Impact |
|---|---|---|---|
| `xmlbomb_billion_laughs.xml` | 731 B | Exponential entity expansion — 9 levels of `&lolN;` entities, each expanding 10× | ~1 GB in memory when parsed; CPU spike |
| `xmlbomb_quadratic.xml` | 196 KB | Quadratic blowup — large entity string referenced thousands of times | O(n²) memory growth |

The **Billion Laughs** attack (`xmlbomb_billion_laughs.xml`) uses chained DTD entity references:
- `&lol9;` → 10× `&lol8;` → 10× `&lol7;` → … → `"lol"`
- 9 levels × 10 expansions = 10⁹ copies of `"lol"` ≈ 3 GB in memory

**Affected parsers:** any XML library that expands external/internal entities without limits (libxml2 without `XML_PARSE_NOENT` restrictions, Python's built-in `xml.etree`, Java's JAXP without `FEATURE_SECURE_PROCESSING`).

---

### YAML Bomb

| File | Size | Technique |
|---|---|---|
| `yamlbomb.yaml` | 339 B | Anchor/alias exponential expansion — 9 levels, each node references 9 aliases |

Uses YAML anchors (`&a`) and aliases (`*a`) to build an exponentially growing structure, identical in principle to Billion Laughs. 9 levels of 9-way aliasing = 9⁹ ≈ 387 million leaf nodes.

**Affected parsers:** PyYAML, SnakeYAML, and any YAML library that resolves aliases without an alias depth or node count limit.

---

### JSON Bomb

| File | Size | Technique |
|---|---|---|
| `jsonbomb_nested.json` | 200 KB | Deeply nested arrays/objects — exhausts parser stack depth and triggers O(n) heap allocations per level |

Tests parsers that recurse on object/array nesting without a depth limit. Effective against `JSON.parse` in older Node.js versions and Java's `org.json`.

---

### Spreadsheet / Document Bombs

| File | Compressed | Technique |
|---|---|---|
| `xlsx_bomb.xlsx` | 2.0 MB | Shared strings XML with millions of references — spreadsheet parsers expand on load |
| `docx_bomb.docx` | 2.0 MB | Repeated content blocks in `word/document.xml` — expands significantly on render/parse |
| `csvbomb_columns.csv` | 1.9 MB | Extreme column count — triggers O(n) header allocation in CSV parsers and spreadsheet importers |

XLSX and DOCX are zip archives containing XML. A small compressed file can contain a `sharedStrings.xml` with millions of entries, exhausting heap when a library loads the document into a DOM model.

---

### Content-Type Confusion

| File | Extension | Actual Content | Tests |
|---|---|---|---|
| `txt.png` | `.png` | Plain text | Whether MIME sniffing or magic-byte validation is enforced; whether a text file accepted as an image causes downstream parser errors |

---

## Detection Bypass Notes

- **Polyglot zips** (`zipbomb_polyglot.pdf`, `zipbomb_polyglot.png`) pass magic-byte checks and MIME type detection as their declared type. The zip structure is only revealed when the file is decompressed.
- **Overlapping-entry bombs** (`zipbomb_overlapping_1k.zip`, `zipbomb_overlapping_10k.zip`) show a normal file count in the central directory, so entry-count limits do not catch them. Only a decompression ratio check will.
- **Zip64** (`zipbomb_zip64_petabyte.zip`) at 255 bytes will not trigger upload size limits but advertises a massive uncompressed size in its headers.

---

## What to Test For

| Control | Passes if… |
|---|---|
| Decompression ratio limit | Server rejects archives with uncompressed/compressed ratio above threshold (e.g. 100:1) |
| Max uncompressed size | Server rejects archives whose total uncompressed size exceeds a configured limit |
| Recursion depth limit | Server refuses to extract archives nested more than N levels |
| XML entity expansion limit | Parser throws on entity expansion exceeding a node/memory budget |
| YAML alias depth limit | Parser throws on alias depth or node count exceeding a limit |
| Archive path validation | Zip Slip entries with `../` paths are rejected before extraction |
| Path depth limit | Entries with 200+ directory levels are rejected |

---

## Related Sections

- [`../File Name Injection/`](../File%20Name%20Injection/) — Path traversal filenames; combine with `zipslip_bomb.zip` technique
- [`../Content Overwrite/`](../Content%20Overwrite/) — Follow-up payloads if zip slip extraction succeeds
