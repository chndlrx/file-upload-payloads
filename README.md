# File Upload Security Testing Toolkit

A collection of payloads, proof-of-concept files, and test vectors for assessing file upload vulnerabilities in web applications. Organized by attack category for systematic penetration testing and security research.

> **For authorized security testing only.** Only use these payloads against systems you own or have explicit written permission to test.

---

## Contents

| Category | Description |
|----------|-------------|
| [Content Overwrite](./Content%20Overwrite/) | Files targeting critical server configs (`.htaccess`, `php.ini`, `nginx.conf`, cron, sudoers, SSH keys, etc.) |
| [DoS](./DoS/) | Compression bombs (zip, tar, bz2, gz, xz), CSV/JSON/YAML/XML bombs, and ZIP slip payloads |
| [EICAR](./EICAR/) | Standard AV test files to verify antivirus and endpoint protection are active |
| [File Name Injection](./File%20Name%20Injection/) | Filename fuzzing wordlists covering path traversal, XSS, SSTI, OS command injection, SQLi, SSRF, and CRLF |
| [Formula Injection](./Formula%20Injection/) | CSV/XLSX spreadsheet injection payloads (DDE, data exfiltration) targeting Excel and Google Sheets |
| [Open Redirect](./Open%20Redirect/) | Redirect payloads embedded in HTML, PDF, SVG, XML, JS, WASM, and Electron file types |
| [SSRF](./SSRF/) | SVG-based SSRF payloads using various XML attributes to trigger internal requests |
| [SSTI](./SSTI/) | Server-Side Template Injection files demonstrating code execution via template rendering |
| [Test](./Test/) | Hundreds of files across a wide range of extensions and MIME types for basic upload filter testing |
| [Web Shells](./Web%20Shells/) | Web shell payloads in PHP, ASP, ASPX, JSP, CFM, Perl, Python, Ruby, and WordPress |
| [XSS](./XSS/) | XSS test files across HTML, PDF, SVG, XML, CSS, JS, and RSS |
| [XXE](./XXE/) | XXE payloads in XML, DOCX, XLSX, ODT, and SVG; covers OOB exfiltration, billion laughs, SSRF chaining |

---

## Usage Tips

- **Filename fuzzing:** For payloads in the `File Name Injection` folder, fuzz the filename parameter while uploading a single valid file. Storing files with special characters or path separators on the filesystem can cause issues — fuzzing the parameter avoids this. Files are still included in case you don't want to listen to me.
- **Start with `Test/`** to quickly map which file types and extensions are accepted before moving to targeted attack payloads.
- **File Handling:** Be sure to see if there are variations in client and server side controls when handling file extensions, file contents, content type, and file size.
---

## Contributing

Contributions are welcome! This toolkit grows more useful with broader coverage of file formats, bypass techniques, and edge cases.

**Ways to contribute:**

- Add new payloads or file formats to an existing category
- Add a new attack category with a brief `README.md` explaining its purpose
- Improve existing payloads with additional encoding/obfuscation variants
- Fix broken or outdated payloads
- Improve documentation

**To contribute:**

1. Fork the repository
2. Create a branch: `git checkout -b add/your-category-or-fix`
3. Add your files and update this README if needed
4. Open a pull request with a clear description of what was added and why

---

## Great Resources

There are several fantastic resources you can review for file upload testing. Some of my favorites are listed below:
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md
- https://portswigger.net/web-security/file-upload
- https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html