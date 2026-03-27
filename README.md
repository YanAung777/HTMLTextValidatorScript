# Comment-Validator

A hardened, OWASP-aligned client-side validator for rich-text comment fields. Defends against XSS, injection, and obfuscation attacks across 8 independent check layers — without blocking legitimate formatted content.

# ⚠️ The "Golden Rule" of WAFs
if you are trying to bypassing WAF rules, please keep in mind: Validation is not Sanitization.

Server-Side is King: An attacker can easily bypass your handleSubmit by using a tool like Postman or curl. This script is only for well-behaved users.  Implement with server-side sanitization layer using a library like DOMPurify.

Output Encoding: The most important OWASP rule is to encode on output. Even if a user "bypasses" this regex and saves <script>, it only becomes dangerous if your website renders it as HTML.

Safe: element.textContent = userComment;
Unsafe: element.innerHTML = userComment;

# The Defense-in-Depth Lifecycle
In a professional cloud architecture, sanitization is one part of a multi-stage funnel.

Client-Side (User Interface): This JavaScript provides immediate feedback to the user and catches of accidental or low-effort "script-kiddie" attacks.

Edge/WAF (Azure/CloudFlare): The Web Application Firewall inspects the HTTP request for common OWASP patterns (SQLi, XSS) before it even reaches backend APIs.

Server-Side (DOMPurify): The final "Gatekeeper." It parses the actual HTML structure and ensures it matches your specific business rules (e.g., "We only allow bold and links").

## Files

| File | Purpose |
|---|---|
| `HTMLSanitiser.js` |Normalises browser-injected markup before the validator sees it. |
| `validatecomment.js` | Core validator module v4.1 — import this into your project |
| `ValidatorUI.HTML` | Interactive test UI — open in a browser to test payloads live |
| `CalidatorTest.HTML` | Automated test suite — 20 attack cases with pass/fail reporting |

https://www.npmjs.com/package/dompurify
---

## Quick Start

```js
import { validatecomment, sanitizePaste } from './validatecomment.js';

const editor = document.getElementById('my-editor');

// Validate on input
editor.addEventListener('input', () => {
  const result = validatecomment({
    html: editor.innerHTML,   // raw innerHTML — for structural checks
    text: editor.innerText,   // plain text   — for length and char checks
  });

  if (!result.valid) {
    console.log('Blocked:', result.errors);
  }
  if (result.warnings.length) {
    console.log('Warnings:', result.warnings);
  }
});

// Strip HTML from paste (plain text only)
editor.addEventListener('paste', sanitizePaste);
```

### Return value

```ts
{
  valid:    boolean,   // false if any hard error fired
  errors:   string[],  // reasons for rejection (empty if valid)
  warnings: string[],  // non-blocking flags (e.g. spam repetition)
}
```

A comment is safe to submit when `valid === true`. Warnings do not block submission but should be surfaced to a moderation layer.

---

## What It Validates

### Allowed HTML

Safe rich-text formatting is explicitly allowed. Everything else is blocked.

**Tags:** `<b>` `<i>` `<u>` `<em>` `<strong>` `<a>` `<ul>` `<ol>` `<li>` `<p>` `<br>` `<span>` `<div>`

**Attributes:** `href` `target` `rel` `title` `class`

- `rel` and `target` are only permitted on `<a>` tags
- `target` must be one of `_blank` `_self` `_parent` `_top`
- `href` must be empty, a fragment (`#`), or an `https?://` URL — after HTML entity decoding

### Check Layers

The validator runs 8 independent layers in order. An input must pass all of them.

| # | Layer | What it catches |
|---|---|---|
| 0a | **Size cap** | Raw HTML over 100 KB (DoS prevention) |
| 0b | **Null byte** | `%00` decoded before DOM touch — WAF bypass attempts |
| 0b | **Injection (decoded)** | Patterns matched on percent-decoded string |
| 0c | **C1 control chars** | `\x7F`–`\x9F` on raw HTML (browser strips from `innerText`) |
| 1 | **Length** | Text shorter than 1 or longer than 8,000 characters |
| 2 | **C0 control chars** | `\x00`–`\x1F` on text layer (second line of defence) |
| 3 | **Spam / ReDoS** | 15+ identical consecutive characters _(warning, not hard error)_ |
| 4 | **Injection patterns** | 16 patterns on normalised HTML (decoded, control-chars stripped, zero-width chars stripped) |
| 5 | **Tag allow-list** | Any tag not in the safe set |
| 6 | **Attribute allow-list** | Any attribute not in the safe set; unsafe `href` protocols; invalid `target` values |
| 7 | **Character allow-list** | Any character outside Unicode letters, numbers, punctuation, symbols, separators, and emoji |

---

## Attack Coverage

### Filter Bypasser

| Payload | Blocked by |
|---|---|
| `<img src=x onerror=alert(1)>` | Tag allow-list (`img`), attribute allow-list (`onerror`) |
| `<a href="javascript:alert(1)">` | `href` protocol check |
| `<ScRiPt>alert(1)</ScRiPt>` | Injection pattern on normalised HTML + tag allow-list |
| `<a href="data:text/html;base64,...">` | `data:text/html` injection pattern + unsafe `href` |
| `<a href="data:image/svg+xml,...">` | `data:image/svg` injection pattern |
| `<a href="&#x6A;avascript:alert(1)">` | `href` decoded via `decodeHtmlEntities()` before protocol check |
| `<a href="&#106;avascript:alert(1)">` | Same — decimal entity variant |
| `<svg onload=alert(1)>` | `<svg>` injection pattern + `onload` attribute check |
| `<base href="https://evil.com/">` | `<base>` injection pattern |
| `<embed src="...">` | `<embed>` injection pattern + tag allow-list |
| `<a target="evil">` | `target` value not in safe set |
| `<span rel="noopener">` | `rel` only permitted on `<a>` |

### Structural Attack

| Payload | Blocked by |
|---|---|
| `Hello%00<script>alert(1)</script>` | Null byte detected (step 0b); script pattern on decoded string |
| `Hidden\x9CControl\x9DChars` | C1 control character check on raw HTML (step 0c) |
| `Aaaaaaaaaaaaaaa...` (15+ repeats) | Spam warning (step 3) — not a hard block |

---

## What It Does Not Cover

**SQL injection** — this is a client-side HTML validator. SQL injection must be prevented server-side with parameterised queries. Client-side validation can always be bypassed by sending raw HTTP requests directly to your API.

```js
// Correct defence for SQL injection — parameterised query
db.query('INSERT INTO comments (body) VALUES (?)', [commentText]);
```

**Server-side XSS** — this validator runs in the browser. You must also sanitise HTML server-side before storing or rendering it. Use a library like [DOMPurify](https://github.com/cure53/DOMPurify) or [sanitize-html]([https://github.com/apostrophecms/sanitize-html](https://github.com/apostrophecms/apostrophe/tree/main/packages/sanitize-html)]) on the server.

**https://wiki.sei.cmu.edu/confluence/spaces/java/pages/88487713/IDS00-J.+Prevent+SQL+injection

**Authentication / authorisation** — out of scope.

**Rate limiting / spam at scale** — the spam repetition check is a basic signal only. For production moderation use a dedicated service.

---

## Browser Compatibility

Requires a browser that supports:

- `Unicode property escapes` in regex (`/\p{L}/u`) — Chrome 64+, Firefox 78+, Safari 11.1+, Edge 79+
- `contentEditable` — all modern browsers
- `document.execCommand` (paste sanitiser) — deprecated in spec but supported in all current browsers; no alternative exists for synchronous caret insertion

---

## Integration Notes

### Editor HTML Sanitiser (UI layer)

Before passing `editor.innerHTML` to `validatecomment`, strip browser-injected markup. Different browsers produce different output from `execCommand`:

| Browser | Bold output | Problem |
|---|---|---|
| Chrome | `<span style="font-weight:bold">` | `style=` not in `SAFE_ATTRS` |
| Safari | `<b style="font-weight:bold">` | Same |
| Firefox | `<b>` | Fine |

The test UI (`validator-ui.html`) includes a `sanitiseEditorHtml()` function that handles this. Copy it into your own editor layer:

```js
function sanitiseEditorHtml(html) {
  const tmp = document.createElement('div');
  tmp.innerHTML = html;

  // Map legacy tags to semantic equivalents
  const TAG_MAP = { STRIKE:'S', DEL:'S', FONT:'SPAN', BOLD:'B', ITALIC:'I', TT:'CODE' };
  [...tmp.querySelectorAll('strike,del,font,bold,italic,tt')].forEach(el => {
    const repl = document.createElement(TAG_MAP[el.tagName] || 'SPAN');
    repl.innerHTML = el.innerHTML;
    el.replaceWith(repl);
  });

  // Strip all attributes not in the safe set
  tmp.querySelectorAll('*').forEach(el => {
    const isAnchor = el.tagName === 'A';
    [...el.attributes].forEach(attr => {
      const n = attr.name.toLowerCase();
      if (!SAFE_ATTRS.has(n) || ((n==='rel'||n==='target') && !isAnchor))
        el.removeAttribute(attr.name);
    });
  });

  return tmp.innerHTML;
}
```

Pass the sanitised output to `validatecomment`, but run threat-detection rules (null byte, C1 chars) on the **raw** `editor.innerHTML` before sanitisation — the sanitiser strips the evidence.

### Server-Side Pairing

Always re-validate and sanitise on the server. Recommended libraries:

- **Node.js:** [DOMPurify](https://github.com/cure53/DOMPurify) with jsdom, or [sanitize-html](https://github.com/apostrophecms/sanitize-html)
- **Python:** [bleach](https://github.com/mozilla/bleach)
- **PHP:** [HTML Purifier](http://htmlpurifier.org/)

---

## Customising

### Change max length

```js
// In validatecomment.js, step 1
if (trimmedText.length < 1 || trimmedText.length > 8000)
//                                                  ^^^^  change this
```

### Add allowed tags

```js
const SAFE_TAGS = new Set([
  'B', 'I', 'U', 'EM', 'STRONG',
  'A', 'UL', 'OL', 'LI',
  'P', 'BR', 'SPAN', 'DIV',
  'BLOCKQUOTE', 'CODE', 'PRE',  // ← add here
]);
```

### Make spam a hard error

```js
// In step 3 — change warnings.push to errors.push
if (/(.)\1{14,}/.test(trimmedText))
  errors.push('Excessive character repetition');  // was warnings.push
```

### Allow relative URLs in href

```js
// In step 6 — add || decoded.startsWith('/')
const safe = decoded === '' ||
             decoded.startsWith('#') ||
             decoded.startsWith('/') ||   // ← add this
             /^https?:\/\//i.test(decoded);
```

---

## Changelog

### v4.1 (current)
- `formaction=` added to injection patterns — catches `<button formaction="javascript:...">` HTML5 form hijack
- `data:` URI patterns consolidated — same coverage with fewer regex entries
- `ALLOWED_PROTOCOLS` constant: `mailto:` and `tel:` now permitted in `href` values
- Relative paths (`/path`) now explicitly allowed in `href`; protocol-relative (`//evil.com`) explicitly blocked
- `decodeEntities` rewritten without DOM dependency — now works in Node.js, Workers, and SSR environments
- `normalizeHtml` was defined but not called in v4 — fixed, invisible Unicode tag-splitting now caught again
- Size cap moved before percent-decode — avoids decoding oversized payloads
- `data:` URI patterns expanded: `image/svg`, `text/xml`, `application/*` added
- HTML entity-encoded `href` values decoded before protocol check (`&#x6A;avascript:` now caught)
- `<svg>`, `<math>`, `<embed>`, `<base>` added to injection patterns
- `normalizeHtml` Unicode strip expanded to full invisible/zero-width character set
- `&#xHEX;` entities stripped in character allow-list check (was missing)
- Raw HTML size cap added (100 KB) before DOM parsing
- `target` attribute validated against safe value set
- `rel` and `target` restricted to `<a>` tags only

### v3
- Null byte injection: `%00` percent-decoded before DOM touch
- C1 control characters checked on raw HTML (browser strips from `innerText`)
- Mixed-case tag bypass: injection patterns tested on lowercased copy

### v2
- `innerHTML` and `innerText` validated separately (rich-text aware)
- DOM-based tag allow-list replaces regex tag blocking
- Attribute allow-list with `href` protocol enforcement
- `vbscript:` added to injection patterns
- `on[a-z]{2,}` regex fix eliminates false positives on words like "only"
- Spam repetition demoted to warning tier
- Paste sanitiser strips HTML on input

### v1
- Initial OWASP-aligned plain-text validator

---

## Security Disclaimer

**This library is provided as a client-side defence layer only. Use it at your own risk.**

Client-side validation is a convenience and usability measure — it is not a security boundary. Any attacker can bypass browser-side code by sending HTTP requests directly to your server, disabling JavaScript, or manipulating the DOM. This validator should always be paired with equivalent server-side sanitisation before storing or rendering user content.

Specifically:

- **This library does not guarantee protection** against all XSS, injection, or obfuscation attacks. Attack techniques evolve continuously and no client-side filter can be considered exhaustive.
- **This library does not protect against SQL injection.** Use parameterised queries on your server. See the Integration Notes section.
- **The maintainers accept no liability** for security breaches, data loss, or damages arising from the use or misuse of this library, whether or not the library was used as documented.
- **Do not rely solely on this library** for compliance with GDPR, PCI-DSS, HIPAA, or any other regulatory framework that requires data security controls. Regulatory compliance requires a defence-in-depth strategy implemented at multiple layers of your stack.
- **No warranty is provided**, expressed or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

This library is designed to reduce risk and improve the user experience of comment moderation. It is one layer in a defence-in-depth strategy — not a replacement for one.

---

## Open Source

This project is released under the **MIT Licence**. See the full licence text below.

### What this means

You are free to:
- Use this library in personal, commercial, and open-source projects
- Modify, adapt, and build upon the source code
- Distribute original or modified versions
- Include it in proprietary software without requiring your code to be open-sourced

You must:
- Include the original copyright notice and licence text in any distributed copy or substantial portion of the code

You may not:
- Hold the maintainers liable for damages arising from use of this software
- Use the maintainers' names or project name to endorse or promote derived products without permission

### Contributing

Contributions are welcome. By submitting a pull request or issue you agree that your contribution will be licensed under the same MIT licence as this project. Please:

- Open an issue before submitting large changes so the approach can be discussed
- Keep pull requests focused — one fix or feature per PR
- Include a test case in `validator.test.html` for any new attack vector or behaviour change
- Update the changelog in `README.md` and the JSDoc header in `validatecomment.js`

### Security Vulnerabilities

If you discover a security vulnerability in this library, **please do not open a public issue**.

Instead, report it privately by emailing the maintainer directly (see repository contact details) or using GitHub's private vulnerability reporting feature if enabled on the repository. Please include:

- A description of the vulnerability and the attack vector it enables
- A proof-of-concept payload that demonstrates the bypass
- The version(s) of the library affected

We aim to acknowledge reports within 72 hours and publish a fix within 14 days of confirmation. Credit will be given in the changelog unless you prefer to remain anonymous.

---

## Licence Text

```
MIT License

Copyright (c) 2025 comment-validator contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
