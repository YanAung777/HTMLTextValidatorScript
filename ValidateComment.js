/**
 * Hardened Rich-Text Comment Validator (OWASP-aligned)
 *
 * v1 → v2
 *  - Validates innerHTML (structure) and innerText (chars) separately
 *  - DOM-based tag allow-list instead of regex tag blocking
 *  - Attribute allow-list with safe href enforcement
 *  - vbscript: added to injection patterns
 *  - on[a-z]{2,} fixes false positives on words like "one", "only"
 *  - Severity tiers: spam repetition is a warning, not a hard error
 *  - Paste sanitization strips HTML before insertion
 *
 * v2 → v3
 *  - Null byte: percent-decoded before any DOM or normalisation touch
 *  - C1 control chars: checked on raw HTML, not innerText (browser strips them)
 *  - Mixed-case tags: injection patterns run on normalised copy
 *
 * v3 → v4
 *  - data: URI expanded: svg+xml, text/xml, xhtml+xml blocked
 *  - HTML entity-encoded hrefs decoded before protocol check
 *  - svg / math / embed / base injection patterns added
 *  - normalizeHtml Unicode strip expanded to full invisible/zero-width set
 *  - &#xHEX; entities stripped in char allow-list check
 *  - Raw HTML size cap (100 KB) before DOM work
 *  - target attribute validated; rel/target restricted to <a>
 *
 * v4 → v4.1 (this version)
 *  - formaction= added to injection patterns (HTML5 form hijack vector)
 *  - data: URI patterns consolidated (fewer regexes, same coverage)
 *  - ALLOWED_PROTOCOLS constant: mailto: and tel: now permitted in href
 *  - Relative paths (/) now permitted in href
 *  - Protocol-relative URLs (//evil.com) explicitly blocked
 *  - decodeEntities rewritten without DOM dependency — works in Node/SSR
 *  - normalizeHtml now correctly called for injection pattern check (was missing)
 *  - Size cap moved before percent-decode (avoids decoding oversized payloads)
 *
 * Usage:
 *   const result = validateComment({ html: editor.innerHTML, text: editor.innerText });
 *   // result: { valid: boolean, errors: string[], warnings: string[] }
 */

// ── Constants ──────────────────────────────────────────────────────────────────

const SAFE_TAGS = new Set([
  'B', 'I', 'U', 'EM', 'STRONG',
  'A', 'UL', 'OL', 'LI',
  'P', 'BR', 'SPAN', 'DIV',
]);

const SAFE_ATTRS = new Set(['href', 'target', 'rel', 'title', 'class']);

const SAFE_TARGET_VALUES = new Set(['_blank', '_self', '_parent', '_top']);

// Protocols explicitly permitted in href values.
// mailto: and tel: are legitimate in comment links.
// https?:// is handled separately. Protocol-relative (//host) is blocked.
const ALLOWED_PROTOCOLS = /^(https?|mailto|tel):/i;

const INJECTION_PATTERNS = [
  /javascript\s*:/i,                    // javascript: URLs
  /vbscript\s*:/i,                      // vbscript: URLs
  /data\s*:\s*text\/(html|xml)/i,       // data:text/html, data:text/xml
  /data\s*:\s*(image\/svg|application\/)/i, // data:image/svg+xml, data:application/*
  /expression\s*\(/i,                   // old IE CSS expression()
  /on[a-z]{2,}\s*=/i,                   // onclick=, onmouseover=, onload= etc.
  /<[^>]*\bon\w+\s*=/i,                 // <tag on...= (belt-and-braces)
  /<[^>]*script/i,                      // <script
  /<[^>]*iframe/i,                      // <iframe
  /<[^>]*object/i,                      // <object
  /<[^>]*embed/i,                       // <embed
  /<[^>]*svg/i,                         // <svg onload=...>
  /<[^>]*math/i,                        // <math> namespace attacks
  /<[^>]*base[\s>]/i,                   // <base href=...> hijacks relative URLs
  /formaction\s*=/i,                    // <button formaction="javascript:...">
];

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Decode numeric HTML entities without any DOM dependency.
 * Handles: decimal &#123; and hex &#x7B;
 * Named entities (&amp; &lt; etc.) are intentionally left as-is —
 * they cannot encode protocol characters so are irrelevant to href validation,
 * and leaving them literal avoids false decoding of safe text.
 *
 * Works in Node.js, Workers, SSR, and browser environments.
 */
const decodeEntities = (s) =>
  s.replace(/&#(x[0-9a-f]+|[0-9]+);/gi, (_, code) => {
    const n = code.startsWith('x') || code.startsWith('X')
      ? parseInt(code.slice(1), 16)
      : parseInt(code, 10);
    return (n > 0 && n < 0x110000) ? String.fromCharCode(n) : '';
  });

/**
 * Normalise raw HTML before injection pattern matching.
 * Collapses common tag-splitting bypass techniques:
 *   <ScRiPt>        → handled by /i flag on patterns
 *   <scr%09ipt>     → tab decoded + stripped
 *   <scr\x00ipt>    → null byte stripped
 *   <s\u200Bcript>  → zero-width space stripped
 *
 * IMPORTANT: only used for pattern matching, never for DOM parsing.
 */
const normalizeHtml = (html) =>
  html
    .replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
    .replace(/[\u00AD\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2064\uFEFF\uFFFE\uFFFF]/g, '');

// ── Validator ──────────────────────────────────────────────────────────────────

/**
 * @param {{ html: string, text: string }} input
 *   html — raw innerHTML from the contenteditable element
 *   text — innerText (plain text) from the same element
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
const validateComment = ({ html, text }) => {
  const trimmedText = (text || '').trim();
  const errors   = [];
  const warnings = [];

  // ── 0. Raw pre-checks (before ANY normalisation or DOM parsing) ───────────────

  // 0a. Size cap first — avoids decoding or parsing oversized payloads
  if (html.length > 102_400) {
    errors.push('Input too large (max 100 KB raw HTML)');
    return { valid: false, errors, warnings };
  }

  // 0b. Percent-decode once for two independent threat checks:
  //     (i)  null byte detection — common WAF bypass signal
  //     (ii) injection patterns on the decoded string — catches <script>
  //          that follows a %00 before normalizeHtml strips \x00
  const percentDecoded = html.replace(
    /%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))
  );

  if (/\x00/.test(percentDecoded))
    errors.push('Null byte detected (possible WAF bypass attempt)');

  if (INJECTION_PATTERNS.some(p => p.test(percentDecoded)))
    errors.push('Injection pattern detected in percent-decoded input');

  // 0c. C1 control characters on the raw HTML string.
  //     Browsers silently drop \x7F–\x9F from innerText — must check raw HTML.
  if (/[\x7F-\x9F]/.test(html))
    errors.push('C1 control characters detected');

  // ── 1. Length (text layer) ───────────────────────────────────────────────────
  if (trimmedText.length < 1 || trimmedText.length > 8000)
    errors.push('Length must be 1–8000 characters');

  // ── 2. C0 control characters (text layer, second line of defence) ────────────
  // C1 caught above. \t \n \r intentionally excluded.
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(trimmedText))
    errors.push('Invalid control characters detected');

  // ── 3. Spam / ReDoS guard ────────────────────────────────────────────────────
  if (/(.)\1{14,}/.test(trimmedText))
    warnings.push('Excessive character repetition (possible spam)');

  // ── 4. Injection patterns on normalised HTML ─────────────────────────────────
  // normalizeHtml decodes %xx, strips control chars AND invisible Unicode —
  // collapsing tag-splitting tricks like <s\u200Bcript> before matching.
  if (INJECTION_PATTERNS.some(p => p.test(normalizeHtml(html))))
    errors.push('Potentially unsafe HTML/script patterns detected');

  // ── 5. DOM-based tag allow-list ──────────────────────────────────────────────
  const tmp = document.createElement('div');
  tmp.innerHTML = html;

  const disallowedTag = [...tmp.querySelectorAll('*')]
    .find(el => !SAFE_TAGS.has(el.tagName));
  if (disallowedTag)
    errors.push(`Tag not allowed: <${disallowedTag.tagName.toLowerCase()}>`);

  // ── 6. Attribute allow-list + href / target enforcement ──────────────────────
  let attrError = null;
  tmp.querySelectorAll('*').forEach(el => {
    if (attrError) return;
    const isAnchor = el.tagName === 'A';

    Array.from(el.attributes).forEach(attr => {
      if (attrError) return;
      const name = attr.name.toLowerCase();

      // rel and target only permitted on <a>
      if ((name === 'rel' || name === 'target') && !isAnchor) {
        attrError = `Attribute "${name}" is only allowed on <a> tags`;
        return;
      }

      if (!SAFE_ATTRS.has(name)) {
        attrError = `Attribute not allowed: ${name}`;
        return;
      }

      if (name === 'href') {
        const raw     = attr.value.trim();
        const decoded = decodeEntities(raw);

        const safe =
          decoded === '' ||
          decoded.startsWith('#') ||
          // Relative paths allowed; protocol-relative (//host) blocked
          (decoded.startsWith('/') && !decoded.startsWith('//')) ||
          ALLOWED_PROTOCOLS.test(decoded);

        if (!safe)
          attrError = `Unsafe or disallowed link target: ${raw.slice(0, 60)}`;
      }

      if (name === 'target') {
        if (!SAFE_TARGET_VALUES.has(attr.value.trim().toLowerCase()))
          attrError = `Unsafe target value: ${attr.value.slice(0, 20)}`;
      }
    });
  });
  if (attrError) errors.push(attrError);

  // ── 7. Character allow-list (text layer) ─────────────────────────────────────
  // Strip named, decimal, and hex entities before testing — all valid in rich text.
  const decodedText = trimmedText
    .replace(/&[a-z][a-z0-9]*;/gi, 'X')
    .replace(/&#[0-9]+;/gi, 'X')
    .replace(/&#x[0-9a-f]+;/gi, 'X');

  const safeChars = /^[\p{L}\p{N}\p{P}\p{S}\p{Z}\p{Emoji_Presentation}\n\r\t\s]*$/u;
  if (!safeChars.test(decodedText))
    errors.push('Unsupported or unsafe characters detected');

  return { valid: errors.length === 0, errors, warnings };
};

// ── Paste sanitizer ───────────────────────────────────────────────────────────

/**
 * Strip all HTML from pasted content, inserting plain text at the caret.
 * Attach to the contenteditable element's 'paste' event.
 *
 * Note: document.execCommand('insertText') is deprecated but remains the only
 * synchronous way to insert at the caret in a contenteditable. The Async
 * Clipboard API cannot target a caret position in a synchronous event handler.
 *
 * Usage:
 *   editor.addEventListener('paste', sanitizePaste);
 */
const sanitizePaste = (e) => {
  e.preventDefault();
  const plain = e.clipboardData?.getData('text/plain') ?? '';
  if (plain) document.execCommand('insertText', false, plain);
};

export { validateComment, sanitizePaste };
