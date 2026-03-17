/**
 * Hardened Rich-Text Comment Validator (OWASP-aligned)
 *
 *  - Validates innerHTML (structure) and innerText (chars) separately
 *  - DOM-based tag allow-list instead of regex tag blocking
 *  - Attribute allow-list with safe href enforcement
 *  - vbscript: added to injection patterns
 *  - on[a-z]{2,} fixes false positives on words like "one", "only"
 *  - Severity tiers: spam repetition is a warning, not a hard error
 *  - Paste sanitization strips HTML before insertion
 *
 *  - Null byte: percent-decoded before any DOM or normalisation touch
 *  - C1 control chars: checked on raw HTML, not innerText (browser strips them)
 *  - Mixed-case tags: injection patterns run on normalised lowercase copy
 *
 *  - data: URI expanded: blocks svg+xml, text/xml, xhtml+xml, not just text/html
 *  - HTML entity-encoded hrefs decoded before protocol check
 *    e.g. &#x6A;avascript: → javascript: → blocked
 *  - svg / math / embed / base injection patterns added
 *  - normalizeHtml Unicode strip expanded to full invisible/zero-width set
 *  - &#xHEX; entities now stripped in step 7 char allow-list
 *  - Raw HTML length cap (100 KB) before expensive DOM work
 *  - target attribute validated: only _blank _self _parent _top allowed
 *  - rel/target only permitted on <a> tags
 *  - sanitizePaste: execCommand use explained and guarded with optional chaining
 *  - Misplaced JSDoc block fixed
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

// Attributes allowed globally (rel/target further restricted to <a> in step 6)
const SAFE_ATTRS = new Set(['href', 'target', 'rel', 'title', 'class']);

// Valid values for target= on <a> tags
const SAFE_TARGET_VALUES = new Set(['_blank', '_self', '_parent', '_top']);

const INJECTION_PATTERNS = [
  /javascript\s*:/i,            // javascript: URLs
  /vbscript\s*:/i,              // vbscript: URLs
  /data\s*:\s*text\/html/i,     // data:text/html
  /data\s*:\s*text\/xml/i,      // data:text/xml
  /data\s*:\s*image\/svg/i,     // data:image/svg+xml — SVG can embed <script>
  /data\s*:\s*application\//i,  // data:application/xhtml+xml etc.
  /expression\s*\(/i,           // old IE CSS expression()
  /on[a-z]{2,}\s*=/i,           // onclick=, onmouseover=, onload= etc.
  /<[^>]*\bon\w+\s*=/i,         // <tag on...= (belt-and-braces)
  /<[^>]*script/i,              // <script
  /<[^>]*iframe/i,              // <iframe
  /<[^>]*object/i,              // <object
  /<[^>]*embed/i,               // <embed
  /<[^>]*svg/i,                 // <svg onload=alert(1)>
  /<[^>]*math/i,                // <math> namespace attacks
  /<[^>]*base[\s>]/i,           // <base href=...> hijacks all relative URLs
];

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Decode HTML entities in a string (named, decimal, and hex).
 * Used to normalise href values before protocol checks so that
 * &#x6A;avascript: and &#106;avascript: are both caught.
 */
const decodeHtmlEntities = (str) => {
  const el = document.createElement('textarea');
  el.innerHTML = str;
  return el.value;
};

/**
 * Normalise raw HTML before injection pattern matching.
 * Collapses common tag-splitting bypass techniques:
 *   <ScRiPt>        → handled by /i flag on patterns
 *   <scr%09ipt>     → %09 decoded to tab, then stripped
 *   <scr\x00ipt>    → null byte stripped
 *   <s\u200Bcript>  → zero-width space stripped
 *
 * IMPORTANT: this string is for pattern matching only.
 * DOM parsing always uses the original html string.
 */
const normalizeHtml = (html) =>
  html
    // 1. Decode all percent-encoded bytes
    .replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    // 2. Strip C0 + C1 control characters
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
    // 3. Strip the full set of Unicode invisible / zero-width characters:
    //    U+00AD soft-hyphen, U+180E Mongolian vowel separator,
    //    U+200B-U+200F zero-width spaces & direction marks,
    //    U+2028-U+202F line/paragraph separators & narrow no-break space,
    //    U+2060-U+2064 word joiners, U+FEFF BOM/ZWNBSP,
    //    U+FFFE-U+FFFF non-characters
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

  // ── 0. Raw pre-checks (before ANY browser normalisation or DOM parsing) ───────

  // 0a. Hard cap on raw HTML size — prevents DoS via huge DOM / querySelectorAll
  if (html.length > 102_400) {
    errors.push('Input too large (max 100 KB raw HTML)');
    return { valid: false, errors, warnings };
  }

  // 0b. Percent-decode once; run two independent checks on the result:
  //     (i)  detect the null byte itself (common WAF bypass signal)
  //     (ii) run injection patterns on the decoded string — catches the
  //          payload that trails a %00 before normalizeHtml strips \x00
  const percentDecoded = html.replace(/%([0-9a-fA-F]{2})/g, (_, h) =>
    String.fromCharCode(parseInt(h, 16)));

  if (/\x00/.test(percentDecoded))
    errors.push('Null byte detected (possible WAF bypass attempt)');

  if (INJECTION_PATTERNS.some(p => p.test(percentDecoded)))
    errors.push('Injection pattern detected in percent-decoded input');

  // 0c. C1 control characters on the raw HTML string.
  //     Browsers silently drop \x7F-\x9F from innerText, so the text-layer
  //     check in step 2 would never see them.
  if (/[\x7F-\x9F]/.test(html))
    errors.push('C1 control characters detected');

  // ── 1. Length (text layer) ───────────────────────────────────────────────────
  if (trimmedText.length < 1 || trimmedText.length > 8000)
    errors.push('Length must be 1–8000 characters');

  // ── 2. C0 control characters (text layer, second line of defence) ────────────
  // C1 is already caught above. \t \n \r are intentionally excluded.
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(trimmedText))
    errors.push('Invalid control characters detected');

  // ── 3. Spam / ReDoS guard ────────────────────────────────────────────────────
  if (/(.)\1{14,}/.test(trimmedText))
    warnings.push('Excessive character repetition (possible spam)');

  // ── 4. Injection patterns on normalised HTML ─────────────────────────────────
  const normHtml = normalizeHtml(html);
  if (INJECTION_PATTERNS.some(p => p.test(normHtml)))
    errors.push('Potentially unsafe HTML/script patterns detected');

  // ── 5. DOM-based tag allow-list ──────────────────────────────────────────────
  const tmp = document.createElement('div');
  tmp.innerHTML = html;

  const disallowedTag = [...tmp.querySelectorAll('*')]
    .find(el => !SAFE_TAGS.has(el.tagName));
  if (disallowedTag)
    errors.push(`Tag not allowed: <${disallowedTag.tagName.toLowerCase()}>`);

  // ── 6. Attribute allow-list, href + target enforcement ───────────────────────
  let attrError = null;
  tmp.querySelectorAll('*').forEach(el => {
    if (attrError) return;
    const isAnchor = el.tagName === 'A';

    Array.from(el.attributes).forEach(attr => {
      if (attrError) return;
      const name = attr.name.toLowerCase();

      // rel and target are only meaningful (and permitted) on <a>
      if ((name === 'rel' || name === 'target') && !isAnchor) {
        attrError = `Attribute "${name}" is only allowed on <a> tags`;
        return;
      }

      if (!SAFE_ATTRS.has(name)) {
        attrError = `Attribute not allowed: ${name}`;
        return;
      }

      if (name === 'href') {
        // Decode HTML entities before checking the protocol so that
        // &#x6A;avascript: and &#106;avascript: are both caught.
        const raw     = attr.value.trim();
        const decoded = decodeHtmlEntities(raw);
        const safe    = decoded === '' ||
                        decoded.startsWith('#') ||
                        /^https?:\/\//i.test(decoded);
        if (!safe)
          attrError = `Unsafe link target: ${raw.slice(0, 60)}`;
      }

      if (name === 'target') {
        if (!SAFE_TARGET_VALUES.has(attr.value.trim().toLowerCase()))
          attrError = `Unsafe target value: ${attr.value.slice(0, 20)}`;
      }
    });
  });
  if (attrError) errors.push(attrError);

  // ── 7. Character allow-list (text layer) ─────────────────────────────────────
  // Strip named, decimal, AND hex HTML entities — all are valid in rich text
  // output but would otherwise fail the Unicode property regex.
  const decodedText = trimmedText
    .replace(/&[a-z][a-z0-9]*;/gi, 'X')   // named:   &amp; &lt; &nbsp;
    .replace(/&#[0-9]+;/gi, 'X')           // decimal: &#123;
    .replace(/&#x[0-9a-f]+;/gi, 'X');      // hex:     &#x7B;  ← was missing in v3

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
 * Note: document.execCommand('insertText') is deprecated in the spec but
 * remains the only synchronous way to insert at the caret in a contenteditable.
 * The Async Clipboard API cannot replace this because it cannot target a caret
 * position within a synchronous user-gesture handler.
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