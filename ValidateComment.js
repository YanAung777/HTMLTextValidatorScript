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
 * v4.1 → v4.2
 * - Added explicit block on xlink:href (legacy SVG vector)
 * - Added SVG animation elements to injection patterns:
 *   animate, set, animateMotion, animateTransform
 * - Expanded data: URI patterns for extra coverage of common dangerous subtypes
 * - Minor pattern list formatting / comments cleanup

 * v4.3 → v4.4
 * - Added more SVG-related dangerous elements to injection patterns:
 *   symbol, marker, filter, clipPath, mask, defs, linearGradient, radialGradient
 *   (these can facilitate referencing, reuse, filtering, or resource-loading attacks)
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

// Allowed protocols in href.
// mailto: and tel: are legitimate. Relative paths and fragments allowed.
// Protocol-relative URLs (//evil.com) blocked separately.
const ALLOWED_PROTOCOLS = /^(https?|mailto|tel):/i;

const INJECTION_PATTERNS = [
  // Dangerous protocol handlers
  /javascript\s*:/i,
  /vbscript\s*:/i,

  // data: URI dangerous subtypes
  /data\s*:\s*text\/(html|xml|xhtml)/i,
  /data\s*:\s*image\/svg\+xml/i,
  /data\s*:\s*application\/(xhtml\+xml|.*xml)/i,
  /data\s*:\s*(image\/svg|application\/)/i, // catch-all for svg / app subtypes

  // Old IE / legacy vectors
  /expression\s*\(/i,

  // Event handlers (both attribute and inline forms)
  /on[a-z]{2,}\s*=/i,
  /<[^>]*\bon\w+\s*=/i,

  // Forbidden / dangerous tags
  /<[^>]*script/i,
  /<[^>]*iframe/i,
  /<[^>]*object/i,
  /<[^>]*embed/i,
  /<[^>]*svg/i,
  /<[^>]*math/i,
  /<[^>]*base[\s>]/i,
  /formaction\s*=/i,

  // SVG animation elements that can carry javascript: in href / to / values
  /<[^>]*animate/i,              // animate, animateTransform, animateMotion
  /<[^>]*set/i,                  // <set attributeName="href" to="javascript:..."/>
  /<[^>]*animatetransform/i,
  /<[^>]*animatemotion/i,

  // Additional dangerous SVG elements
  /<[^>]*foreignobject/i,        // Can embed arbitrary HTML / <script> inside SVG
  /<[^>]*use/i,                  // Can reference external or malicious content
  /<[^>]*symbol/i,               // Reusable definitions, often combined with <use>
  /<[^>]*marker/i,               // Can contain shapes with events or be referenced
  /<[^>]*filter/i,               // FeImage / fe* primitives can load resources
  /<[^>]*clippath/i,             // Clipping paths that reference content
  /<[^>]*mask/i,                 // Masks that reference external content
  /<[^>]*defs/i,                 // Container for reusable (potentially malicious) defs
  /<[^>]*lineargradient/i,       // Gradients that can reference stops / images
  /<[^>]*radialgradient/i,       // Same as linearGradient
];
// ── Helpers ────────────────────────────────────────────────────────────────────
const decodeEntities = (s) =>
  s.replace(/&#(x[0-9a-f]+|[0-9]+);/gi, (_, code) => {
    const n = code.startsWith('x') || code.startsWith('X')
      ? parseInt(code.slice(1), 16)
      : parseInt(code, 10);
    return (n > 0 && n < 0x110000) ? String.fromCharCode(n) : '';
  });

const normalizeHtml = (html) =>
  html
    .replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
    .replace(/[\u00AD\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2064\uFEFF\uFFFE\uFFFF]/g, '');

// ── Validator ──────────────────────────────────────────────────────────────────
const validateComment = ({ html, text }) => {
  const trimmedText = (text || '').trim();
  const errors = [];
  const warnings = [];

  // ── 0. Raw pre-checks ───────────────────────────────────────────────────────
  if (html.length > 102_400) {
    errors.push('Input too large (max 100 KB raw HTML)');
    return { valid: false, errors, warnings };
  }

  const percentDecoded = html.replace(
    /%([0-9a-fA-F]{2})/g,
    (_, h) => String.fromCharCode(parseInt(h, 16))
  );

  if (/\x00/.test(percentDecoded))
    errors.push('Null byte detected (possible WAF bypass attempt)');

  if (INJECTION_PATTERNS.some(p => p.test(percentDecoded)))
    errors.push('Injection pattern detected in percent-decoded input');

  if (/[\x7F-\x9F]/.test(html))
    errors.push('C1 control characters detected');

  // ── 1. Length check ─────────────────────────────────────────────────────────
  if (trimmedText.length < 1 || trimmedText.length > 8000)
    errors.push('Length must be 1–8000 characters');

  // ── 2. C0 controls (text layer) ────────────────────────────────────────────
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(trimmedText))
    errors.push('Invalid control characters detected');

  // ── 3. Spam guard ───────────────────────────────────────────────────────────
  if (/(.)\1{14,}/.test(trimmedText))
    warnings.push('Excessive character repetition (possible spam)');

  // ── 4. Injection patterns on normalized HTML ────────────────────────────────
  if (INJECTION_PATTERNS.some(p => p.test(normalizeHtml(html))))
    errors.push('Potentially unsafe HTML/script patterns detected');

  // ── 5. DOM-based tag allow-list ─────────────────────────────────────────────
  const tmp = document.createElement('div');
  tmp.innerHTML = html;

  const disallowedTag = [...tmp.querySelectorAll('*')].find(
    el => !SAFE_TAGS.has(el.tagName)
  );
  if (disallowedTag)
    errors.push(`Tag not allowed: <${disallowedTag.tagName.toLowerCase()}>`);

  // ── 6. Attribute allow-list + href/target enforcement ───────────────────────
  let attrError = null;
  tmp.querySelectorAll('*').forEach(el => {
    if (attrError) return;
    const isAnchor = el.tagName === 'A';

    Array.from(el.attributes).forEach(attr => {
      if (attrError) return;
      const name = attr.name.toLowerCase();

      // Explicitly forbid xlink:href (legacy SVG XSS vector)
      if (name === 'xlink:href') {
        attrError = 'Forbidden attribute: xlink:href';
        return;
      }

      // rel and target only on <a>
      if ((name === 'rel' || name === 'target') && !isAnchor) {
        attrError = `Attribute "${name}" is only allowed on <a> tags`;
        return;
      }

      if (!SAFE_ATTRS.has(name)) {
        attrError = `Attribute not allowed: ${name}`;
        return;
      }

      if (name === 'href') {
        const raw = attr.value.trim();
        const decoded = decodeEntities(raw);
        const safe =
          decoded === '' ||
          decoded.startsWith('#') ||
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

  // ── 7. Character allow-list (text layer) ────────────────────────────────────
  const decodedText = trimmedText
    .replace(/&[a-z][a-z0-9]*;/gi, 'X')
    .replace(/&#[0-9]+;/gi, 'X')
    .replace(/&#x[0-9a-f]+;/gi, 'X');

  const safeChars = /^[\p{L}\p{N}\p{P}\p{S}\p{Z}\p{Emoji_Presentation}\n\r\t\s]*$/u;
  if (!safeChars.test(decodedText))
    errors.push('Unsupported or unsafe characters detected');

  return { valid: errors.length === 0, errors, warnings };
};

// ── Paste sanitizer (unchanged) ───────────────────────────────────────────────
const sanitizePaste = (e) => {
  e.preventDefault();
  const plain = e.clipboardData?.getData('text/plain') ?? '';
  if (plain) document.execCommand('insertText', false, plain);
};

export { validateComment, sanitizePaste };
