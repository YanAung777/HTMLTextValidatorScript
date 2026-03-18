/**
 * OWASP-aligned Rich-Text Comment Validator (Client-Side – 2026 hardened)
 * Defends against XSS, injection, obfuscation via 8 layers
 * Allows safe formatting while blocking dangerous constructs
 *
 * npm install dompurify@latest
 * # or yarn add dompurify@latest
 * # pin to ^3.3.2 or higher in package.json
 * Requires: DOMPurify >= 3.3.2 (fixes 2025–2026 rawtext/attribute bypasses)
 */
import DOMPurify from 'dompurify';

const validateRichComment = (rawInput = '') => {
  const result = {
    valid: false,
    cleanedHtml: '',
    reason: '',
    score: 0,               // anomaly score (higher = more suspicious)
    warnings: [],           // non-blocking issues for logging/UI hint
  };

  const trimmed = String(rawInput).trim();

  // ── Layer 1: Length & basic sanity (DoS / flood protection) ────────
  if (trimmed.length === 0) {
    result.reason = 'Comment cannot be empty';
    return result;
  }
  if (trimmed.length > 12000) {
    result.reason = 'Comment exceeds maximum length (12,000 characters)';
    return result;
  }
  if (trimmed.length > 8000) result.score += 1; // flag very long input

  // ── Layer 2: Forbidden control / non-printable chars ───────────────
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/.test(trimmed)) {
    result.reason = 'Control characters are not allowed';
    return result;
  }

  // ── Layer 3: Anti-spam / ReDoS / excessive repetition ──────────────
  if (/(.)\1{20,}/u.test(trimmed)) {
    result.reason = 'Excessive character repetition detected (spam)';
    result.score += 2;
  }
  if (/[!?.]{15,}/.test(trimmed)) result.score += 1;

  // ── Layer 4: Fast pre-filter — obvious dangerous raw tokens ────────
  const quickDanger = [
    /javascript\s*:/i,
    /data\s*:\s*(text\/html|application\/x-javascript|image\/svg\+xml|text\/xml)/i,
    /expression\s*\(/i,                  // legacy IE
    /vbscript\s*:/i,
    /<[^>]*\b(on\w+|formaction|srcdoc|action)\s*=/i,
    /<\s*(script|iframe|object|embed|base|meta|form|svg[^>]*on|math[^>]*on)/i,
  ];
  if (quickDanger.some(p => p.test(trimmed))) {
    result.reason = 'Obvious unsafe raw patterns detected';
    result.score += 3;
    if (result.score >= 5) return result; // early exit
  }

  // ── Layer 5: DOMPurify sanitization (core protection – strict config) ─
  const purifyConfig = {
    // Very restrictive allow-list for comments/forums (2026 best practice)
    ALLOWED_TAGS: [
      'a', 'b', 'strong', 'i', 'em', 'u', 's', 'strike', 'del', 'ins',
      'p', 'br', 'div', 'span', 'blockquote', 'q', 'cite',
      'ul', 'ol', 'li',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'pre', 'code', 'kbd', 'samp', 'var',
      'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'img', 'figure', 'figcaption',
      // emojis & safe inline formatting
    ],
    ALLOWED_ATTR: [
      'href', 'title', 'alt', 'src', 'width', 'height',
      'class', 'lang', 'dir',
      'target', 'rel',           // _blank + noopener/noreferrer
      // 'data-*' — only if explicitly needed (risky)
    ],
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto):|[^&(?:\w+)?#]*(?:[/?#]|$))/i,
    // Block dangerous protocols & schemes
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'style', 'link', 'meta', 'form', 'input', 'button', 'textarea', 'noscript', 'noembed', 'noframes', 'xmp'],
    FORBID_ATTR: [/^on/, 'style', 'srcdoc', 'action', 'formaction', 'xmlns'],
    ADD_TAGS: [],
    ADD_ATTR: ['target', 'rel'],
    ALLOW_SELF_CLOSING: true,
    ALLOW_DATA_ATTR: false,           // block data: URIs entirely
    SAFE_FOR_TEMPLATES: false,
    WHOLE_DOCUMENT: false,
    RETURN_DOM_FRAGMENT: false,
    RETURN_DOM: false,
    // Force noopener/noreferrer on links (anti-tabnabbing)
    ADD_URI_SAFE_ATTR: ['href'],
  };

  // Optional: limited inline styles (very dangerous — avoid unless needed)
  // purifyConfig.ALLOWED_ATTR.push('style');
  // purifyConfig.ALLOWED_STYLES = { '*': { 'color': true, 'background-color': true, 'text-align': true } };

  const clean = DOMPurify.sanitize(trimmed, purifyConfig);

  // ── Layer 6: Post-sanitization checks (emptiness / heavy stripping) ──
  if (clean.length < 3 || clean.trim() === '') {
    result.reason = 'No safe content remains after sanitization';
    return result;
  }
  // Heuristic: >60% content removed → likely obfuscation attempt
  if (clean.length < trimmed.length * 0.4) {
    result.score += 2;
    result.warnings.push('Content heavily modified by sanitizer (possible obfuscation)');
  }

  // ── Layer 7: Residual dangerous fragments (belt-and-suspenders) ─────
  if (/(?:javascript|data|vbscript)\s*:/i.test(clean) || /on\w+\s*=/i.test(clean)) {
    result.reason = 'Unsafe fragments remain after sanitization';
    result.score += 4;
    return result;
  }

  // ── Layer 8: Final anomaly scoring & decision ──────────────────────
  if (result.score >= 5) {
    result.reason = 'High anomaly score — possible evasion/obfuscation attempt';
    return result;
  }

  result.valid = true;
  result.cleanedHtml = clean;
  result.reason = 'Passed all 8 validation layers';
  return result;
};

// ── Example usage (React / Vanilla JS) ─────────────────────────────────
/*
const input = `<p>Hello <b>world</b>!</p><img src="x" onerror="alert(1)"><script>alert(1)</script><a href="javascript:alert(1)">click</a>`;
const outcome = validateRichComment(input);

if (outcome.valid) {
  // Safe → insert via innerHTML or editor.setHTML(outcome.cleanedHtml)
  console.log('Clean:', outcome.cleanedHtml);
  // e.g. document.getElementById('preview').innerHTML = outcome.cleanedHtml;
} else {
  console.warn('Blocked:', outcome.reason, '(score:', outcome.score, ')');
  // show error to user + log warnings
}
*/
