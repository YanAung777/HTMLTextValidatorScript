const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

// 1. Setup a virtual window/DOM environment
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

/**
 * To implement server-side sanitization using DOMPurify, you need to run it in a Node.js environment. Since DOMPurify is designed to work with the Document Object Model (DOM), which doesn't exist natively in Node.js, you must use a library like jsdom to provide a "virtual" window for it to operate.
 * Server-side Sanitizer
 * You will need both the DOMPurify library and the JSDOM emulator.
 * npm install dompurify jsdom
 * Mirrors the constraints of your client-side validator
 */
function sanitizeComment(dirtyHtml) {
  return DOMPurify.sanitize(dirtyHtml, {
    // 2. Define the "Allow-list" (Everything else is stripped)
    ALLOWED_TAGS: ['b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'p', 'br', 'span', 'div'],
    ALLOWED_ATTR: ['href', 'target', 'rel', 'title', 'class'],
    
    // 3. Security Hardening
    RETURN_DOM: false,          // Return a string, not a DOM node
    WHOLE_DOCUMENT: false,      // We only want the fragment
    FORCE_BODY: false,          // Prevents wrapping in <body> tags
    
    // 4. URI Validation
    // This automatically handles the "javascript:" and "data:" URI checks
    ALLOW_UNKNOWN_PROTOCOLS: false,
  });
}

// Example Usage in an Express Route
// app.post('/api/comment', (req, res) => {
//   const cleanHtml = sanitizeComment(req.body.commentHtml);
//   // ... Save cleanHtml to database
// });
