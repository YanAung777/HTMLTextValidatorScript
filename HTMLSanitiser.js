/* ═══════════════════════════════════════════════════════════════
   EDITOR HTML SANITISER
   Normalises browser-injected markup before the validator sees it.
   execCommand output varies by browser:
     Chrome bold  -> <span style="font-weight:bold">  (style= would be blocked)
     Firefox bold -> <b>                              (fine)
     Safari bold  -> <b style="...">                 (style= would be blocked)
     Some browsers inject id= on list items, dir= on text, etc.
   This strips disallowed attributes and maps legacy tags to semantic
   equivalents so the validator only sees user intent, not browser quirks.
=============================================================== */
function sanitiseEditorHtml(html) {
  const tmp = document.createElement('div');
  tmp.innerHTML = html;
 
  // Replace legacy/non-semantic tags with safe equivalents
  const TAG_MAP = { STRIKE:'S', DEL:'S', FONT:'SPAN', BOLD:'B', ITALIC:'I', TT:'CODE' };
  [...tmp.querySelectorAll('strike,del,font,bold,italic,tt')].forEach(el => {
    const repl = document.createElement(TAG_MAP[el.tagName] || 'SPAN');
    repl.innerHTML = el.innerHTML;
    el.replaceWith(repl);
  });
 
  // Strip every attribute not in the safe set; enforce rel/target on <a> only
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
