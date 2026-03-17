# HTMLTextValidatorScript
Sample project to validate the HTML Text with Javascript before pushing to WAF, OWASP aligned.

This validator is a client-side HTML/XSS filter for a rich-text comment field. 

## SQL injection is a completely different attack class that operates at a different layer:

XSSSQL InjectionTargetThe browser / other users viewing the commentYour database serverWhere it's exploitedWhen the comment is rendered as HTMLWhen the comment value is interpolated into a SQL queryWho defends against itThe client + output encodingThe server / database layerThis validator covers it?✓ Yes✗ No — wrong layer


SQL injection cannot be reliably prevented client-side for two reasons:

Clients can be bypassed entirely. An attacker can send a raw HTTP request directly to your API, skipping your JS validator completely. Any input validation that matters for SQL injection must happen server-side.
SQL injection isn't about "bad characters". Blocking ', --, ;, DROP, SELECT etc. is fragile and causes false positives on legitimate comments like "it's great" or "SELECT the best option". 
The correct fix is parameterised queries / prepared statements — which make injection structurally impossible regardless of what the input contains.
