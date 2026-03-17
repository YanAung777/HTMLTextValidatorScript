# HTMLTextValidatorScript
Sample project to validate the HTML Text with Javascript before pushing to WAF, OWASP aligned.

This validator is a client-side HTML/XSS filter for a rich-text comment field. SQL injection is a completely different attack class that operates at a different layer:

XSSSQL InjectionTargetThe browser / other users viewing the commentYour database serverWhere it's exploitedWhen the comment is rendered as HTMLWhen the comment value is interpolated into a SQL queryWho defends against itThe client + output encodingThe server / database layerThis validator covers it?✓ Yes✗ No — wrong layer
