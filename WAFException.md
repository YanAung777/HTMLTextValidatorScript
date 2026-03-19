These focus on handling false positives from anomaly-based rules, such as special character counts or heuristics involving hyphens, parentheses, brackets, or punctuation—especially relevant for public free-text fields like Salesforce rich text comments.

Exclusions are typically placed in dedicated files to avoid being overwritten during CRS updates:

* REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf (for configure-time/global exclusions).  
* RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf (for post-CRS adjustments, e.g., target updates).  
* Or custom files included after the main CRS rules.

Always add comments explaining the exclusion (e.g., rule name, reason, affected fields/URIs) for maintainability.

### **1\. Global Exclusion (Disable a Rule Entirely)**

Useful for rules that are too noisy across the board (rare for production; prefer targeted).

apache  
*\# CRS Rule Exclusion: Disable special character anomaly rule globally due to high FPs in public comments*  
*\# (e.g., 942430 \- Restricted SQL Character Anomaly Detection, often triggers on lists, dashes, brackets)*  
SecRuleRemoveById 942430

Or for a group (e.g., all SQLi anomaly rules):

apache  
*\# CRS Rule Exclusion: Remove all SQL injection anomaly-based rules (high FP risk in free text)*  
SecRuleRemoveByTag attack-sqli

### **2\. Scoped Exclusion by URI/Path (Runtime, Recommended for Rich Text Fields)**

Apply only to specific endpoints (e.g., comment submission forms). Use ctl:ruleRemoveById for runtime control.

apache  
*\# Exclude dense special char / hyphen/parenthesis rules on comment submission endpoint*  
SecRule REQUEST\_URI "@beginsWith /comments/submit" \\  
    "id:10001,phase:1,pass,nolog,ctl:ruleRemoveById=942430,ctl:ruleRemoveById=942431,ctl:ruleRemoveById=942432"

Or with regex for broader matching (e.g., all Salesforce/AEM form paths):

apache  
SecRule REQUEST\_URI "@rx ^/(salesforce|aem)/forms/.\*" \\  
    "id:10002,phase:1,pass,nolog,ctl:ruleRemoveById=942420,ctl:ruleRemoveById=942430"

### **3\. Exclude Specific Parameters/Fields (Best for Rich Text)**

Target only the problematic parameter (e.g., comment, body, description) instead of the whole request. Use SecRuleUpdateTargetById (configure-time) or ctl: actions.

apache  
*\# CRS Rule Exclusion: Exclude rich text field from SQLi special char anomaly rules*  
*\# (prevents FPs from parentheses, hyphens, brackets in user comments)*  
SecRuleUpdateTargetById 942430 "\!ARGS:comment\_body"  
SecRuleUpdateTargetById 942431 "\!ARGS:comment\_body"  
SecRuleUpdateTargetById 942432 "\!ARGS:comment\_body"

For multiple fields or regex:

apache  
*\# Exclude from all args starting with 'rich\_' or specific names*  
SecRuleUpdateTargetByTag attack-sqli "\!ARGS:/^rich\_text\_|^comment|^description/"

Or runtime (more flexible):

apache  
SecRule ARGS\_NAMES "@rx ^(comment|body|description)$" \\  
    "id:10003,phase:2,pass,nolog,ctl:ruleRemoveById=942430"

### **4\. Exclude by Target for XSS/SQLi Heuristics (Parentheses/Hyphens)**

For rules flagging HTML-like patterns or comment sequences in text:

apache  
*\# CRS Rule Exclusion: Exclude comment field from XSS HTML tag handler rule (common FP in rich text)*  
SecRuleUpdateTargetById 941320 "\!ARGS:wp\_post"   \# Example from WordPress-like fields; adapt to your param

*\# Or broader for parentheses/hyphen density in SQLi/XSS heuristics*  
SecRuleUpdateTargetById 941100 "\!ARGS:free\_text\_comment"

### **5\. Combining with Paranoia Level Tuning**

If running at PL2+ (where these anomaly rules activate more aggressively), start with high thresholds and tune iteratively:

In crs-setup.conf:

apache  
SecAction \\  
 "id:900110,\\  
  phase:1,\\  
  pass,\\  
  nolog,\\  
  setvar:tx.inbound\_anomaly\_score\_threshold=10"  \# Higher than default 5 to reduce blocking

Then exclude noisy siblings progressively (942430 → 942431 → 942432 are increasingly strict special char counts).

### **Best Practices & Tips**

* **Order matters**: Place exclusions *before* the main CRS includes for configure-time (SecRuleRemoveById), or use ctl: in phase 1 for runtime.  
* **Test in detection-only first**: Set tx.inbound\_anomaly\_score\_threshold very high (e.g., 10000\) to log without blocking while gathering data.  
* **Use tags over IDs when possible**: SecRuleRemoveByTag paranoia-level/2 or attack-xss for broader coverage without listing every ID.  
* **App-specific packages**: CRS includes pre-built exclusion packages (e.g., for WordPress, Drupal). Enable in crs-setup.conf with setvar:tx.crs\_exclusions\_wordpress=1 — useful if your Salesforce/AEM setup resembles CMS comment forms.  
* **Monitor & iterate**: After exclusions, review audit logs for remaining FPs. Report persistent generic issues to the CRS GitHub for potential upstream fixes.  
* **Avoid over-exclusion**: Don't blanket-remove entire categories (e.g., all SQLi) unless justified — it weakens protection. Prefer per-parameter or per-URI.

For your Salesforce rich text scenario (HTML stripped server-side, public punctuation allowed), the parameter-specific exclusions above (e.g., targeting the comment/description arg) align perfectly with minimizing global impact while keeping null bytes/control chars blocked (those are usually lower-ID rules like 920270/920271, which you can leave enabled).

