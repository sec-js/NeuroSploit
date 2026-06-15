"""
NeuroSploit v3 - Task/Prompt Library System

Manage reusable tasks and prompts for the AI Agent.
- Create, save, edit, delete tasks
- Preset tasks for common scenarios
- Custom task builder
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class TaskCategory(Enum):
    """Task categories"""
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    CUSTOM = "custom"
    FULL_AUTO = "full_auto"


@dataclass
class Task:
    """A reusable task/prompt"""
    id: str
    name: str
    description: str
    category: str
    prompt: str
    system_prompt: Optional[str] = None
    tools_required: List[str] = None
    estimated_tokens: int = 0
    created_at: str = ""
    updated_at: str = ""
    author: str = "user"
    tags: List[str] = None
    is_preset: bool = False

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
        if self.tools_required is None:
            self.tools_required = []
        if self.tags is None:
            self.tags = []


class TaskLibrary:
    """Manage the task/prompt library"""

    def __init__(self, library_path: str = "prompts/task_library.json"):
        self.library_path = Path(library_path)
        self.library_path.parent.mkdir(parents=True, exist_ok=True)
        self.tasks: Dict[str, Task] = {}
        self._load_library()
        self._ensure_presets()

    def _load_library(self):
        """Load tasks from library file"""
        if self.library_path.exists():
            try:
                with open(self.library_path, 'r') as f:
                    data = json.load(f)
                    for task_data in data.get("tasks", []):
                        task = Task(**task_data)
                        self.tasks[task.id] = task
            except Exception as e:
                print(f"Error loading task library: {e}")

    def _save_library(self):
        """Save tasks to library file"""
        data = {
            "version": "1.0",
            "updated_at": datetime.utcnow().isoformat(),
            "tasks": [asdict(task) for task in self.tasks.values()]
        }
        with open(self.library_path, 'w') as f:
            json.dump(data, f, indent=2)

    def _ensure_presets(self):
        """Ensure preset tasks exist"""
        presets = self._get_preset_tasks()
        for preset in presets:
            if preset.id not in self.tasks:
                self.tasks[preset.id] = preset
        self._save_library()

    def _get_preset_tasks(self) -> List[Task]:
        """Get all preset tasks"""
        return [
            # === RECON TASKS ===
            Task(
                id="recon_full",
                name="Full Reconnaissance",
                description="Complete reconnaissance: subdomains, ports, technologies, endpoints",
                category=TaskCategory.RECON.value,
                prompt="""Perform comprehensive reconnaissance on the target:

1. **Subdomain Enumeration**: Find all subdomains
2. **Port Scanning**: Identify open ports and services
3. **Technology Detection**: Fingerprint web technologies, frameworks, servers
4. **Endpoint Discovery**: Crawl and find all accessible endpoints
5. **Parameter Discovery**: Find URL parameters and form inputs
6. **JavaScript Analysis**: Extract endpoints from JS files
7. **API Discovery**: Find API endpoints and documentation

Consolidate all findings into a structured report.""",
                system_prompt="You are a reconnaissance expert. Gather information systematically and thoroughly.",
                tools_required=["subfinder", "httpx", "nmap", "katana", "gau"],
                estimated_tokens=2000,
                tags=["recon", "discovery", "enumeration"],
                is_preset=True
            ),
            Task(
                id="recon_passive",
                name="Passive Reconnaissance",
                description="Non-intrusive reconnaissance using public data only",
                category=TaskCategory.RECON.value,
                prompt="""Perform PASSIVE reconnaissance only (no direct interaction with target):

1. **OSINT**: Search for public information
2. **DNS Records**: Enumerate DNS records
3. **Historical Data**: Check Wayback Machine, archive.org
4. **Certificate Transparency**: Find subdomains from CT logs
5. **Google Dorking**: Search for exposed files/information
6. **Social Media**: Find related accounts and information

Do NOT send any requests directly to the target.""",
                system_prompt="You are an OSINT expert. Only use passive techniques.",
                tools_required=["subfinder", "gau", "waybackurls"],
                estimated_tokens=1500,
                tags=["recon", "passive", "osint"],
                is_preset=True
            ),

            # === VULNERABILITY TASKS ===
            Task(
                id="vuln_owasp_top10",
                name="OWASP Top 10 Assessment",
                description="Test for OWASP Top 10 vulnerabilities",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test the target for OWASP Top 10 vulnerabilities:

1. **A01 - Broken Access Control**: Test for IDOR, privilege escalation
2. **A02 - Cryptographic Failures**: Check for weak crypto, exposed secrets
3. **A03 - Injection**: Test SQL, NoSQL, OS, LDAP injection
4. **A04 - Insecure Design**: Analyze business logic flaws
5. **A05 - Security Misconfiguration**: Check headers, default configs
6. **A06 - Vulnerable Components**: Identify outdated libraries
7. **A07 - Authentication Failures**: Test auth bypass, weak passwords
8. **A08 - Data Integrity Failures**: Check for insecure deserialization
9. **A09 - Security Logging Failures**: Test for logging gaps
10. **A10 - SSRF**: Test for server-side request forgery

For each finding:
- Provide CVSS score and calculation
- Detailed description
- Proof of Concept
- Remediation recommendation""",
                system_prompt="You are a web security expert specializing in OWASP vulnerabilities.",
                tools_required=["nuclei", "sqlmap", "xsstrike"],
                estimated_tokens=5000,
                tags=["vulnerability", "owasp", "web"],
                is_preset=True
            ),
            Task(
                id="vuln_api_security",
                name="API Security Testing",
                description="Test API endpoints for security issues",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test the API for security vulnerabilities:

1. **Authentication**: Test JWT, OAuth, API keys
2. **Authorization**: Check for BOLA, BFLA, broken object level auth
3. **Rate Limiting**: Test for missing rate limits
4. **Input Validation**: Injection attacks on API params
5. **Data Exposure**: Check for excessive data exposure
6. **Mass Assignment**: Test for mass assignment vulnerabilities
7. **Security Misconfiguration**: CORS, headers, error handling
8. **Injection**: GraphQL, SQL, NoSQL injection

For each finding provide CVSS, PoC, and remediation.""",
                system_prompt="You are an API security expert.",
                tools_required=["nuclei", "ffuf"],
                estimated_tokens=4000,
                tags=["vulnerability", "api", "rest", "graphql"],
                is_preset=True
            ),
            Task(
                id="vuln_injection",
                name="Injection Testing",
                description="Comprehensive injection vulnerability testing",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test all input points for injection vulnerabilities:

1. **SQL Injection**: Error-based, union, blind, time-based
2. **NoSQL Injection**: MongoDB, CouchDB injections
3. **Command Injection**: OS command execution
4. **LDAP Injection**: Directory service injection
5. **XPath Injection**: XML path injection
6. **Template Injection (SSTI)**: Jinja2, Twig, Freemarker
7. **Header Injection**: Host header, CRLF injection
8. **Email Header Injection**: SMTP injection

Test ALL parameters: URL, POST body, headers, cookies.
Provide working PoC for each finding.""",
                system_prompt="You are an injection attack specialist. Test thoroughly but safely.",
                tools_required=["sqlmap", "commix"],
                estimated_tokens=4000,
                tags=["vulnerability", "injection", "sqli", "rce"],
                is_preset=True
            ),

            # === FULL AUTO TASKS ===
            Task(
                id="full_bug_bounty",
                name="Bug Bounty Hunter Mode",
                description="Full automated bug bounty workflow: recon -> analyze -> test -> report",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute complete bug bounty workflow:

## PHASE 1: RECONNAISSANCE
- Enumerate all subdomains and assets
- Probe for live hosts
- Discover all endpoints
- Identify technologies and frameworks

## PHASE 2: ANALYSIS
- Analyze attack surface
- Identify high-value targets
- Map authentication flows
- Document API endpoints

## PHASE 3: VULNERABILITY TESTING
- Test for critical vulnerabilities first (RCE, SQLi, Auth Bypass)
- Test for high severity (XSS, SSRF, IDOR)
- Test for medium/low (Info disclosure, misconfigs)

## PHASE 4: EXPLOITATION
- Develop PoC for confirmed vulnerabilities
- Calculate CVSS scores
- Document impact and risk

## PHASE 5: REPORTING
- Generate professional report
- Include all findings with evidence
- Provide remediation steps

Focus on impact. Prioritize critical findings.""",
                system_prompt="""You are an elite bug bounty hunter. Your goal is to find real, impactful vulnerabilities.
Be thorough but efficient. Focus on high-severity issues first.
Every finding must have: Evidence, CVSS, Impact, PoC, Remediation.""",
                tools_required=["subfinder", "httpx", "nuclei", "katana", "sqlmap"],
                estimated_tokens=10000,
                tags=["full", "bug_bounty", "automated"],
                is_preset=True
            ),
            Task(
                id="full_pentest",
                name="Full Penetration Test",
                description="Complete penetration test workflow",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute comprehensive penetration test:

## PHASE 1: INFORMATION GATHERING
- Passive reconnaissance
- Active reconnaissance
- Network mapping
- Service enumeration

## PHASE 2: VULNERABILITY ANALYSIS
- Automated scanning
- Manual testing
- Business logic analysis
- Configuration review

## PHASE 3: EXPLOITATION
- Exploit confirmed vulnerabilities
- Post-exploitation (if authorized)
- Privilege escalation attempts
- Lateral movement (if authorized)

## PHASE 4: DOCUMENTATION
- Document all findings
- Calculate CVSS 3.1 scores
- Create proof of concepts
- Write remediation recommendations

## PHASE 5: REPORTING
- Executive summary
- Technical findings
- Risk assessment
- Remediation roadmap

This is a full penetration test. Be thorough and professional.""",
                system_prompt="""You are a professional penetration tester conducting an authorized security assessment.
Document everything. Be thorough. Follow methodology.
All findings must include: Title, CVSS, Description, Evidence, Impact, Remediation.""",
                tools_required=["nmap", "nuclei", "sqlmap", "nikto", "ffuf"],
                estimated_tokens=15000,
                tags=["full", "pentest", "professional"],
                is_preset=True
            ),

            # === CUSTOM/FLEXIBLE TASKS ===
            Task(
                id="custom_prompt",
                name="Custom Prompt (Full AI Mode)",
                description="Execute any custom prompt - AI decides what tools to use",
                category=TaskCategory.CUSTOM.value,
                prompt="""[USER_PROMPT_HERE]

Analyze this request and:
1. Determine what information/tools are needed
2. Plan the approach
3. Execute the necessary tests
4. Analyze results
5. Report findings

You have full autonomy to use any tools and techniques needed.""",
                system_prompt="""You are an autonomous AI security agent.
Analyze the user's request and execute it completely.
You can use any tools available. Be creative and thorough.
If the task requires testing, test. If it requires analysis, analyze.
Always provide detailed results with evidence.""",
                tools_required=[],
                estimated_tokens=5000,
                tags=["custom", "flexible", "ai"],
                is_preset=True
            ),
            Task(
                id="analyze_only",
                name="Analysis Only (No Testing)",
                description="AI analysis without active testing - uses provided data",
                category=TaskCategory.CUSTOM.value,
                prompt="""Analyze the provided data/context WITHOUT performing active tests:

1. Review all provided information
2. Identify potential security issues
3. Assess risk levels
4. Provide recommendations

Do NOT send any requests to the target.
Base your analysis only on provided data.""",
                system_prompt="You are a security analyst. Analyze provided data without active testing.",
                tools_required=[],
                estimated_tokens=2000,
                tags=["analysis", "passive", "review"],
                is_preset=True
            ),

            # === REPORTING TASKS ===
            Task(
                id="report_executive",
                name="Executive Summary Report",
                description="Generate executive-level security report",
                category=TaskCategory.REPORTING.value,
                prompt="""Generate an executive summary report from the findings:

1. **Executive Summary**: High-level overview for management
2. **Risk Assessment**: Overall security posture rating
3. **Key Findings**: Top critical/high findings only
4. **Business Impact**: How vulnerabilities affect the business
5. **Recommendations**: Prioritized remediation roadmap
6. **Metrics**: Charts and statistics

Keep it concise and business-focused. Avoid technical jargon.""",
                system_prompt="You are a security consultant writing for executives.",
                tools_required=[],
                estimated_tokens=2000,
                tags=["reporting", "executive", "summary"],
                is_preset=True
            ),
            Task(
                id="report_technical",
                name="Technical Security Report",
                description="Generate detailed technical security report",
                category=TaskCategory.REPORTING.value,
                prompt="""Generate a detailed technical security report:

For each vulnerability include:
1. **Title**: Clear, descriptive title
2. **Severity**: Critical/High/Medium/Low/Info
3. **CVSS Score**: Calculate CVSS 3.1 score with vector
4. **CWE ID**: Relevant CWE classification
5. **Description**: Detailed technical explanation
6. **Affected Component**: Endpoint, parameter, function
7. **Proof of Concept**: Working PoC code/steps
8. **Evidence**: Screenshots, requests, responses
9. **Impact**: What an attacker could achieve
10. **Remediation**: Specific fix recommendations
11. **References**: OWASP, CWE, vendor docs

Be thorough and technical.""",
                system_prompt="You are a senior security engineer writing a technical report.",
                tools_required=[],
                estimated_tokens=3000,
                tags=["reporting", "technical", "detailed"],
                is_preset=True
            ),

            # === ADVANCED VULNERABILITY TASKS ===
            Task(
                id="vuln_xss_deep",
                name="Deep XSS Assessment",
                description="Comprehensive XSS testing: reflected, stored, DOM, blind, mutation, filter bypass",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform deep cross-site scripting assessment:

## PHASE 1: REFLECTION MAPPING
- Crawl all pages and identify every input reflection point
- Map reflection contexts: HTML body, attribute, JavaScript, URL, CSS
- Test encoding behavior for <, >, ", ', `, /, \\

## PHASE 2: REFLECTED XSS
- Test each reflection point with context-appropriate payloads
- Bypass WAF/filters using encoding, case variation, event handlers
- Test alternative tags: <svg>, <img>, <details>, <math>, <video>
- Test attribute injection: onfocus, onmouseover, autofocus
- Test JavaScript context: '-alert(1)-', \\'-alert(1)//, template literals

## PHASE 3: STORED XSS
- Identify all storage points (comments, profiles, messages, file names)
- Submit XSS payloads and find where they render
- Verify cross-user rendering (payload visible to other users)
- Test rich text editors for HTML injection

## PHASE 4: DOM XSS
- Analyze all JavaScript for source→sink flows
- Test location.hash, location.search, document.referrer sources
- Test innerHTML, document.write, eval, jQuery sinks
- Test postMessage handlers for origin validation

## PHASE 5: ADVANCED TECHNIQUES
- Blind XSS via admin/backend rendering (callback payloads)
- Mutation XSS via browser parsing quirks (mXSS)
- Polyglot payloads that work in multiple contexts
- CSP bypass techniques (unsafe-eval, unsafe-inline, nonce reuse, base-uri)
- Script gadget exploitation (known library bypasses)

## PHASE 6: BROWSER VALIDATION
- Validate all findings with Playwright/headless browser
- Confirm script execution (alert, cookie access, DOM modification)
- Document exact context and working payload

For each finding: CVSS, PoC, context analysis, browser verification.""",
                system_prompt="You are a XSS specialist. Test every context, bypass every filter. Prove execution in browser.",
                tools_required=["katana", "httpx", "nuclei"],
                estimated_tokens=6000,
                tags=["vulnerability", "xss", "dom", "stored", "reflected", "bypass"],
                is_preset=True
            ),
            Task(
                id="vuln_sqli_deep",
                name="Deep SQL Injection Assessment",
                description="Advanced SQLi: error, union, blind, time, ORM, second-order, WAF bypass",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform comprehensive SQL injection assessment:

## PHASE 1: INJECTION POINT DISCOVERY
- Test ALL parameters: URL, POST body, headers, cookies
- Test hidden parameters, JSON fields, XML attributes
- Test file upload filenames and metadata
- Use canary values to identify SQL context

## PHASE 2: ERROR-BASED SQLi
- Trigger database errors with syntax breaking: ', ", `, ), ;
- Identify database type from error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Extract data via EXTRACTVALUE, UPDATEXML, CONVERT (DB-specific)
- Test stacked queries where supported

## PHASE 3: UNION-BASED SQLi
- Determine column count (ORDER BY, UNION SELECT NULL)
- Find output columns (visible vs invisible)
- Extract schema: database names, table names, column names
- Extract sensitive data: users, passwords, tokens

## PHASE 4: BLIND SQLi (BOOLEAN & TIME)
- Boolean: AND 1=1 vs AND 1=2 response difference
- Time: SLEEP(), WAITFOR DELAY, pg_sleep()
- Optimize extraction with binary search
- Test conditional errors for error-based blind

## PHASE 5: ADVANCED TECHNIQUES
- Second-order injection (stored SQL executed later)
- Out-of-band: DNS exfiltration, HTTP callbacks
- WAF bypass: comments (/*!*/), encoding, case mixing, null bytes
- ORM injection: order-by, HQL/JPQL specific syntax
- NoSQL variant: test JSON operators if MongoDB suspected

## PHASE 6: POST-EXPLOITATION
- Read sensitive files (LOAD_FILE, UTL_FILE)
- Write web shell (INTO OUTFILE, xp_cmdshell)
- Enumerate database users and privileges
- Test for database links to other systems

For each finding: DB type, injection type, extracted data, CVSS, PoC, remediation.""",
                system_prompt="You are a SQL injection expert. Test every parameter, every technique, every database. Extract real data as proof.",
                tools_required=["sqlmap", "nuclei", "httpx"],
                estimated_tokens=6000,
                tags=["vulnerability", "sqli", "injection", "database", "blind"],
                is_preset=True
            ),
            Task(
                id="vuln_auth_testing",
                name="Authentication Security Testing",
                description="Test all auth mechanisms: login, registration, password reset, session, JWT, OAuth, 2FA",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform comprehensive authentication security testing:

## PHASE 1: LOGIN SECURITY
- Test for default credentials on all login panels
- Test password brute force resistance (lockout, rate limiting)
- Test credential stuffing protection
- Check for username enumeration (response timing, messages)
- Test login bypass via SQL injection, type juggling

## PHASE 2: SESSION MANAGEMENT
- Analyze session token entropy and randomness
- Test session fixation (does session regenerate on login?)
- Test session hijacking (predictable tokens, insecure transport)
- Check session timeout and expiration
- Test concurrent session limits
- Check session invalidation on logout and password change

## PHASE 3: PASSWORD RESET
- Test for host header poisoning in reset links
- Test token predictability/brute-forceability
- Check token expiration and single-use enforcement
- Test for user enumeration via reset flow
- Check if old password required for change

## PHASE 4: JWT ANALYSIS
- Decode and analyze JWT structure
- Test none algorithm attack
- Test algorithm confusion (RS256 to HS256)
- Test weak signing secrets (hashcat/jwt_tool)
- Test claim manipulation (role, sub, exp)
- Check for JWK/JKU injection

## PHASE 5: OAUTH TESTING
- Map OAuth flow and identify grant type
- Test redirect_uri manipulation
- Test state parameter absence/reuse (CSRF)
- Test scope escalation
- Check for token leakage in URL/referer

## PHASE 6: 2FA TESTING
- Test 2FA bypass by direct navigation
- Test code brute force (rate limits?)
- Test code reuse / non-expiration
- Test backup codes predictability
- Test 2FA enrollment bypass

For each finding: CVSS, attack scenario, PoC, remediation.""",
                system_prompt="You are an authentication security expert. Test every auth mechanism thoroughly. Focus on real bypass scenarios.",
                tools_required=["nuclei", "ffuf", "hydra"],
                estimated_tokens=5000,
                tags=["vulnerability", "auth", "jwt", "oauth", "session", "2fa"],
                is_preset=True
            ),
            Task(
                id="vuln_access_control",
                name="Access Control Testing",
                description="Test IDOR, BOLA, BFLA, privilege escalation, mass assignment, forced browsing",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform comprehensive access control testing:

## PHASE 1: IDOR/BOLA TESTING
- Map all endpoints with object IDs (user_id, order_id, file_id)
- Test cross-user access: change ID while keeping your auth token
- CRITICAL: Compare DATA content (not just HTTP status)
- Test all CRUD operations: read, update, delete other users' objects
- Test with sequential IDs, UUIDs, encoded references

## PHASE 2: BFLA (FUNCTION LEVEL)
- Map admin vs user endpoints
- Access admin endpoints with regular user credentials
- Test with no authentication at all
- Check API documentation for hidden admin endpoints
- Verify ACTIONS execute, not just status 200

## PHASE 3: PRIVILEGE ESCALATION
- Find role/permission parameters in requests
- Test role parameter manipulation (role=admin, isAdmin=true)
- Test JWT claim escalation (admin claim in token)
- Test registration with elevated role

## PHASE 4: MASS ASSIGNMENT
- Find object creation/update endpoints
- Add extra fields (role, isAdmin, verified, plan)
- Check if hidden fields accepted and stored
- Test property binding in frameworks (Spring, Rails)

## PHASE 5: FORCED BROWSING
- Enumerate hidden paths (admin, debug, internal, api/v1)
- Test backup files, config files, database dumps
- Check for sensitive files without auth checks
- Test path traversal in file download endpoints

DATA COMPARISON IS MANDATORY for all findings.
Status code alone is NEVER proof of access control failure.

For each finding: CVSS, comparison evidence, PoC, remediation.""",
                system_prompt="You are an access control expert. DATA COMPARISON is mandatory for every finding. Never report based on status codes alone.",
                tools_required=["nuclei", "ffuf", "httpx"],
                estimated_tokens=5000,
                tags=["vulnerability", "idor", "bola", "bfla", "access_control", "authz"],
                is_preset=True
            ),
            Task(
                id="vuln_ssrf",
                name="SSRF Deep Testing",
                description="Server-Side Request Forgery: internal access, cloud metadata, protocol smuggling",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform comprehensive SSRF testing:

## PHASE 1: IDENTIFY SSRF VECTORS
- Find URL parameters (url=, href=, src=, callback=, redirect=, proxy=)
- Test file import, webhook, PDF generation, screenshot features
- Check for image/URL preview functionality
- Test XML with external entity references (XXE→SSRF)

## PHASE 2: BASIC SSRF TESTING
- Test with attacker-controlled URL (Burp Collaborator, webhook.site, interactsh)
- Verify server makes the request (DNS callback, HTTP callback)
- Test HTTP vs HTTPS handling
- Test different HTTP methods via SSRF

## PHASE 3: INTERNAL ACCESS
- Test 127.0.0.1, localhost, 0.0.0.0, [::1] variations
- Test internal RFC1918 ranges (10.x, 172.16.x, 192.168.x)
- Port scan internal services via SSRF
- Access internal APIs, admin panels, databases

## PHASE 4: CLOUD METADATA
- AWS: http://169.254.169.254/latest/meta-data/
- GCP: http://metadata.google.internal/computeMetadata/v1/
- Azure: http://169.254.169.254/metadata/instance
- DigitalOcean: http://169.254.169.254/metadata/v1/

## PHASE 5: FILTER BYPASS
- URL encoding, double encoding
- DNS rebinding (attacker domain resolving to internal IP)
- Redirect chains (your domain → 302 → internal)
- Alternative IP formats: decimal, hex, octal
- IPv6: [::ffff:127.0.0.1], [::1]
- URL parsing differentials: http://evil@127.0.0.1

## PHASE 6: PROTOCOL SMUGGLING
- gopher:// for Redis, Memcached, SMTP interaction
- file:// for local file read
- dict:// for service interaction
- ftp:// for FTP bounce scanning

CRITICAL: Status code change alone is NEVER SSRF proof.
Must show CONTENT from internal service or callback received.

For each finding: CVSS, internal data retrieved, PoC, remediation.""",
                system_prompt="You are an SSRF specialist. Status code changes are NOT proof. Show actual internal data or OOB callbacks.",
                tools_required=["nuclei", "httpx"],
                estimated_tokens=5000,
                tags=["vulnerability", "ssrf", "cloud", "metadata", "internal"],
                is_preset=True
            ),
            Task(
                id="vuln_file_upload",
                name="File Upload Vulnerability Testing",
                description="Test file upload: web shells, extension bypass, content-type manipulation, path traversal",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform comprehensive file upload security testing:

## PHASE 1: IDENTIFY UPLOADS
- Find all file upload functionality (profile photos, documents, imports)
- Map upload restrictions (size, type, extension)
- Determine where files are stored and if web-accessible

## PHASE 2: EXTENSION BYPASS
- Test dangerous extensions: .php, .php5, .phtml, .jsp, .aspx, .py, .pl
- Double extensions: file.php.jpg, file.jpg.php
- Null byte: file.php%00.jpg (older systems)
- Case variation: .pHp, .PhP, .PHP
- Special extensions: .php7, .phar, .htaccess, .config

## PHASE 3: CONTENT-TYPE MANIPULATION
- Upload script with image Content-Type (image/jpeg)
- Upload polyglot file (valid image + embedded script)
- Test MIME type vs extension mismatch handling
- Upload with no Content-Type header

## PHASE 4: CONTENT BYPASS
- Embed code in image metadata (EXIF, ICC profile)
- Use polyglot files (valid JPEG header + PHP code)
- Test SVG upload with embedded JavaScript
- Upload HTML file for stored XSS

## PHASE 5: PATH MANIPULATION
- Use ../ in filename for path traversal upload
- Upload .htaccess to enable script execution
- Upload web.config for IIS configuration manipulation
- Test filename with special characters

## PHASE 6: POST-UPLOAD
- Locate uploaded file URL
- Verify server-side execution
- Test for file overwrite capabilities
- Check for race conditions in upload processing

For each finding: CVSS, upload technique, execution proof, remediation.""",
                system_prompt="You are a file upload security expert. Test every bypass technique. Prove code execution.",
                tools_required=["nuclei", "httpx", "ffuf"],
                estimated_tokens=4000,
                tags=["vulnerability", "file_upload", "web_shell", "rce"],
                is_preset=True
            ),
            Task(
                id="vuln_business_logic",
                name="Business Logic Testing",
                description="Test workflow manipulation, race conditions, price tampering, process bypass",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform comprehensive business logic testing:

## PHASE 1: WORKFLOW MAPPING
- Map all multi-step processes (registration, checkout, approval)
- Identify expected flow and business rules
- Document validation points and enforcement locations

## PHASE 2: PROCESS MANIPULATION
- Skip required steps (jump directly to final step)
- Change step order (submit payment before verification)
- Repeat steps that should be one-time (coupon reuse)
- Modify flow parameters between steps

## PHASE 3: VALUE MANIPULATION
- Change prices, quantities, discounts in requests
- Test negative values (negative price, negative quantity)
- Test zero values where minimum should be enforced
- Test integer overflow/underflow in calculations
- Modify currency, tax, or shipping calculations

## PHASE 4: RACE CONDITIONS
- Double-spend: submit same payment/transfer simultaneously
- Coupon/reward abuse: redeem multiple times in parallel
- Registration races: claim same username concurrently
- Inventory races: purchase beyond stock limit
- Use HTTP/1.1 pipelining for precise timing

## PHASE 5: BOUNDARY TESTING
- Test minimum/maximum limits (character counts, file sizes, quantities)
- Test with boundary values (exactly at limit, limit+1, limit-1)
- Test with very large numbers, very small numbers
- Test special values: NaN, Infinity, null, undefined

## PHASE 6: ROLE INTERACTION
- Test actions between different user types
- Merchant/customer role confusion
- Support/admin escalation via feature abuse
- Multi-tenant data leakage via shared resources

FOCUS ON BUSINESS IMPACT: Financial loss, unauthorized access, data manipulation.

For each finding: business impact, reproduction steps, CVSS, remediation.""",
                system_prompt="You are a business logic testing expert. Think like a fraudster. Test every assumption the application makes.",
                tools_required=["httpx"],
                estimated_tokens=5000,
                tags=["vulnerability", "business_logic", "race_condition", "workflow"],
                is_preset=True
            ),

            # === ADDITIONAL FULL-AUTO TASKS ===
            Task(
                id="full_api_pentest",
                name="Full API Penetration Test",
                description="Complete API security assessment: REST, GraphQL, auth, injection, business logic",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute complete API penetration test:

## PHASE 1: API DISCOVERY & MAPPING
- Discover all API endpoints (REST, GraphQL, SOAP)
- Find API documentation (Swagger/OpenAPI, GraphQL introspection)
- Map authentication mechanisms
- Identify API versions and differences

## PHASE 2: AUTHENTICATION TESTING
- Test JWT security (none alg, weak secrets, claim manipulation)
- Test OAuth flows (redirect manipulation, state bypass)
- Test API key exposure and rotation
- Test session handling and token refresh

## PHASE 3: AUTHORIZATION TESTING
- Test BOLA/IDOR on every endpoint with IDs
- Test BFLA across user roles
- Test mass assignment on create/update endpoints
- Test rate limiting and resource quotas

## PHASE 4: INJECTION TESTING
- SQL/NoSQL injection in all parameters
- GraphQL injection (if applicable)
- Command injection in API parameters
- Header injection in API requests

## PHASE 5: DATA VALIDATION
- Test input validation (type, length, format)
- Test for excessive data exposure in responses
- Check for sensitive data in URLs
- Test error handling and information disclosure

## PHASE 6: BUSINESS LOGIC
- Test API-specific business logic flaws
- Test race conditions on concurrent API calls
- Test parameter pollution and type juggling
- Test batch/bulk endpoint abuse

For each finding: OWASP API Top 10 mapping, CVSS, PoC, remediation.""",
                system_prompt="""You are an API security specialist conducting a comprehensive API pentest.
Focus on OWASP API Security Top 10. Every finding needs DATA-based proof.""",
                tools_required=["nuclei", "ffuf", "httpx", "sqlmap"],
                estimated_tokens=10000,
                tags=["full", "api", "pentest", "graphql", "rest"],
                is_preset=True
            ),
            Task(
                id="full_cloud_security",
                name="Cloud Security Assessment",
                description="Full cloud security audit: misconfigs, IAM, storage, serverless, containers",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute comprehensive cloud security assessment:

## PHASE 1: CLOUD ASSET DISCOVERY
- Identify cloud provider (AWS, Azure, GCP)
- Enumerate all cloud resources (S3, Lambda, etc.)
- Map public-facing cloud services
- Check for exposed cloud management interfaces

## PHASE 2: STORAGE SECURITY
- Test S3/Blob/GCS bucket permissions (list, read, write)
- Check for sensitive data in public storage
- Test for backup data exposure
- Check for insecure storage configurations

## PHASE 3: IAM & ACCESS CONTROL
- Test for cloud metadata exposure (SSRF → credentials)
- Check IAM role permissions (overly permissive?)
- Test for credential leakage in code/config
- Check for cross-account access misconfigs

## PHASE 4: SERVERLESS & CONTAINERS
- Test serverless function security (Lambda, Functions)
- Check container configurations (privileged, capabilities)
- Test for container escape vectors
- Check Kubernetes/Docker exposed management

## PHASE 5: NETWORK SECURITY
- Test for overly permissive security groups
- Check for public-facing internal services
- Test VPC/VNet segmentation
- Check for exposed admin ports

## PHASE 6: COMPLIANCE & HARDENING
- Check against CIS benchmarks
- Verify encryption at rest and in transit
- Check logging and monitoring configuration
- Review IAM policies for least privilege

For each finding: cloud provider, resource affected, risk level, remediation.""",
                system_prompt="""You are a cloud security expert. Assess all cloud resources for misconfigurations and security issues.
Focus on practical exploitation paths, not theoretical risks.""",
                tools_required=["nuclei", "httpx", "nmap", "ffuf"],
                estimated_tokens=8000,
                tags=["full", "cloud", "aws", "azure", "gcp", "iam"],
                is_preset=True
            ),
            Task(
                id="full_mobile_api",
                name="Mobile API Security Assessment",
                description="Test mobile application backend APIs: certificate pinning bypass, auth, data exposure",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute mobile API backend security assessment:

## PHASE 1: API DISCOVERY
- Identify mobile API endpoints (different from web)
- Check for API versioning differences
- Find undocumented mobile-specific endpoints
- Map authentication flow (JWT, OAuth, custom tokens)

## PHASE 2: AUTHENTICATION
- Test for missing certificate pinning validation server-side
- Test auth token security (expiration, rotation, revocation)
- Check for hardcoded API keys or secrets
- Test device binding and fingerprinting bypass

## PHASE 3: AUTHORIZATION
- Test all endpoints for BOLA/IDOR
- Check for server-side enforcement of client-side restrictions
- Test for user data segregation
- Check for admin API exposure to mobile clients

## PHASE 4: DATA SECURITY
- Check for excessive data in API responses
- Test for PII exposure in responses
- Check for sensitive data in push notifications
- Test for data caching issues

## PHASE 5: INJECTION & LOGIC
- Test all parameters for injection vulnerabilities
- Test business logic specific to mobile flow
- Check for race conditions in mobile-specific features
- Test deep link handling for security issues

For each finding: OWASP Mobile Top 10 mapping, CVSS, PoC, remediation.""",
                system_prompt="You are a mobile API security expert. Focus on the unique attack surface of mobile backends.",
                tools_required=["nuclei", "httpx", "ffuf"],
                estimated_tokens=6000,
                tags=["full", "mobile", "api", "ios", "android"],
                is_preset=True
            ),

            # === SPECIALIZED VULNERABILITY TASKS ===
            Task(
                id="vuln_deserialization",
                name="Deserialization Testing",
                description="Test insecure deserialization: Java, PHP, Python, .NET, Node.js",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test for insecure deserialization vulnerabilities:

## PHASE 1: IDENTIFY SERIALIZED DATA
- Check cookies, hidden fields, API parameters for serialized data
- Look for Java serialized objects (rO0AB, aced0005 in base64)
- Check for PHP serialized data (O:, a:, s: prefixes)
- Look for Python pickle (base64 with specific patterns)
- Check for .NET ViewState (__VIEWSTATE parameter)
- Check for YAML deserialization points

## PHASE 2: DETERMINE FORMAT
- Decode and identify serialization format
- Map the object types/classes being deserialized
- Identify the framework's serialization library
- Check for custom vs standard serialization

## PHASE 3: CRAFT PAYLOADS
- Java: Use ysoserial gadget chains (CommonsBeanutils, CommonsCollections)
- PHP: Craft POP chain for target framework
- Python: pickle payloads with __reduce__
- .NET: Use ysoserial.net for .NET gadget chains
- Node.js: Test node-serialize RCE payload

## PHASE 4: INJECT AND VERIFY
- Replace original serialized data with crafted payload
- Test for command execution (DNS callback, HTTP callback, time delay)
- Check for error messages revealing class loading
- Test for denial of service via recursive objects

For each finding: framework, gadget chain, proof of execution, CVSS, remediation.""",
                system_prompt="You are a deserialization security expert. Identify and exploit insecure deserialization across all platforms.",
                tools_required=["nuclei", "httpx"],
                estimated_tokens=4000,
                tags=["vulnerability", "deserialization", "java", "php", "rce"],
                is_preset=True
            ),
            Task(
                id="vuln_graphql",
                name="GraphQL Security Testing",
                description="GraphQL: introspection, injection, DoS, authorization, batch attacks",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Perform comprehensive GraphQL security testing:

## PHASE 1: DISCOVERY
- Find GraphQL endpoints (/graphql, /gql, /query, /api/graphql)
- Test introspection query (__schema, __type)
- If introspection disabled: field suggestion brute force
- Map all queries, mutations, subscriptions

## PHASE 2: AUTHORIZATION
- Test each query/mutation with different auth levels
- Check field-level authorization
- Test for nested object authorization bypass
- Test subscription access control

## PHASE 3: INJECTION
- Test all arguments for SQL/NoSQL injection
- Test for IDOR in query arguments (id, userId)
- Test for SSRF in URL-type arguments
- Check for command injection in arguments

## PHASE 4: DENIAL OF SERVICE
- Test query depth limits (deeply nested queries)
- Test query complexity limits (wide queries)
- Test batch query abuse (aliases, array queries)
- Test for resource exhaustion via subscriptions

## PHASE 5: INFORMATION DISCLOSURE
- Check for verbose error messages
- Test for type enumeration via errors
- Check for debug mode in GraphQL playground
- Test for schema exposure via error messages

For each finding: GraphQL-specific risk, CVSS, query PoC, remediation.""",
                system_prompt="You are a GraphQL security expert. Test every query, mutation, and subscription for security issues.",
                tools_required=["nuclei", "httpx"],
                estimated_tokens=4000,
                tags=["vulnerability", "graphql", "api", "injection", "dos"],
                is_preset=True
            ),
            Task(
                id="vuln_csrf_clickjacking",
                name="CSRF & Clickjacking Assessment",
                description="Test CSRF protection, clickjacking defenses, and cross-origin attacks",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test for cross-origin attack vulnerabilities:

## PHASE 1: CSRF TESTING
- Map all state-changing actions (forms, API calls)
- Check for CSRF tokens on each action
- Test token validation: remove, empty, wrong token, other user's token
- Test SameSite cookie attribute enforcement
- Test Content-Type restrictions (form-data vs json)
- Build cross-origin PoC for each vulnerable action

## PHASE 2: CLICKJACKING
- Check X-Frame-Options header on all pages
- Check CSP frame-ancestors directive
- Test iframe embedding from external domain
- Identify clickable sensitive actions (delete, transfer, settings)
- Build overlay PoC demonstrating the attack
- Test frame-busting JavaScript bypasses (sandbox attribute)

## PHASE 3: CORS MISCONFIGURATION
- Test ACAO header reflection for arbitrary origins
- Check Allow-Credentials with reflected origin
- Test null origin handling
- Identify endpoints with sensitive data and weak CORS

## PHASE 4: CROSS-ORIGIN ATTACKS
- Test postMessage handlers for origin validation
- Check WebSocket cross-origin restrictions
- Test JSONP endpoints for data leakage
- Check for cross-origin resource sharing issues

For each finding: cross-origin scenario, HTML PoC, CVSS, remediation.""",
                system_prompt="You are a cross-origin attack specialist. Build working PoC for every finding.",
                tools_required=["nuclei", "httpx"],
                estimated_tokens=4000,
                tags=["vulnerability", "csrf", "clickjacking", "cors", "cross_origin"],
                is_preset=True
            ),
            Task(
                id="vuln_cloud_native",
                name="Cloud-Native Vulnerability Testing",
                description="Test cloud-specific vulns: SSRF→metadata, S3, container escape, serverless",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Test cloud-native specific vulnerabilities:

## PHASE 1: CLOUD METADATA ACCESS
- Test SSRF vectors to cloud metadata services
- AWS: 169.254.169.254/latest/meta-data/iam/security-credentials/
- GCP: metadata.google.internal/computeMetadata/v1/
- Azure: 169.254.169.254/metadata/instance?api-version=2021-02-01
- Test IMDSv2 bypass techniques

## PHASE 2: STORAGE MISCONFIGURATIONS
- Enumerate and test S3 bucket permissions
- Test Azure Blob Storage public access
- Test GCS bucket permissions
- Check for sensitive data in public storage

## PHASE 3: CONTAINER SECURITY
- Test for Docker socket exposure
- Check for privileged container escape
- Test Kubernetes API server access
- Check for container image vulnerabilities

## PHASE 4: SERVERLESS SECURITY
- Test Lambda/Functions for injection
- Check for environment variable exposure
- Test function URL authentication
- Check for excessive IAM permissions

## PHASE 5: SUBDOMAIN TAKEOVER
- Find dangling CNAME records
- Check for unclaimed cloud resources
- Test for NS delegation takeover
- Verify takeover feasibility

For each finding: cloud platform, resource, access level, CVSS, remediation.""",
                system_prompt="You are a cloud-native security expert. Focus on cloud-specific attack vectors and misconfigurations.",
                tools_required=["nuclei", "httpx", "nmap"],
                estimated_tokens=4000,
                tags=["vulnerability", "cloud", "ssrf", "metadata", "s3", "container"],
                is_preset=True
            ),
            Task(
                id="vuln_crypto",
                name="Cryptographic Vulnerability Testing",
                description="Test encryption, hashing, random number generation, TLS, certificate issues",
                category=TaskCategory.VULNERABILITY.value,
                prompt="""Assess cryptographic security:

## PHASE 1: TLS/SSL ANALYSIS
- Scan TLS configuration (protocols, cipher suites)
- Check for deprecated protocols (SSLv3, TLS 1.0, 1.1)
- Identify weak cipher suites (RC4, DES, NULL, EXPORT)
- Test for known TLS vulnerabilities (BEAST, POODLE, Heartbleed, ROBOT, DROWN)
- Verify certificate chain and key strength

## PHASE 2: PASSWORD STORAGE
- Check for plain-text password storage (observable in responses/errors)
- Test for weak hashing (MD5, SHA1 without salt)
- Check for proper key derivation (bcrypt, scrypt, argon2)
- Test password reset token randomness

## PHASE 3: TOKEN/SESSION SECURITY
- Analyze session token entropy
- Check for predictable token generation
- Test CSRF token randomness
- Verify API key length and entropy

## PHASE 4: DATA ENCRYPTION
- Check for cleartext transmission of sensitive data
- Verify HSTS enforcement
- Check for mixed content issues
- Test for sensitive data in HTTP (non-HTTPS) requests

## PHASE 5: CRYPTOGRAPHIC MISUSE
- Check for ECB mode usage (pattern preservation)
- Test for padding oracle vulnerabilities
- Check for reused nonces/IVs
- Test for weak random number generation (Math.random vs crypto)

For each finding: crypto weakness, exploitability, CVSS, remediation.""",
                system_prompt="You are a cryptographic security expert. Analyze all crypto implementations for weaknesses.",
                tools_required=["nmap", "nuclei", "sslscan"],
                estimated_tokens=4000,
                tags=["vulnerability", "crypto", "tls", "ssl", "encryption", "hashing"],
                is_preset=True
            ),

            # === ADDITIONAL RECON TASKS ===
            Task(
                id="recon_api_mapping",
                name="API Endpoint Mapping",
                description="Comprehensive API discovery: REST, GraphQL, SOAP, WebSocket, OpenAPI/Swagger",
                category=TaskCategory.RECON.value,
                prompt="""Perform comprehensive API endpoint mapping:

1. **REST API Discovery**: Crawl and enumerate all REST endpoints
2. **GraphQL Detection**: Test /graphql, introspection, schema dump
3. **OpenAPI/Swagger**: Search for swagger.json, openapi.yaml, api-docs
4. **SOAP/WSDL**: Check for ?wsdl, /ws/, /soap/ endpoints
5. **WebSocket**: Identify ws:// and wss:// endpoints
6. **Hidden APIs**: Analyze JS files for hardcoded endpoints
7. **API Versioning**: Find and compare all API versions

Produce structured API inventory with methods, params, and auth requirements.""",
                system_prompt="You are an API reconnaissance specialist. Map every API endpoint systematically.",
                tools_required=["httpx", "katana", "ffuf", "nuclei"],
                estimated_tokens=3000,
                tags=["recon", "api", "graphql", "rest", "swagger"],
                is_preset=True
            ),
            Task(
                id="recon_js_analysis",
                name="JavaScript Security Analysis",
                description="Deep JS analysis: endpoints, secrets, DOM sinks, source maps, hidden routes",
                category=TaskCategory.RECON.value,
                prompt="""Perform deep JavaScript security analysis:

1. **File Collection**: Crawl and collect all JS files including source maps
2. **Endpoint Extraction**: Extract all API URLs from fetch/XMLHttpRequest/axios calls
3. **Secret Detection**: Search for API keys, tokens, credentials in JS
4. **DOM Sink Analysis**: Map innerHTML, eval, document.write usage
5. **Route Analysis**: Extract client-side routing tables
6. **Third-Party Audit**: Inventory libraries, check for known CVEs
7. **Sensitive Logic**: Find client-side auth, validation, business logic

Report all findings with file paths and risk assessment.""",
                system_prompt="You are a JavaScript security analyst. Extract every security-relevant detail from JavaScript.",
                tools_required=["katana", "httpx", "nuclei"],
                estimated_tokens=3000,
                tags=["recon", "javascript", "secrets", "dom", "source_maps"],
                is_preset=True
            ),

            # === ADDITIONAL REPORTING TASKS ===
            Task(
                id="report_bug_bounty",
                name="Bug Bounty Report",
                description="Generate HackerOne/Bugcrowd-style vulnerability report",
                category=TaskCategory.REPORTING.value,
                prompt="""Generate a bug bounty platform report for each finding:

For each vulnerability:
1. **Title**: Clear, descriptive title matching platform conventions
2. **Severity**: P1-P5 with CVSS 3.1 score and vector
3. **Summary**: One-paragraph executive description
4. **Steps to Reproduce**: Numbered step-by-step reproduction
5. **Impact**: Real-world attack scenario and business impact
6. **Proof of Concept**: Working PoC (curl commands, scripts, or screenshots)
7. **Remediation**: Specific fix recommendations with code examples
8. **References**: CWE, OWASP, relevant advisories

Format: One report per finding, ready to submit to bug bounty platform.
Focus on IMPACT to maximize bounty value.""",
                system_prompt="You are a top bug bounty hunter writing reports. Clear, impactful, with reproducible PoC. Focus on maximizing severity rating through demonstrated impact.",
                tools_required=[],
                estimated_tokens=3000,
                tags=["reporting", "bug_bounty", "hackerone", "bugcrowd"],
                is_preset=True
            ),
            Task(
                id="report_compliance",
                name="Compliance Security Report",
                description="Generate compliance-focused report: PCI-DSS, OWASP, SOC2, HIPAA mapping",
                category=TaskCategory.REPORTING.value,
                prompt="""Generate compliance-focused security report:

## COMPLIANCE MAPPINGS
For each finding, map to relevant frameworks:
1. **OWASP Top 10**: A01-A10 classification
2. **PCI-DSS**: Requirement mapping (Req 6.5, 8.1, etc.)
3. **CIS Controls**: Control mapping
4. **NIST 800-53**: Security control mapping
5. **SOC 2**: Trust criteria mapping

## REPORT SECTIONS
1. **Compliance Posture Summary**: Overall compliance status
2. **Gap Analysis**: Failed controls and requirements
3. **Risk Register**: Findings with compliance impact
4. **Remediation Roadmap**: Prioritized by compliance deadline
5. **Evidence Matrix**: Finding-to-requirement mapping table

Use formal compliance language suitable for auditors.""",
                system_prompt="You are a compliance security consultant. Map findings to compliance frameworks with proper control references.",
                tools_required=[],
                estimated_tokens=3000,
                tags=["reporting", "compliance", "pci", "owasp", "nist", "soc2"],
                is_preset=True
            ),

            # === EXPLOITATION TASKS ===
            Task(
                id="exploit_chain",
                name="Vulnerability Chain Exploitation",
                description="Chain multiple findings into high-impact attack scenarios",
                category=TaskCategory.EXPLOITATION.value,
                prompt="""Analyze all findings and build exploit chains:

## PHASE 1: CATALOG FINDINGS
- List all confirmed vulnerabilities with their capabilities
- Identify what each vulnerability provides (info leak, access, execution)
- Map relationships between findings

## PHASE 2: CHAIN ANALYSIS
- Open Redirect → OAuth Token Theft → Account Takeover
- SSRF → Cloud Metadata → IAM Credentials → Cloud Compromise
- XSS → CSRF → Account Takeover
- Info Disclosure → Targeted Exploit → RCE
- IDOR → PII Exposure → Social Engineering
- File Upload → Web Shell → Lateral Movement

## PHASE 3: BUILD CHAINS
- For each viable chain, build a step-by-step attack scenario
- Create working PoC that demonstrates the full chain
- Calculate combined CVSS impact score
- Document prerequisites and limitations

## PHASE 4: IMPACT ASSESSMENT
- Business impact of each chain
- Likelihood assessment
- Risk rating (Critical/High/Medium/Low)
- Time-to-compromise estimate

Present chains from highest to lowest impact.""",
                system_prompt="""You are an exploitation specialist. Chain vulnerabilities for maximum impact.
Think like an attacker: what is the worst-case scenario with these findings?""",
                tools_required=[],
                estimated_tokens=4000,
                tags=["exploitation", "chain", "impact", "attack_path"],
                is_preset=True
            ),
            Task(
                id="exploit_poc_builder",
                name="PoC Generator",
                description="Generate professional proof-of-concept exploits for all findings",
                category=TaskCategory.EXPLOITATION.value,
                prompt="""Generate proof-of-concept code for all confirmed findings:

For each vulnerability, create:

## POC FORMATS
1. **curl command**: One-liner curl demonstrating the vulnerability
2. **Python script**: Standalone Python PoC script
3. **HTML page**: For client-side vulns (XSS, CSRF, clickjacking)
4. **Browser console**: JavaScript PoC for DOM vulnerabilities

## POC REQUIREMENTS
- Must be REPRODUCIBLE (works without modification)
- Include clear success/failure indicators
- Add comments explaining each step
- Include cleanup instructions if needed
- Mark with [AUTHORIZED_TEST_ONLY] disclaimer

## VALIDATION CHECKLIST
- [ ] PoC runs without errors
- [ ] Success condition is clearly observable
- [ ] PoC is target-specific (not generic scanner output)
- [ ] Impact is demonstrated (not just detection)

Generate PoC in order of severity (Critical → Info).""",
                system_prompt="""You are a PoC development specialist. Create clean, reproducible, professional exploit code.
Every PoC must demonstrate real impact, not just detection.""",
                tools_required=[],
                estimated_tokens=5000,
                tags=["exploitation", "poc", "exploit", "code"],
                is_preset=True
            ),

            # === SPECIALIZED AUTO TASKS ===
            Task(
                id="full_recon_to_report",
                name="Automated Recon-to-Report Pipeline",
                description="Full automated pipeline: deep recon → smart vuln selection → testing → reporting",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute intelligent automated pipeline:

## STREAM 1: DEEP RECONNAISSANCE (Parallel)
- Subdomain enumeration (multi-source)
- Port scanning and service fingerprinting
- Technology stack identification
- JavaScript analysis for endpoints and secrets
- API documentation discovery
- Cloud asset enumeration

## STREAM 2: SMART VULNERABILITY SELECTION (Parallel)
Based on discovered technology stack:
- PHP/WordPress → Focus: SQLi, LFI, file upload, plugin vulns
- Java/Spring → Focus: SSTI, deserialization, EL injection
- Node.js/Express → Focus: Prototype pollution, SSRF, NoSQL
- Python/Django → Focus: SSTI, CSRF, debug mode
- .NET/ASP.NET → Focus: deserialization, ViewState, padding oracle
- GraphQL → Focus: introspection, injection, DoS, auth bypass
- API-heavy → Focus: BOLA, BFLA, mass assignment, rate limits

## STREAM 3: TOOL SCANNING (Parallel)
- Run Nuclei with technology-specific templates
- Run targeted tool scans based on discovered stack
- Process and validate tool findings

## PHASE 4: DEEP TESTING (Post-Recon)
- Test top-priority vulnerabilities per technology
- AI-driven testing with context awareness
- Validate all findings with negative controls

## PHASE 5: REPORT GENERATION
- AI-generated professional report
- Executive summary + technical details
- Per-finding CVSS, PoC, remediation

This is a fully autonomous smart pipeline. Minimize false positives.""",
                system_prompt="""You are an elite autonomous pentester. Execute the full pipeline with intelligence.
Adapt your testing strategy to the discovered technology stack.
Minimize false positives. Maximize impact.""",
                tools_required=["subfinder", "httpx", "nuclei", "katana", "nmap", "ffuf", "sqlmap"],
                estimated_tokens=15000,
                tags=["full", "automated", "smart", "pipeline", "adaptive"],
                is_preset=True
            ),
            Task(
                id="full_red_team",
                name="Red Team Assessment",
                description="Advanced red team: stealth testing, chained attacks, persistence, data exfiltration",
                category=TaskCategory.FULL_AUTO.value,
                prompt="""Execute red team assessment with advanced techniques:

## PHASE 1: PASSIVE RECONNAISSANCE
- OSINT on organization and employees
- Technology fingerprinting without direct interaction
- Identify external attack surface
- Map employee roles and access levels

## PHASE 2: INITIAL ACCESS
- Identify the most likely entry point
- Test for: exposed services, weak auth, public exploits
- Focus on high-value targets first
- Maintain stealth (avoid triggering WAF/IDS)

## PHASE 3: EXPLOITATION
- Chain vulnerabilities for maximum access
- Escalate privileges where possible
- Test for lateral movement opportunities
- Document each step of the attack chain

## PHASE 4: POST-EXPLOITATION SIMULATION
- Identify sensitive data accessible
- Map internal network/API reach
- Document what an attacker could achieve
- Assess data exfiltration paths

## PHASE 5: STEALTH & EVASION
- WAF bypass techniques for all payloads
- Encoding and obfuscation strategies
- Rate limiting avoidance
- Token rotation and session management

## PHASE 6: COMPREHENSIVE REPORTING
- Attack narrative (story-based report)
- Full attack chain documentation
- Time-to-compromise metrics
- Defensive improvement recommendations

Think like a real attacker. Prioritize stealth and impact.""",
                system_prompt="""You are a red team operator. Think strategically. Prioritize stealth and real-world attack scenarios.
Chain vulnerabilities for maximum impact. Document everything for blue team improvement.""",
                tools_required=["nmap", "nuclei", "httpx", "katana", "ffuf", "sqlmap"],
                estimated_tokens=15000,
                tags=["full", "red_team", "advanced", "stealth", "chain"],
                is_preset=True
            ),
        ]

    def create_task(self, task: Task) -> Task:
        """Create a new task"""
        if not task.id:
            task.id = f"custom_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        task.created_at = datetime.utcnow().isoformat()
        task.updated_at = task.created_at
        self.tasks[task.id] = task
        self._save_library()
        return task

    def update_task(self, task_id: str, updates: Dict) -> Optional[Task]:
        """Update an existing task"""
        if task_id not in self.tasks:
            return None
        task = self.tasks[task_id]
        for key, value in updates.items():
            if hasattr(task, key):
                setattr(task, key, value)
        task.updated_at = datetime.utcnow().isoformat()
        self._save_library()
        return task

    def delete_task(self, task_id: str) -> bool:
        """Delete a task (cannot delete presets)"""
        if task_id not in self.tasks:
            return False
        if self.tasks[task_id].is_preset:
            return False  # Cannot delete presets
        del self.tasks[task_id]
        self._save_library()
        return True

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID"""
        return self.tasks.get(task_id)

    def list_tasks(self, category: Optional[str] = None) -> List[Task]:
        """List all tasks, optionally filtered by category"""
        tasks = list(self.tasks.values())
        if category:
            tasks = [t for t in tasks if t.category == category]
        return sorted(tasks, key=lambda t: (not t.is_preset, t.name))

    def search_tasks(self, query: str) -> List[Task]:
        """Search tasks by name, description, or tags"""
        query = query.lower()
        results = []
        for task in self.tasks.values():
            if (query in task.name.lower() or
                query in task.description.lower() or
                any(query in tag.lower() for tag in task.tags)):
                results.append(task)
        return results

    def get_categories(self) -> List[str]:
        """Get all task categories"""
        return [c.value for c in TaskCategory]

    def export_task(self, task_id: str, filepath: str) -> bool:
        """Export a task to a file"""
        task = self.get_task(task_id)
        if not task:
            return False
        with open(filepath, 'w') as f:
            json.dump(asdict(task), f, indent=2)
        return True

    def import_task(self, filepath: str) -> Optional[Task]:
        """Import a task from a file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            task = Task(**data)
            task.is_preset = False  # Imported tasks are not presets
            return self.create_task(task)
        except Exception as e:
            print(f"Error importing task: {e}")
            return None


# Singleton instance
_library_instance = None

def get_task_library() -> TaskLibrary:
    """Get the singleton task library instance"""
    global _library_instance
    if _library_instance is None:
        _library_instance = TaskLibrary()
    return _library_instance
