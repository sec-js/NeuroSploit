"""
CLI Instructions Builder - Generates prompt files for CLI agents inside Kali containers.

Creates:
1. instructions.md - Master prompt with target, output format, rules
2. CLAUDE.md - Auto-loaded project context for Claude Code CLI
3. .gemini (or equivalent) for other CLI tools
"""
import os
import json
import logging
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

# Pre-installed tools in the Kali container
KALI_TOOLS_PREINSTALLED = [
    "nmap", "nuclei", "httpx", "sqlmap", "nikto", "ffuf", "gobuster",
    "subfinder", "katana", "dnsx", "dalfox", "waybackurls", "uncover",
    "masscan", "whatweb", "curl", "wget", "python3", "git", "jq",
    "dig", "whois", "netcat",
]

KALI_TOOLS_INSTALLABLE = [
    "wpscan", "dirb", "hydra", "john", "hashcat", "testssl.sh", "sslscan",
    "enum4linux", "dnsrecon", "fierce", "amass", "medusa",
    "dirsearch", "wfuzz", "arjun", "wafw00f", "sslyze", "commix",
    "gau", "gitleaks", "httprobe",
]


def build_instructions(
    target: str,
    auth_headers: Optional[Dict] = None,
    methodology_path: str = "/opt/pentest/methodology.md",
    extra_context: Optional[str] = None,
) -> str:
    """Build the master instructions file for the CLI agent."""

    auth_section = ""
    if auth_headers:
        auth_section = f"""## Authentication
Use these headers in ALL requests:
```
{json.dumps(auth_headers, indent=2)}
```
"""
    else:
        auth_section = """## Authentication
No authentication provided. Test unauthenticated access only.
If you discover login forms, note them but do NOT attempt brute-force without auth credentials.
"""

    extra_section = ""
    if extra_context:
        extra_section = f"""## Additional Context
{extra_context}
"""

    return f"""# AUTOMATED PENETRATION TEST - MISSION BRIEFING

## Target
{target}

{auth_section}

## Your Mission
You are an expert penetration tester conducting a comprehensive security assessment against the target above.
You have full access to a Kali Linux environment with all tools pre-installed.

## Methodology
Read and follow the comprehensive methodology file at: {methodology_path}
Execute each phase systematically. Do not skip phases.

{extra_section}

## Available Tools

**Pre-installed** (use directly):
{', '.join(KALI_TOOLS_PREINSTALLED)}

**Installable on-demand** (use `apt-get install -y <tool>` or `pip3 install <tool>`):
{', '.join(KALI_TOOLS_INSTALLABLE)}

You can also install any other tool available in Kali repositories.

## CRITICAL: Output Format for Findings

When you discover and CONFIRM a vulnerability, output it in EXACTLY this format:

===FINDING_START===
{{
  "title": "SQL Injection in login endpoint",
  "severity": "critical",
  "vulnerability_type": "sqli_error",
  "endpoint": "{target}/api/login",
  "parameter": "username",
  "evidence": "The response contained: You have an error in your SQL syntax...",
  "poc_code": "curl -X POST '{target}/api/login' -d 'username=admin\\'--&password=x'",
  "request": "POST /api/login HTTP/1.1\\nHost: ...\\nContent-Type: application/x-www-form-urlencoded\\n\\nusername=admin'--&password=x",
  "response": "HTTP/1.1 500 Internal Server Error\\n...\\n{{\\"error\\": \\"SQL syntax error near...\\"}}",
  "impact": "An attacker can extract all database contents including user credentials",
  "cvss_score": 9.8
}}
===FINDING_END===

## Phase Progress Tracking

Mark each phase with:
```
echo "[PHASE] Starting Phase N: Description"
```

When ALL testing is complete:
```
echo "[COMPLETE] Penetration test finished"
```

## Rules

1. **VERIFY before reporting**: Only output findings with REAL evidence (actual HTTP responses, error messages, data leakage). Do NOT report theoretical vulnerabilities.
2. **Be thorough**: Test ALL phases in the methodology. Test every endpoint, parameter, and header you discover.
3. **Output immediately**: Report each finding as soon as you confirm it. Don't wait until the end.
4. **Include real evidence**: Copy actual HTTP requests/responses in the finding. Show the exact command that confirmed the vulnerability.
5. **Use multiple tools**: Cross-validate findings with different tools when possible (e.g., confirm SQLi with both manual testing AND sqlmap).
6. **Follow the methodology**: The methodology file contains detailed testing procedures for 100+ vulnerability types. Follow it step by step.
7. **Escalate findings**: If you find a low-severity issue, check if it can be escalated (e.g., information disclosure → credential access → admin takeover).
8. **Document everything**: Even if a test is negative, log what you tested so we know the coverage.
9. **Time management**: Spend more time on high-risk areas (auth, injection, file access) and less on informational checks.
10. **No hallucination**: If a tool produces no output or an error, report what happened honestly. Do NOT fabricate results.

## Vulnerability Types to Test (Priority Order)

**Critical Priority**: SQL Injection, Command Injection, SSRF, XXE, File Upload, Auth Bypass, IDOR
**High Priority**: XSS (Reflected, Stored, DOM), SSTI, Path Traversal, LFI/RFI, CSRF, JWT Manipulation
**Medium Priority**: Open Redirect, CORS Misconfiguration, CRLF Injection, Rate Limiting, Information Disclosure
**Lower Priority**: Security Headers, SSL/TLS Issues, Clickjacking, Directory Listing, HTTP Methods

## Start Now
Begin by reading {methodology_path}, then:
1. Reconnaissance: Probe the target, discover endpoints, detect technologies
2. Map the attack surface: Forms, APIs, parameters, headers, cookies
3. Test systematically: Follow the methodology phase by phase
4. Report findings: Output each confirmed vulnerability in the format above
"""


def build_claude_md(target: str, auth_headers: Optional[Dict] = None) -> str:
    """Build CLAUDE.md file (auto-read by Claude Code CLI as project context)."""
    auth_note = ""
    if auth_headers:
        auth_note = f"\nAuthentication headers are provided in instructions.md."

    return f"""# Penetration Testing Agent - Project Context

## Mission
Comprehensive penetration test against: {target}
{auth_note}

## Working Directory
- `/opt/pentest/methodology.md` - Full testing methodology (READ THIS FIRST)
- `/opt/pentest/instructions.md` - Target details, output format, rules
- `/opt/pentest/output.log` - Your output is being captured here

## Output Format
For EVERY confirmed vulnerability, output between markers:
===FINDING_START===
{{"title": "...", "severity": "critical|high|medium|low|info", "vulnerability_type": "...", "endpoint": "...", "evidence": "...", "poc_code": "..."}}
===FINDING_END===

## Key Rules
- ONLY report CONFIRMED vulnerabilities with real evidence
- Include actual HTTP requests/responses as proof
- Use Kali Linux tools (nmap, nuclei, sqlmap, ffuf, etc.)
- Follow the methodology systematically
- Mark phases: echo "[PHASE] Starting Phase N: ..."
- When done: echo "[COMPLETE] Penetration test finished"

## Environment
- Kali Linux with full toolset
- Network access to target
- All Kali tools available (install more with apt-get if needed)
"""


def build_gemini_instructions(target: str, auth_headers: Optional[Dict] = None) -> str:
    """Build instructions optimized for Gemini CLI."""
    # Gemini CLI uses GEMINI.md or similar - same content, adapted format
    return build_claude_md(target, auth_headers)


def load_methodology(methodology_path: str) -> str:
    """Load methodology file content."""
    if not methodology_path:
        return ""

    # Resolve environment variable
    if methodology_path.startswith("$"):
        var_name = methodology_path.lstrip("$").strip("{}")
        methodology_path = os.getenv(var_name, "")

    if not methodology_path or not os.path.exists(methodology_path):
        # Try common locations
        common_paths = [
            "/opt/Prompts-PenTest/pentestcompleto_en.md",
            "/opt/Prompts-PenTest/pentestcompleto.md",
            "/opt/Prompts-PenTest/PROMPT_PENTEST_FINAL_COMPLETO.md",
        ]
        for path in common_paths:
            if os.path.exists(path):
                methodology_path = path
                break
        else:
            logger.warning("[CLI-BUILDER] No methodology file found")
            return ""

    try:
        with open(methodology_path, "r", encoding="utf-8") as f:
            content = f.read()
        logger.info(f"[CLI-BUILDER] Loaded methodology: {methodology_path} ({len(content)} chars)")
        return content
    except Exception as e:
        logger.error(f"[CLI-BUILDER] Failed to load methodology: {e}")
        return ""
