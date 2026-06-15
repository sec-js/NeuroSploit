"""
CLI Output Parser - 3-tier finding extraction from CLI agent output.

Tier 1: JSON marker blocks (===FINDING_START=== / ===FINDING_END===)
Tier 2: Regex patterns for known tool output formats (nuclei, nmap, sqlmap)
Tier 3: AI-assisted extraction via LLM for unstructured text
"""
import json
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

logger = logging.getLogger(__name__)

# JSON finding markers used in CLI instructions
FINDING_START = "===FINDING_START==="
FINDING_END = "===FINDING_END==="

# Progress markers
PHASE_PATTERN = re.compile(r'\[PHASE\]\s*(.+)', re.IGNORECASE)
COMPLETE_PATTERN = re.compile(r'\[COMPLETE\]', re.IGNORECASE)
PROGRESS_PATTERN = re.compile(r'\[PROGRESS\]\s*(\d+)%?\s*(.*)', re.IGNORECASE)

# Severity keywords for regex extraction
SEVERITY_MAP = {
    "critical": "critical", "crit": "critical",
    "high": "high",
    "medium": "medium", "med": "medium",
    "low": "low",
    "info": "info", "informational": "info",
}

# Nuclei JSONL output pattern
NUCLEI_JSON_PATTERN = re.compile(r'^\{.*"template-id".*"matched-at".*\}$', re.MULTILINE)

# Generic vulnerability patterns in CLI output
VULN_PATTERNS = [
    # [VULNERABILITY] Title - Severity
    re.compile(
        r'\[(?:VULNERABILITY|VULN|FINDING|ALERT)\]\s*(.+?)(?:\s*[-–]\s*(critical|high|medium|low|info))?$',
        re.IGNORECASE | re.MULTILINE
    ),
    # SQLMap style: Parameter 'X' is vulnerable
    re.compile(
        r"(?:Parameter|Param)\s+['\"]?(\w+)['\"]?\s+(?:is|appears)\s+(?:vulnerable|injectable)",
        re.IGNORECASE
    ),
    # Nuclei text: [severity] [template-id] URL
    re.compile(
        r'\[(critical|high|medium|low|info)\]\s*\[([^\]]+)\]\s*(https?://\S+)',
        re.IGNORECASE
    ),
]


@dataclass
class ParsedFinding:
    """A finding extracted from CLI output."""
    title: str
    severity: str = "medium"
    vulnerability_type: str = ""
    endpoint: str = ""
    parameter: str = ""
    evidence: str = ""
    poc_code: str = ""
    request: str = ""
    response: str = ""
    impact: str = ""
    cvss_score: Optional[float] = None
    source: str = "cli_agent"

    def to_dict(self) -> Dict:
        d = {
            "title": self.title,
            "severity": self.severity,
            "vulnerability_type": self.vulnerability_type or self._infer_vuln_type(),
            "affected_endpoint": self.endpoint,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "poc_code": self.poc_code,
            "request": self.request,
            "response": self.response,
            "impact": self.impact,
            "source": self.source,
            "ai_status": "confirmed",
            "ai_verified": True,
            "confidence_score": 70,
        }
        if self.cvss_score:
            d["cvss_score"] = self.cvss_score
        return d

    def _infer_vuln_type(self) -> str:
        """Infer vulnerability type from title keywords."""
        title_lower = self.title.lower()
        type_map = {
            "sql injection": "sqli_error", "sqli": "sqli_error",
            "xss": "xss_reflected", "cross-site scripting": "xss_reflected",
            "stored xss": "xss_stored", "dom xss": "xss_dom",
            "command injection": "command_injection", "rce": "command_injection",
            "ssrf": "ssrf", "server-side request": "ssrf",
            "lfi": "lfi", "local file": "lfi", "path traversal": "path_traversal",
            "rfi": "rfi", "remote file": "rfi",
            "xxe": "xxe", "xml external": "xxe",
            "ssti": "ssti", "template injection": "ssti",
            "csrf": "csrf", "cross-site request": "csrf",
            "idor": "idor", "insecure direct": "idor",
            "open redirect": "open_redirect",
            "file upload": "file_upload",
            "directory listing": "directory_listing",
            "information disclosure": "information_disclosure",
            "sensitive data": "sensitive_data_exposure",
            "security header": "security_headers",
            "ssl": "ssl_issues", "tls": "ssl_issues",
            "cors": "cors_misconfig",
            "crlf": "crlf_injection",
            "nosql": "nosql_injection",
            "ldap": "ldap_injection",
            "jwt": "jwt_manipulation",
            "auth bypass": "auth_bypass",
            "brute force": "brute_force",
            "rate limit": "rate_limit_bypass",
            "clickjacking": "clickjacking",
            "http smuggling": "http_smuggling",
            "cache poison": "cache_poisoning",
            "deserialization": "insecure_deserialization",
            "prototype pollution": "prototype_pollution",
            "graphql": "graphql_injection",
            "host header": "host_header_injection",
            "race condition": "race_condition",
            "business logic": "business_logic",
        }
        for keyword, vtype in type_map.items():
            if keyword in title_lower:
                return vtype
        return "unknown"


class CLIOutputParser:
    """3-tier output parser for CLI agent findings."""

    def __init__(self):
        self._seen_finding_hashes: Set[str] = set()
        self._buffer = ""  # Accumulates partial JSON blocks across chunks
        self._unparsed_chunks: List[str] = []
        self._total_findings = 0
        self._phases_seen: List[str] = []
        self._is_complete = False

    def parse_chunk(self, text: str) -> List[ParsedFinding]:
        """Parse a chunk of CLI output. Returns newly extracted findings."""
        if not text or not text.strip():
            return []

        findings: List[ParsedFinding] = []

        # Track progress markers
        for m in PHASE_PATTERN.finditer(text):
            phase = m.group(1).strip()
            if phase not in self._phases_seen:
                self._phases_seen.append(phase)
                logger.info(f"[CLI-PARSER] Phase: {phase}")

        if COMPLETE_PATTERN.search(text):
            self._is_complete = True

        # Tier 1: JSON marker blocks
        combined = self._buffer + text
        tier1 = self._extract_json_markers(combined)
        findings.extend(tier1)

        # Tier 2: Regex patterns
        tier2 = self._extract_regex_findings(text)
        findings.extend(tier2)

        # Tier 2b: Nuclei JSONL
        tier2b = self._extract_nuclei_jsonl(text)
        findings.extend(tier2b)

        # Track unparsed text for later AI extraction
        if not tier1 and not tier2 and not tier2b:
            if len(text.strip()) > 50:
                self._unparsed_chunks.append(text)

        # Deduplicate
        unique = []
        for f in findings:
            h = f"{f.title}|{f.endpoint}|{f.severity}"
            if h not in self._seen_finding_hashes:
                self._seen_finding_hashes.add(h)
                unique.append(f)
                self._total_findings += 1

        return unique

    def get_unparsed_text(self, clear: bool = True) -> str:
        """Get accumulated unparsed text for AI extraction."""
        text = "\n".join(self._unparsed_chunks)
        if clear:
            self._unparsed_chunks = []
        return text

    @property
    def is_complete(self) -> bool:
        return self._is_complete

    @property
    def phases(self) -> List[str]:
        return self._phases_seen

    @property
    def total_findings(self) -> int:
        return self._total_findings

    def _extract_json_markers(self, text: str) -> List[ParsedFinding]:
        """Tier 1: Extract findings from ===FINDING_START=== / ===FINDING_END=== blocks."""
        findings = []
        remaining_buffer = ""

        # Find all complete blocks
        parts = text.split(FINDING_START)
        for i, part in enumerate(parts):
            if i == 0:
                continue  # Text before first marker

            if FINDING_END in part:
                json_text, after = part.split(FINDING_END, 1)
                json_text = json_text.strip()
                try:
                    data = json.loads(json_text)
                    f = self._json_to_finding(data)
                    if f:
                        findings.append(f)
                except json.JSONDecodeError:
                    # Try to fix common JSON issues
                    fixed = self._try_fix_json(json_text)
                    if fixed:
                        f = self._json_to_finding(fixed)
                        if f:
                            findings.append(f)
                    else:
                        logger.debug(f"[CLI-PARSER] Invalid JSON in marker block: {json_text[:100]}")
            else:
                # Incomplete block - save to buffer for next chunk
                remaining_buffer = FINDING_START + part

        self._buffer = remaining_buffer
        return findings

    def _extract_regex_findings(self, text: str) -> List[ParsedFinding]:
        """Tier 2: Extract findings using regex patterns."""
        findings = []

        for pattern in VULN_PATTERNS:
            for match in pattern.finditer(text):
                groups = match.groups()
                if len(groups) >= 1:
                    title = groups[0].strip()
                    severity = "medium"
                    endpoint = ""

                    if len(groups) >= 2 and groups[1]:
                        sev = groups[1].lower().strip()
                        severity = SEVERITY_MAP.get(sev, "medium")

                    if len(groups) >= 3 and groups[2]:
                        endpoint = groups[2].strip()

                    # Skip very short or generic titles
                    if len(title) < 5 or title.lower() in ("n/a", "none", "test"):
                        continue

                    findings.append(ParsedFinding(
                        title=title,
                        severity=severity,
                        endpoint=endpoint,
                        evidence=match.group(0),
                    ))

        return findings

    def _extract_nuclei_jsonl(self, text: str) -> List[ParsedFinding]:
        """Tier 2b: Extract findings from Nuclei JSONL output."""
        findings = []

        for match in NUCLEI_JSON_PATTERN.finditer(text):
            try:
                data = json.loads(match.group(0))
                template_id = data.get("template-id", "")
                matched_at = data.get("matched-at", "")
                info = data.get("info", {})
                severity = info.get("severity", "medium").lower()
                name = info.get("name", template_id)
                description = info.get("description", "")

                findings.append(ParsedFinding(
                    title=f"[Nuclei] {name}",
                    severity=SEVERITY_MAP.get(severity, "medium"),
                    vulnerability_type=self._nuclei_to_vuln_type(template_id),
                    endpoint=matched_at,
                    evidence=f"Template: {template_id}\n{description}",
                    poc_code=f"nuclei -t {template_id} -u {matched_at}",
                ))
            except json.JSONDecodeError:
                continue

        return findings

    def _json_to_finding(self, data: Dict) -> Optional[ParsedFinding]:
        """Convert a JSON dict to ParsedFinding."""
        title = data.get("title", "").strip()
        if not title:
            return None

        severity = data.get("severity", "medium").lower()
        severity = SEVERITY_MAP.get(severity, severity)
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        return ParsedFinding(
            title=title,
            severity=severity,
            vulnerability_type=data.get("vulnerability_type", ""),
            endpoint=data.get("endpoint", data.get("affected_endpoint", "")),
            parameter=data.get("parameter", ""),
            evidence=data.get("evidence", ""),
            poc_code=data.get("poc_code", data.get("poc", "")),
            request=data.get("request", ""),
            response=data.get("response", ""),
            impact=data.get("impact", ""),
            cvss_score=data.get("cvss_score"),
        )

    @staticmethod
    def _try_fix_json(text: str) -> Optional[Dict]:
        """Try to fix common JSON issues."""
        # Remove trailing commas
        fixed = re.sub(r',\s*}', '}', text)
        fixed = re.sub(r',\s*]', ']', fixed)
        # Try to parse
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        # Try wrapping in braces
        if not fixed.startswith('{'):
            try:
                return json.loads('{' + fixed + '}')
            except json.JSONDecodeError:
                pass
        return None

    @staticmethod
    def _nuclei_to_vuln_type(template_id: str) -> str:
        """Map nuclei template ID to vulnerability type."""
        tid = template_id.lower()
        mappings = {
            "sqli": "sqli_error", "sql-injection": "sqli_error",
            "xss": "xss_reflected", "cross-site-scripting": "xss_reflected",
            "ssrf": "ssrf", "server-side-request": "ssrf",
            "lfi": "lfi", "local-file": "lfi",
            "rfi": "rfi", "remote-file": "rfi",
            "rce": "command_injection", "command-injection": "command_injection",
            "ssti": "ssti", "template-injection": "ssti",
            "xxe": "xxe", "xml-external": "xxe",
            "redirect": "open_redirect",
            "cors": "cors_misconfig",
            "crlf": "crlf_injection",
            "csrf": "csrf",
            "header-injection": "header_injection",
            "directory-listing": "directory_listing",
            "info-disclosure": "information_disclosure",
            "exposure": "sensitive_data_exposure",
            "ssl": "ssl_issues", "tls": "ssl_issues",
            "default-login": "default_credentials",
            "misconfig": "security_headers",
        }
        for key, vtype in mappings.items():
            if key in tid:
                return vtype
        return "unknown"


# AI-assisted extraction prompt template
AI_EXTRACT_PROMPT = """Analyze this penetration testing CLI output and extract any CONFIRMED vulnerability findings.

IMPORTANT: Only extract findings where there is clear evidence of a vulnerability (error messages,
data leakage, successful exploitation). Do NOT extract theoretical or untested issues.

CLI Output:
{output}

For each confirmed finding, provide:
- title: concise vulnerability name
- severity: critical|high|medium|low|info
- vulnerability_type: e.g., sqli_error, xss_reflected, ssrf, command_injection, etc.
- endpoint: the affected URL
- parameter: affected parameter (if applicable)
- evidence: the actual proof (HTTP response, error, data leaked)
- poc_code: the command or request that confirmed it

Respond ONLY with valid JSON:
{{"findings": [{{"title": "...", "severity": "...", "vulnerability_type": "...", "endpoint": "...", "parameter": "...", "evidence": "...", "poc_code": "..."}}]}}

If no confirmed findings, respond: {{"findings": []}}"""


async def ai_extract_findings(text: str, llm, max_chars: int = 8000) -> List[ParsedFinding]:
    """Tier 3: AI-assisted extraction of findings from unstructured CLI output."""
    if not text or len(text.strip()) < 100:
        return []

    # Truncate to max_chars
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated]"

    prompt = AI_EXTRACT_PROMPT.format(output=text)

    try:
        response = await llm.generate(
            prompt=prompt,
            system="You are a security finding extractor. Extract only confirmed vulnerabilities with real evidence.",
            max_tokens=2000,
        )

        if not response:
            return []

        # Extract JSON from response
        json_match = re.search(r'\{.*"findings".*\}', response, re.DOTALL)
        if not json_match:
            return []

        data = json.loads(json_match.group(0))
        findings_data = data.get("findings", [])

        findings = []
        for fd in findings_data:
            if not fd.get("title"):
                continue
            findings.append(ParsedFinding(
                title=fd["title"],
                severity=fd.get("severity", "medium"),
                vulnerability_type=fd.get("vulnerability_type", ""),
                endpoint=fd.get("endpoint", ""),
                parameter=fd.get("parameter", ""),
                evidence=fd.get("evidence", ""),
                poc_code=fd.get("poc_code", ""),
            ))

        logger.info(f"[CLI-PARSER] AI extracted {len(findings)} findings")
        return findings

    except Exception as e:
        logger.warning(f"[CLI-PARSER] AI extraction failed: {e}")
        return []
