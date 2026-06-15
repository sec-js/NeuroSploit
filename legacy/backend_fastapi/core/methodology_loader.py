"""
Methodology Loader - Parses external pentest methodology .md files and indexes them
for smart injection into all LLM call sites in the autonomous agent.

Supports FASE-based methodology documents (like pentestcompleto.md) as well as
generic markdown documents. Maps sections to vulnerability types and agent contexts
for targeted injection with per-context character budgets.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ─── FASE → Vulnerability Type Mapping ───────────────────────────────────────
# Maps each FASE section to the agent's vulnerability type identifiers.
# These match the 100 types in vuln_engine/registry.py.

FASE_VULN_TYPE_MAP: Dict[str, List[str]] = {
    "fase_0": [],  # Recon - broad, no specific vuln types
    "fase_1": [],  # Architecture analysis - broad strategy
    "fase_2": [
        "jwt_manipulation", "session_fixation", "broken_auth", "auth_bypass",
        "insecure_password_reset", "account_takeover", "cookie_manipulation",
        "captcha_bypass", "session_hijacking",
    ],
    "fase_3": [
        "idor", "bola", "bfla", "privilege_escalation", "forced_browsing",
        "auth_bypass", "mass_assignment",
    ],
    "fase_4": [
        "race_condition", "business_logic", "workflow_bypass",
        "payment_manipulation", "insufficient_anti_automation",
    ],
    "fase_5": [],  # CVE/Zero-day - applies to all types via strategy context
    "fase_6": [
        "ssrf", "cloud_misconfig", "s3_bucket_misconfiguration",
        "cloud_metadata_exposure", "serverless_misconfiguration",
        "kubernetes_misconfig", "iam_misconfig",
    ],
    "fase_7": [],  # OWASP WSTG reference - strategy context
    "fase_8": [
        "bola", "bfla", "mass_assignment", "excessive_data_exposure",
        "api_abuse", "api_rate_limiting", "rest_api_versioning",
        "broken_auth", "ssrf",
    ],
    "fase_9": [
        "graphql_injection", "graphql_introspection", "graphql_dos",
        "websocket_security", "grpc_security",
    ],
    "fase_10": [
        "sqli_error", "sqli_union", "sqli_blind", "sqli_time", "sqli_oob",
        "nosql_injection", "ssti", "ldap_injection", "xpath_injection",
        "crlf_injection", "header_injection", "parameter_pollution",
        "command_injection", "email_injection", "expression_language_injection",
        "log_injection", "orm_injection", "ssi_injection", "xslt_injection",
        "csv_injection",
    ],
    "fase_11": [
        "xss_reflected", "xss_stored", "xss_dom", "cors_misconfig",
        "csp_bypass", "clickjacking", "open_redirect", "prototype_pollution",
        "html_injection", "css_injection", "dom_clobbering", "postmessage_abuse",
        "dangling_markup",
    ],
    "fase_12": [
        "http_request_smuggling", "cache_poisoning", "cache_deception",
        "http2_smuggling", "connection_pool_poisoning", "http_method_tampering",
    ],
    "fase_13": [
        "file_upload", "lfi", "rfi", "path_traversal", "zip_slip",
    ],
    "fase_14": [
        "ssrf", "dns_rebinding", "blind_ssrf",
    ],
    "fase_15": [
        "broken_auth", "insecure_password_reset", "brute_force",
        "account_enumeration", "captcha_bypass", "session_fixation",
        "account_takeover", "mfa_bypass",
    ],
    "fase_16": [
        "mass_assignment", "rate_limit_bypass", "api_rate_limiting",
        "brute_force",
    ],
    "fase_17": [
        "information_disclosure", "subdomain_takeover", "directory_listing",
        "default_credentials", "security_headers", "ssl_tls",
        "debug_endpoints", "backup_files", "source_code_exposure",
        "sensitive_data_exposure",
    ],
    "fase_18": [
        "insecure_deserialization",
    ],
    "fase_19": [
        "denial_of_service", "graphql_dos", "redos", "xml_bomb",
    ],
    "fase_20": [
        "xxe",
    ],
}


# ─── FASE → Agent Context Mapping ────────────────────────────────────────────
# Maps each FASE to the agent contexts where it should be injected.

FASE_CONTEXT_MAP: Dict[str, List[str]] = {
    "fase_0": ["strategy"],
    "fase_1": ["strategy"],
    "fase_2": ["testing", "verification", "confirmation"],
    "fase_3": ["testing", "verification", "confirmation"],
    "fase_4": ["testing", "confirmation", "strategy"],
    "fase_5": ["strategy", "testing"],
    "fase_6": ["testing", "verification"],
    "fase_7": ["strategy"],
    "fase_8": ["testing", "verification", "confirmation"],
    "fase_9": ["testing", "verification"],
    "fase_10": ["testing", "verification", "confirmation"],
    "fase_11": ["testing", "verification", "confirmation"],
    "fase_12": ["testing", "verification"],
    "fase_13": ["testing", "verification", "confirmation"],
    "fase_14": ["testing", "verification"],
    "fase_15": ["testing", "verification", "confirmation"],
    "fase_16": ["testing", "confirmation"],
    "fase_17": ["testing", "reporting"],
    "fase_18": ["testing", "verification", "confirmation"],
    "fase_19": ["testing"],
    "fase_20": ["testing", "verification", "confirmation"],
}


# ─── Keyword → Vuln Type Mapping (for non-FASE documents) ───────────────────

KEYWORD_VULN_MAP: Dict[str, List[str]] = {
    "sql injection": ["sqli_error", "sqli_union", "sqli_blind", "sqli_time"],
    "xss": ["xss_reflected", "xss_stored", "xss_dom"],
    "cross-site scripting": ["xss_reflected", "xss_stored", "xss_dom"],
    "ssrf": ["ssrf", "blind_ssrf"],
    "server-side request forgery": ["ssrf", "blind_ssrf"],
    "xxe": ["xxe"],
    "xml external entity": ["xxe"],
    "ssti": ["ssti"],
    "template injection": ["ssti"],
    "idor": ["idor", "bola"],
    "broken access": ["bola", "bfla", "idor"],
    "deserialization": ["insecure_deserialization"],
    "file upload": ["file_upload"],
    "lfi": ["lfi", "path_traversal"],
    "local file inclusion": ["lfi", "path_traversal"],
    "rfi": ["rfi"],
    "remote file inclusion": ["rfi"],
    "command injection": ["command_injection"],
    "cors": ["cors_misconfig"],
    "csrf": ["csrf"],
    "clickjacking": ["clickjacking"],
    "open redirect": ["open_redirect"],
    "jwt": ["jwt_manipulation"],
    "oauth": ["broken_auth", "auth_bypass"],
    "race condition": ["race_condition"],
    "prototype pollution": ["prototype_pollution"],
    "request smuggling": ["http_request_smuggling"],
    "cache poisoning": ["cache_poisoning"],
    "graphql": ["graphql_injection", "graphql_introspection", "graphql_dos"],
    "websocket": ["websocket_security"],
    "nosql": ["nosql_injection"],
    "ldap": ["ldap_injection"],
    "crlf": ["crlf_injection"],
    "mass assignment": ["mass_assignment"],
    "rate limit": ["rate_limit_bypass", "api_rate_limiting"],
}


@dataclass
class MethodologySection:
    """A parsed section from a methodology document."""
    fase_id: str
    title: str
    content: str
    sub_sections: Dict[str, str] = field(default_factory=dict)
    vuln_types: List[str] = field(default_factory=list)
    contexts: List[str] = field(default_factory=list)

    @property
    def char_count(self) -> int:
        return len(self.content)


class MethodologyIndex:
    """Indexed methodology for fast retrieval by vuln_type and context."""

    def __init__(self):
        self.sections: Dict[str, MethodologySection] = {}
        self.vuln_type_index: Dict[str, List[str]] = {}  # vuln_type → [fase_ids]
        self.context_index: Dict[str, List[str]] = {}    # context → [fase_ids]

    def add_section(self, section: MethodologySection) -> None:
        self.sections[section.fase_id] = section
        for vt in section.vuln_types:
            self.vuln_type_index.setdefault(vt, []).append(section.fase_id)
        for ctx in section.contexts:
            self.context_index.setdefault(ctx, []).append(section.fase_id)

    def get_for_vuln_and_context(
        self,
        vuln_type: str,
        context: str,
        max_chars: int = 2000,
    ) -> str:
        """Get methodology text relevant to both vuln_type and context.

        Prefers sub-sections that mention the vuln_type for precision.
        Truncates to max_chars budget.
        """
        if not self.sections:
            return ""

        candidate_fase_ids: set = set()

        # Find FASEs matching vuln_type
        if vuln_type:
            # Direct match
            for fid in self.vuln_type_index.get(vuln_type, []):
                candidate_fase_ids.add(fid)
            # Fuzzy match: try without common suffixes
            base_vt = vuln_type.replace("_reflected", "").replace("_stored", "").replace("_dom", "")
            base_vt = base_vt.replace("_error", "").replace("_union", "").replace("_blind", "").replace("_time", "")
            if base_vt != vuln_type:
                for fid in self.vuln_type_index.get(base_vt, []):
                    candidate_fase_ids.add(fid)

        # Filter by context
        if context:
            context_fases = set(self.context_index.get(context, []))
            if candidate_fase_ids:
                # Intersect for precision
                filtered = candidate_fase_ids & context_fases
                if filtered:
                    candidate_fase_ids = filtered
                # If intersection is empty, keep vuln_type matches (they're more specific)
            else:
                # No vuln_type specified: use all context matches
                candidate_fase_ids = context_fases

        if not candidate_fase_ids:
            return ""

        # Build output, preferring targeted sub-sections
        parts: List[str] = []
        total = 0

        for fase_id in sorted(candidate_fase_ids):
            section = self.sections.get(fase_id)
            if not section:
                continue

            remaining = max_chars - total
            if remaining < 100:
                break

            # Try to find a targeted sub-section first
            best_sub = self._find_best_subsection(section, vuln_type)

            if best_sub:
                title, content = best_sub
                text = f"### {title}\n{content}"
            else:
                # Use full section content, truncated
                text = f"### {section.title}\n{section.content}"

            if len(text) > remaining:
                text = text[:remaining]

            if len(text) < 50:
                continue  # Skip tiny fragments

            parts.append(text)
            total += len(text)

        return "\n\n".join(parts)

    def _find_best_subsection(
        self, section: MethodologySection, vuln_type: str
    ) -> Optional[tuple]:
        """Find the sub-section most relevant to a vuln_type."""
        if not vuln_type or not section.sub_sections:
            return None

        # Normalize for matching
        vt_variants = set()
        vt_lower = vuln_type.lower()
        vt_variants.add(vt_lower)
        vt_variants.add(vt_lower.replace("_", " "))
        vt_variants.add(vt_lower.replace("_", "-"))

        # Common name mappings
        name_map = {
            "sqli": "sql injection",
            "xss_reflected": "reflected xss",
            "xss_stored": "stored xss",
            "xss_dom": "dom xss",
            "lfi": "lfi",
            "rfi": "rfi",
            "ssrf": "ssrf",
            "ssti": "ssti",
            "xxe": "xxe",
            "nosql_injection": "nosql",
            "crlf_injection": "crlf",
            "cors_misconfig": "cors",
            "insecure_deserialization": "deserialization",
            "http_request_smuggling": "request smuggling",
            "cache_poisoning": "cache poisoning",
            "prototype_pollution": "prototype pollution",
        }
        mapped = name_map.get(vt_lower)
        if mapped:
            vt_variants.add(mapped)

        best_score = 0
        best = None

        for sub_title, sub_content in section.sub_sections.items():
            title_lower = sub_title.lower()
            score = 0
            for variant in vt_variants:
                if variant in title_lower:
                    score = 10  # Title match is strongest
                    break
                if variant in sub_content[:500].lower():
                    score = max(score, 5)  # Content match

            if score > best_score:
                best_score = score
                best = (sub_title, sub_content)

        return best


class MethodologyLoader:
    """Loads and indexes methodology documents from files or DB prompts."""

    def load_from_file(self, file_path: str) -> MethodologyIndex:
        """Load a .md methodology file and build an index."""
        if not os.path.exists(file_path):
            logger.warning(f"Methodology file not found: {file_path}")
            return MethodologyIndex()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read methodology file: {e}")
            return MethodologyIndex()

        sections = self._parse_markdown_sections(content)
        index = MethodologyIndex()
        for section in sections:
            index.add_section(section)

        logger.info(
            f"[METHODOLOGY] Loaded {len(sections)} sections from {file_path} "
            f"({sum(s.char_count for s in sections)} chars, "
            f"{len(index.vuln_type_index)} vuln types mapped)"
        )
        return index

    def load_from_db_prompts(self, prompts: List[Dict]) -> MethodologyIndex:
        """Index database-loaded custom prompts into a MethodologyIndex."""
        index = MethodologyIndex()

        for i, p in enumerate(prompts):
            content = p.get("content", "")
            if not content:
                continue

            parsed_vulns = p.get("parsed_vulnerabilities", [])

            # Try FASE-based parsing first
            sections = self._parse_markdown_sections(content)

            if not sections:
                # Treat entire content as one section
                vuln_types = [
                    v.get("type", "") for v in parsed_vulns if v.get("type")
                ]
                if not vuln_types:
                    vuln_types = self._detect_vuln_types_by_keywords(content)

                section = MethodologySection(
                    fase_id=f"db_prompt_{i}",
                    title=p.get("name", f"Custom Prompt {i}"),
                    content=content,
                    sub_sections={},
                    vuln_types=vuln_types,
                    contexts=["testing", "strategy", "confirmation",
                              "verification", "reporting"],
                )
                sections = [section]

            for section in sections:
                index.add_section(section)

        logger.info(
            f"[METHODOLOGY] Indexed {len(index.sections)} sections from "
            f"{len(prompts)} DB prompts"
        )
        return index

    def merge_indices(self, *indices: MethodologyIndex) -> MethodologyIndex:
        """Merge multiple MethodologyIndex objects into one."""
        merged = MethodologyIndex()
        for idx in indices:
            for section in idx.sections.values():
                # Avoid duplicate fase_ids
                if section.fase_id not in merged.sections:
                    merged.add_section(section)
        return merged

    def _parse_markdown_sections(self, content: str) -> List[MethodologySection]:
        """Parse a markdown document into indexed sections.

        Looks for FASE headings first, falls back to generic ## headings.
        """
        sections = self._parse_fase_sections(content)
        if sections:
            return sections

        # Fallback: parse generic ## headings
        return self._parse_generic_sections(content)

    def _parse_fase_sections(self, content: str) -> List[MethodologySection]:
        """Parse FASE-structured methodology documents."""
        # Match ## FASE N: or # FASE N: or ## 🔐 FASE N: (with emoji)
        fase_pattern = re.compile(
            r'^(#{1,2})\s*(?:[^\w]*\s*)?FASE\s+(\d+)\s*[:\-]?\s*(.*?)$',
            re.MULTILINE | re.IGNORECASE,
        )

        matches = list(fase_pattern.finditer(content))
        if not matches:
            return []

        sections: List[MethodologySection] = []

        # Also capture pre-FASE content (e.g., recon steps before FASE 1)
        if matches[0].start() > 200:
            pre_content = content[:matches[0].start()].strip()
            if pre_content:
                pre_subs = self._extract_sub_sections(pre_content)
                sections.append(MethodologySection(
                    fase_id="fase_0",
                    title="Recon & Preparation",
                    content=pre_content,
                    sub_sections=pre_subs,
                    vuln_types=FASE_VULN_TYPE_MAP.get("fase_0", []),
                    contexts=FASE_CONTEXT_MAP.get("fase_0", ["strategy"]),
                ))

        for i, match in enumerate(matches):
            fase_num = match.group(2)
            fase_title = f"FASE {fase_num}: {match.group(3).strip()}"
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            body = content[start:end].strip()

            fase_id = f"fase_{fase_num}"
            sub_sections = self._extract_sub_sections(body)
            vuln_types = FASE_VULN_TYPE_MAP.get(fase_id, [])
            contexts = FASE_CONTEXT_MAP.get(fase_id, ["testing"])

            # If not in our hardcoded map, try keyword detection
            if not vuln_types:
                vuln_types = self._detect_vuln_types_by_keywords(body)

            sections.append(MethodologySection(
                fase_id=fase_id,
                title=fase_title,
                content=body,
                sub_sections=sub_sections,
                vuln_types=vuln_types,
                contexts=contexts,
            ))

        return sections

    def _parse_generic_sections(self, content: str) -> List[MethodologySection]:
        """Parse generic ## heading structured documents."""
        heading_pattern = re.compile(r'^##\s+(.*?)$', re.MULTILINE)
        matches = list(heading_pattern.finditer(content))

        if not matches:
            return []

        sections: List[MethodologySection] = []

        for i, match in enumerate(matches):
            title = match.group(1).strip()
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            body = content[start:end].strip()

            vuln_types = self._detect_vuln_types_by_keywords(
                title + " " + body[:1000]
            )
            sub_sections = self._extract_sub_sections(body)

            sections.append(MethodologySection(
                fase_id=f"section_{i}",
                title=title,
                content=body,
                sub_sections=sub_sections,
                vuln_types=vuln_types,
                contexts=["testing", "strategy"],
            ))

        return sections

    def _extract_sub_sections(self, body: str) -> Dict[str, str]:
        """Extract ### sub-sections from a section body."""
        sub_pattern = re.compile(r'^###\s+(.*?)$', re.MULTILINE)
        sub_matches = list(sub_pattern.finditer(body))
        sub_sections: Dict[str, str] = {}

        for j, sub in enumerate(sub_matches):
            sub_title = sub.group(1).strip()
            sub_start = sub.end()
            sub_end = (
                sub_matches[j + 1].start()
                if j + 1 < len(sub_matches)
                else len(body)
            )
            sub_content = body[sub_start:sub_end].strip()
            if sub_content:
                sub_sections[sub_title] = sub_content

        return sub_sections

    def _detect_vuln_types_by_keywords(self, text: str) -> List[str]:
        """Detect vuln types from text content via keyword matching."""
        text_lower = text.lower()
        found: List[str] = []
        seen: set = set()

        for keyword, types in KEYWORD_VULN_MAP.items():
            if keyword in text_lower:
                for vt in types:
                    if vt not in seen:
                        found.append(vt)
                        seen.add(vt)

        return found
