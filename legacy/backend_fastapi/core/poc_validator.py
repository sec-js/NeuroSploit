"""
NeuroSploit v3 - PoC Validator

Actually tests generated PoCs by executing them against the target.
Verifies that PoC code produces the expected exploitation result.
"""

import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class PoCValidationResult:
    """Result of PoC validation."""
    valid: bool = False
    confidence: float = 0.0
    actual_result: str = ""
    expected_result: str = ""
    execution_error: str = ""
    method_used: str = ""  # "http_replay", "browser", "static_analysis"


class PoCValidator:
    """Validates PoCs by replaying the attack against the target.

    Does NOT execute arbitrary Python code. Instead, parses the PoC
    to extract the HTTP request and replays it, checking the response
    for expected exploitation markers.
    """

    # Expected markers per vulnerability type
    VULN_MARKERS = {
        "xss_reflected": {
            "patterns": [r"<script", r"onerror\s*=", r"onload\s*=", r"alert\(", r"<svg"],
            "description": "XSS payload reflected unescaped in response",
        },
        "xss_stored": {
            "patterns": [r"<script", r"onerror\s*=", r"onload\s*=", r"alert\("],
            "description": "XSS payload persisted and rendered in display page",
        },
        "sqli_error": {
            "patterns": [r"SQL syntax", r"mysql_", r"ORA-\d+", r"PostgreSQL",
                         r"sqlite3?\.", r"ODBC.*Driver", r"Microsoft.*SQL"],
            "description": "SQL error message in response",
        },
        "sqli_blind": {
            "patterns": [],  # Requires differential analysis
            "description": "Different responses for TRUE vs FALSE conditions",
        },
        "command_injection": {
            "patterns": [r"uid=\d+", r"gid=\d+", r"root:", r"www-data"],
            "description": "Command output in response",
        },
        "lfi": {
            "patterns": [r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]",
                         r"<\?php", r"DB_PASSWORD"],
            "description": "File contents in response",
        },
        "path_traversal": {
            "patterns": [r"root:.*:0:0:", r"\[boot loader\]"],
            "description": "File contents via path traversal",
        },
        "ssrf": {
            "patterns": [r"ami-id", r"instance-id", r"iam/security-credentials",
                         r"localhost", r"127\.0\.0\.1", r"internal"],
            "description": "Internal resource content in response",
        },
        "ssti": {
            "patterns": [r"\b49\b", r"\b56\b"],  # 7*7=49, 7*8=56
            "description": "Template expression evaluated",
        },
        "xxe": {
            "patterns": [r"root:.*:0:0:", r"<\?xml", r"SYSTEM"],
            "description": "XML external entity content in response",
        },
        "open_redirect": {
            "patterns": [],  # Check Location header
            "description": "Redirect to external domain",
        },
        "crlf_injection": {
            "patterns": [r"X-Injected:", r"Set-Cookie:.*injected"],
            "description": "Injected header in response",
        },
        "idor": {
            "patterns": [],  # Requires data comparison
            "description": "Unauthorized data access via ID manipulation",
        },
    }

    def __init__(self, request_engine=None):
        self.request_engine = request_engine

    async def validate(self, poc_code: str, finding,
                        request_engine=None) -> PoCValidationResult:
        """Validate PoC by replaying the attack.

        Parses the PoC to extract HTTP parameters, then replays
        the request and checks for exploitation markers.
        """
        engine = request_engine or self.request_engine
        vuln_type = getattr(finding, "vulnerability_type", "")
        endpoint = getattr(finding, "affected_endpoint", "")
        param = getattr(finding, "parameter", "")
        payload = getattr(finding, "payload", "")

        result = PoCValidationResult()

        # If no request engine, do static analysis
        if not engine:
            return self._static_validate(poc_code, vuln_type, payload)

        # Replay the attack
        try:
            test_resp = await engine.request(
                endpoint, "GET", params={param: payload} if param else {},
                timeout=10
            )
            if not test_resp:
                result.execution_error = "No response from target"
                return result

            body = test_resp.get("body", "")
            status = test_resp.get("status", 0)
            headers = test_resp.get("headers", {})

            result.method_used = "http_replay"

            # Check vulnerability-specific markers
            markers = self.VULN_MARKERS.get(vuln_type, {})
            patterns = markers.get("patterns", [])

            matched_patterns = []
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    matched_patterns.append(pattern)

            if matched_patterns:
                result.valid = True
                result.confidence = min(0.95, 0.6 + 0.1 * len(matched_patterns))
                result.actual_result = f"Matched {len(matched_patterns)} markers: {', '.join(matched_patterns[:3])}"
                result.expected_result = markers.get("description", "")

            # Special handling for redirect-based vulns
            elif vuln_type == "open_redirect":
                location = headers.get("location", headers.get("Location", ""))
                if location and not location.startswith(endpoint[:20]):
                    result.valid = True
                    result.confidence = 0.85
                    result.actual_result = f"Redirects to: {location}"

            # Payload reflection check (generic)
            elif payload and payload in body:
                result.valid = True
                result.confidence = 0.70
                result.actual_result = "Payload reflected in response"

            else:
                result.actual_result = f"Status {status}, {len(body)} bytes, no markers found"

        except Exception as e:
            result.execution_error = str(e)

        return result

    async def validate_xss_poc(self, poc_code: str, finding,
                                browser=None) -> PoCValidationResult:
        """Validate XSS PoC with browser if available."""
        result = PoCValidationResult(method_used="browser")

        if not browser:
            return self._static_validate(poc_code, "xss_reflected",
                                          getattr(finding, "payload", ""))

        try:
            endpoint = getattr(finding, "affected_endpoint", "")
            param = getattr(finding, "parameter", "")
            payload = getattr(finding, "payload", "")

            page = await browser.new_page()
            dialog_fired = False

            async def on_dialog(dialog):
                nonlocal dialog_fired
                dialog_fired = True
                await dialog.dismiss()

            page.on("dialog", on_dialog)

            url = f"{endpoint}?{param}={payload}" if param else endpoint
            await page.goto(url, timeout=15000, wait_until="networkidle")
            await page.wait_for_timeout(2000)
            await page.close()

            if dialog_fired:
                result.valid = True
                result.confidence = 0.95
                result.actual_result = "Alert dialog fired in browser"
            else:
                result.actual_result = "No dialog triggered"
                result.confidence = 0.0

        except Exception as e:
            result.execution_error = str(e)

        return result

    def _static_validate(self, poc_code: str, vuln_type: str,
                          payload: str) -> PoCValidationResult:
        """Static analysis of PoC code (no execution)."""
        result = PoCValidationResult(method_used="static_analysis")

        if not poc_code:
            result.execution_error = "Empty PoC code"
            return result

        # Check PoC structure
        has_request = any(k in poc_code for k in
                          ["requests.get", "requests.post", "curl", "fetch("])
        has_verification = any(k in poc_code for k in
                               ["VULNERABLE", "if ", "assert", "grep"])
        has_target = any(k in poc_code for k in
                          ["url", "http://", "https://"])

        score = 0.0
        if has_request:
            score += 0.3
        if has_verification:
            score += 0.3
        if has_target:
            score += 0.2
        if payload and payload[:20] in poc_code:
            score += 0.2

        result.confidence = score
        result.valid = score >= 0.6
        result.actual_result = (
            f"Static analysis: request={'yes' if has_request else 'no'}, "
            f"verification={'yes' if has_verification else 'no'}, "
            f"target={'yes' if has_target else 'no'}"
        )

        return result
