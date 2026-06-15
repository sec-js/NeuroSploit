"""
NeuroSploit v3 - Request Repeater

Burp Suite-inspired request repeater for deep finding validation.
Sends, modifies, compares, and replays HTTP requests to verify vulnerability findings
with high confidence before reporting.

Usage:
    repeater = RequestRepeater(session)
    result = await repeater.validate_finding(finding)
    if result.reproducible:
        finding.confidence_score += result.confidence_boost
"""

import asyncio
import difflib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class RepeaterRequest:
    """A request to be sent by the repeater."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    timeout: float = 15.0


@dataclass
class RepeaterResponse:
    """Full response captured by the repeater."""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    elapsed_ms: float = 0.0
    redirect_chain: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 400 and self.error is None


@dataclass
class ComparisonResult:
    """Result of comparing two responses."""
    similarity_score: float = 0.0  # 0.0 = completely different, 1.0 = identical
    status_diff: bool = False
    body_length_diff: int = 0
    body_length_diff_pct: float = 0.0
    body_content_diff: str = ""  # unified diff summary
    new_headers: List[str] = field(default_factory=list)
    removed_headers: List[str] = field(default_factory=list)
    timing_diff_ms: float = 0.0
    significant_changes: List[str] = field(default_factory=list)


@dataclass
class MethodResult:
    """Result of testing a specific HTTP method."""
    method: str = ""
    response: Optional[RepeaterResponse] = None
    payload_reflected: bool = False
    vulnerability_signal: bool = False
    details: str = ""


@dataclass
class ValidationResult:
    """Result of repeater-based finding validation."""
    reproducible: bool = False
    reproduction_count: int = 0  # out of N retries
    attack_vs_baseline: Optional[ComparisonResult] = None
    attack_vs_control: Optional[ComparisonResult] = None
    confidence_boost: int = 0  # points to add to confidence score
    analysis: str = ""
    method_results: List[MethodResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Request Repeater
# ---------------------------------------------------------------------------

class RequestRepeater:
    """Burp Suite-like repeater: send, modify, compare, validate."""

    def __init__(self, session=None, timeout: float = 15.0, max_body_capture: int = 100000):
        self.session = session
        self.timeout = timeout
        self.max_body_capture = max_body_capture
        self._request_count = 0
        self._request_delay = 0.2  # 200ms between requests to avoid rate limiting

    async def send(self, request: RepeaterRequest, session=None) -> RepeaterResponse:
        """Send a single request and capture full response details."""
        sess = session or self.session
        if not sess:
            return RepeaterResponse(error="No HTTP session available")

        self._request_count += 1

        # Rate limiting
        if self._request_count > 1:
            await asyncio.sleep(self._request_delay)

        start_time = time.monotonic()
        try:
            timeout_obj = aiohttp.ClientTimeout(total=request.timeout or self.timeout)

            # Build request kwargs
            kwargs: Dict[str, Any] = {
                "allow_redirects": request.follow_redirects,
                "timeout": timeout_obj,
            }

            if request.headers:
                kwargs["headers"] = request.headers
            if request.cookies:
                kwargs["cookies"] = request.cookies

            method = request.method.upper()
            url = request.url

            # Handle params based on method
            if method == "GET":
                if request.params:
                    kwargs["params"] = request.params
            else:
                if request.body:
                    kwargs["data"] = request.body
                elif request.params:
                    kwargs["data"] = request.params

            redirect_chain = []

            async with sess.request(method, url, **kwargs) as resp:
                elapsed = (time.monotonic() - start_time) * 1000

                # Capture redirect history
                if hasattr(resp, 'history') and resp.history:
                    redirect_chain = [str(r.url) for r in resp.history]

                body = ""
                try:
                    raw_body = await resp.read()
                    body = raw_body[:self.max_body_capture].decode('utf-8', errors='replace')
                except Exception:
                    body = ""

                headers = {k: v for k, v in resp.headers.items()}

                return RepeaterResponse(
                    status=resp.status,
                    headers=headers,
                    body=body,
                    body_length=len(body),
                    elapsed_ms=elapsed,
                    redirect_chain=redirect_chain,
                )

        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start_time) * 1000
            return RepeaterResponse(
                elapsed_ms=elapsed,
                error=f"Timeout after {elapsed:.0f}ms",
            )
        except Exception as e:
            elapsed = (time.monotonic() - start_time) * 1000
            return RepeaterResponse(
                elapsed_ms=elapsed,
                error=f"Request error: {str(e)[:200]}",
            )

    def compare(self, baseline: RepeaterResponse, attack: RepeaterResponse) -> ComparisonResult:
        """Deep comparison between two responses."""
        result = ComparisonResult()

        # Status code diff
        result.status_diff = baseline.status != attack.status

        # Body length diff
        result.body_length_diff = abs(attack.body_length - baseline.body_length)
        if baseline.body_length > 0:
            result.body_length_diff_pct = (result.body_length_diff / baseline.body_length) * 100
        else:
            result.body_length_diff_pct = 100.0 if attack.body_length > 0 else 0.0

        # Body content diff (unified diff, first 20 diff lines)
        if baseline.body and attack.body:
            baseline_lines = baseline.body[:5000].splitlines(keepends=True)
            attack_lines = attack.body[:5000].splitlines(keepends=True)
            diff = list(difflib.unified_diff(
                baseline_lines, attack_lines,
                fromfile='baseline', tofile='attack', n=1
            ))
            result.body_content_diff = ''.join(diff[:30])

            # Similarity using SequenceMatcher
            matcher = difflib.SequenceMatcher(None, baseline.body[:5000], attack.body[:5000])
            result.similarity_score = matcher.ratio()
        elif not baseline.body and not attack.body:
            result.similarity_score = 1.0
        else:
            result.similarity_score = 0.0

        # Header diff
        baseline_keys = set(baseline.headers.keys())
        attack_keys = set(attack.headers.keys())
        result.new_headers = list(attack_keys - baseline_keys)
        result.removed_headers = list(baseline_keys - attack_keys)

        # Timing diff
        result.timing_diff_ms = attack.elapsed_ms - baseline.elapsed_ms

        # Identify significant changes
        if result.status_diff:
            result.significant_changes.append(
                f"Status: {baseline.status} → {attack.status}"
            )
        if result.body_length_diff_pct > 10:
            result.significant_changes.append(
                f"Body length: {baseline.body_length} → {attack.body_length} "
                f"({result.body_length_diff_pct:.1f}% diff)"
            )
        if result.new_headers:
            result.significant_changes.append(
                f"New headers: {', '.join(result.new_headers)}"
            )
        if abs(result.timing_diff_ms) > 2000:
            result.significant_changes.append(
                f"Timing: {baseline.elapsed_ms:.0f}ms → {attack.elapsed_ms:.0f}ms "
                f"(delta: {result.timing_diff_ms:+.0f}ms)"
            )

        return result

    async def replay_with_variations(
        self, base_request: RepeaterRequest, variations: List[Dict],
        session=None
    ) -> List[RepeaterResponse]:
        """Replay request with parameter/header/method variations."""
        responses = []
        for variation in variations:
            req = RepeaterRequest(
                url=variation.get("url", base_request.url),
                method=variation.get("method", base_request.method),
                params={**base_request.params, **variation.get("params", {})},
                headers={**base_request.headers, **variation.get("headers", {})},
                body=variation.get("body", base_request.body),
                cookies=base_request.cookies,
                follow_redirects=variation.get("follow_redirects", base_request.follow_redirects),
                timeout=base_request.timeout,
            )
            resp = await self.send(req, session=session)
            responses.append(resp)
        return responses

    async def validate_finding(
        self, finding, session=None, retries: int = 2
    ) -> ValidationResult:
        """Multi-step validation using repeater comparison.

        Steps:
        1. Send original attack request -> capture response
        2. Send benign version of same param -> capture baseline
        3. Send empty param version -> capture control
        4. Compare all three: attack vs baseline vs control
        5. Replay attack N more times -> check reproducibility
        """
        sess = session or self.session
        if not sess:
            return ValidationResult(analysis="No HTTP session available")

        result = ValidationResult()

        url = getattr(finding, 'url', '') or ''
        method = getattr(finding, 'method', 'GET') or 'GET'
        parameter = getattr(finding, 'parameter', '') or ''
        payload = getattr(finding, 'payload', '') or ''

        if not url or not parameter or not payload:
            result.analysis = "Insufficient finding details for repeater validation"
            return result

        # Extract existing params from URL
        parsed = urlparse(url)
        existing_params = dict(parse_qs(parsed.query, keep_blank_values=True))
        base_params = {k: v[0] if isinstance(v, list) else v for k, v in existing_params.items()}

        # Build base URL without query string
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 1. Attack request (original payload)
        attack_params = {**base_params, parameter: payload}
        attack_req = RepeaterRequest(url=base_url, method=method, params=attack_params)
        attack_resp = await self.send(attack_req, session=sess)

        if attack_resp.error:
            result.analysis = f"Attack request failed: {attack_resp.error}"
            return result

        # 2. Baseline request (benign value)
        benign_params = {**base_params, parameter: "neurosploit_test_benign_value"}
        baseline_req = RepeaterRequest(url=base_url, method=method, params=benign_params)
        baseline_resp = await self.send(baseline_req, session=sess)

        # 3. Control request (empty value)
        control_params = {**base_params, parameter: ""}
        control_req = RepeaterRequest(url=base_url, method=method, params=control_params)
        control_resp = await self.send(control_req, session=sess)

        # 4. Compare
        if baseline_resp.is_success:
            result.attack_vs_baseline = self.compare(baseline_resp, attack_resp)
        if control_resp.is_success:
            result.attack_vs_control = self.compare(control_resp, attack_resp)

        # 5. Reproducibility — replay attack N more times
        reproduction_successes = 0
        for i in range(retries):
            retry_resp = await self.send(attack_req, session=sess)
            if retry_resp.is_success and not retry_resp.error:
                # Check if response is similar to original attack response
                retry_comparison = self.compare(attack_resp, retry_resp)
                if retry_comparison.similarity_score > 0.8:
                    reproduction_successes += 1

        result.reproduction_count = reproduction_successes
        result.reproducible = reproduction_successes >= (retries // 2 + 1)

        # 6. Analyze and score
        analysis_parts = []
        confidence_boost = 0

        # Reproducibility boost
        if result.reproducible:
            confidence_boost += 10
            analysis_parts.append(
                f"Reproducible: {reproduction_successes}/{retries} replays matched"
            )
        else:
            analysis_parts.append(
                f"Not reproducible: only {reproduction_successes}/{retries} replays matched"
            )

        # Attack vs baseline difference
        if result.attack_vs_baseline:
            cmp = result.attack_vs_baseline
            if cmp.similarity_score < 0.9:
                confidence_boost += 5
                analysis_parts.append(
                    f"Attack differs from baseline (similarity: {cmp.similarity_score:.2f})"
                )
                if cmp.significant_changes:
                    analysis_parts.append(f"Changes: {'; '.join(cmp.significant_changes[:3])}")
            else:
                confidence_boost -= 5
                analysis_parts.append(
                    f"Attack similar to baseline (similarity: {cmp.similarity_score:.2f}) — "
                    "payload may not have effect"
                )

        # Attack vs control difference
        if result.attack_vs_control:
            cmp = result.attack_vs_control
            if cmp.status_diff:
                analysis_parts.append(
                    f"Status differs from empty control: {cmp.significant_changes[0] if cmp.significant_changes else 'status change'}"
                )

        result.confidence_boost = max(-10, min(15, confidence_boost))
        result.analysis = "; ".join(analysis_parts) if analysis_parts else "No analysis available"

        return result

    async def test_method_variations(
        self, url: str, param: str, payload: str, session=None,
        methods: Optional[List[str]] = None
    ) -> List[MethodResult]:
        """Test same payload across GET/POST/PUT/PATCH/DELETE.

        Returns which methods produce vulnerability signals.
        """
        sess = session or self.session
        if not sess:
            return []

        if methods is None:
            methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

        results = []
        for method in methods:
            req = RepeaterRequest(
                url=url,
                method=method,
                params={param: payload},
                follow_redirects=True,
            )
            resp = await self.send(req, session=sess)

            mr = MethodResult(method=method, response=resp)

            if resp.is_success and resp.body:
                # Check if payload is reflected in response
                if payload in resp.body:
                    mr.payload_reflected = True
                    mr.vulnerability_signal = True
                    mr.details = f"{method}: payload reflected in response (status {resp.status})"
                elif resp.status != 405:  # Method Not Allowed
                    mr.details = f"{method}: accepted (status {resp.status}), payload not reflected"
            elif resp.status == 405:
                mr.details = f"{method}: Method Not Allowed"
            elif resp.error:
                mr.details = f"{method}: {resp.error}"
            else:
                mr.details = f"{method}: status {resp.status}"

            results.append(mr)

        return results

    async def test_method_override(
        self, url: str, param: str, payload: str,
        target_method: str = "DELETE", session=None
    ) -> List[MethodResult]:
        """Test method override techniques to bypass method restrictions."""
        sess = session or self.session
        if not sess:
            return []

        override_techniques = [
            {"method": "POST", "headers": {"X-HTTP-Method-Override": target_method}},
            {"method": "POST", "headers": {"X-Method-Override": target_method}},
            {"method": "POST", "headers": {"X-HTTP-Method": target_method}},
            {"method": "POST", "params": {"_method": target_method}},
            {"method": "POST", "params": {"http_method": target_method}},
        ]

        results = []
        for technique in override_techniques:
            params = {param: payload}
            params.update(technique.get("params", {}))

            req = RepeaterRequest(
                url=url,
                method=technique["method"],
                params=params,
                headers=technique.get("headers", {}),
                follow_redirects=True,
            )
            resp = await self.send(req, session=sess)

            override_desc = ""
            if "headers" in technique:
                hdr = list(technique["headers"].keys())[0]
                override_desc = f"{hdr}: {target_method}"
            else:
                prm = [k for k in technique.get("params", {}) if k != param][0]
                override_desc = f"?{prm}={target_method}"

            mr = MethodResult(
                method=f"POST→{target_method} ({override_desc})",
                response=resp,
            )

            if resp.is_success and resp.body and payload in resp.body:
                mr.payload_reflected = True
                mr.vulnerability_signal = True
                mr.details = f"Override accepted: {override_desc} (status {resp.status})"
            elif resp.status == 405:
                mr.details = f"Override rejected: {override_desc}"
            else:
                mr.details = f"Override: {override_desc} → status {resp.status}"

            results.append(mr)

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Return repeater usage statistics."""
        return {
            "total_requests": self._request_count,
            "request_delay_ms": self._request_delay * 1000,
        }
