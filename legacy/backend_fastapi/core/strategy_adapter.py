"""
NeuroSploit v3 - Strategy Adapter

Mid-scan strategy adaptation: signal tracking, 403 bypass attempts,
diminishing returns detection, endpoint health monitoring, and
dynamic reprioritization for autonomous pentesting.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class EndpointHealth:
    """Health tracking for a single endpoint."""
    url: str
    total_tests: int = 0
    consecutive_failures: int = 0
    status_403_count: int = 0
    status_429_count: int = 0
    timeout_count: int = 0
    findings_count: int = 0
    is_dead: bool = False
    waf_detected: bool = False
    avg_response_time: float = 0.0
    _response_times: list = field(default_factory=list)
    tested_types: set = field(default_factory=set)
    last_test_time: float = 0.0


@dataclass
class VulnTypeStats:
    """Tracking stats per vulnerability type."""
    vuln_type: str
    total_tests: int = 0
    confirmed_count: int = 0
    rejected_count: int = 0
    waf_block_count: int = 0
    success_rate: float = 0.0
    avg_confidence: float = 0.0
    _confidences: list = field(default_factory=list)


class BypassTechniques:
    """403 Forbidden bypass with 15+ techniques."""

    HEADER_BYPASSES = [
        {"X-Original-URL": "{path}"},
        {"X-Rewrite-URL": "{path}"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "localhost"},
    ]

    PATH_BYPASSES = [
        "{path}/.",           # /admin/.
        "{path}/./",          # /admin/./
        "{path}..;/",         # /admin..;/
        "/{path}//",          # //admin//
        "{path}%20",          # /admin%20
        "{path}%00",          # /admin%00 (null byte)
        "{path}?",            # /admin?
        "{path}???",          # /admin???
        "{path}#",            # /admin#
        "/%2e/{path_no_slash}",    # /%2e/admin
        "/{path_no_slash};/",      # /admin;/
        "/{path_no_slash}..;/",    # /admin..;/
        "/{path_upper}",           # /ADMIN
    ]

    METHOD_BYPASSES = ["OPTIONS", "PUT", "PATCH", "TRACE", "HEAD"]

    @classmethod
    async def attempt_bypass(
        cls,
        request_engine,
        url: str,
        original_method: str = "GET",
        original_response: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """Try bypass techniques on a 403'd URL.
        
        Returns the first successful bypass response, or None.
        """
        parsed = urlparse(url)
        path = parsed.path
        path_no_slash = path.lstrip("/")
        path_upper = path.upper()
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1: Header bypasses
        for header_set in cls.HEADER_BYPASSES:
            try:
                headers = {}
                for k, v in header_set.items():
                    headers[k] = v.format(path=path)
                
                result = await request_engine.request(
                    url, method=original_method, headers=headers
                )
                if result and result.status not in (403, 401, 0):
                    logger.info(f"403 bypass via header {list(header_set.keys())[0]}: {url}")
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "bypass_method": f"header:{list(header_set.keys())[0]}",
                    }
            except Exception:
                continue

        # Phase 2: Path bypasses
        for path_tmpl in cls.PATH_BYPASSES:
            try:
                new_path = path_tmpl.format(
                    path=path, path_no_slash=path_no_slash, path_upper=path_upper
                )
                bypass_url = f"{base_url}{new_path}"
                if parsed.query:
                    bypass_url += f"?{parsed.query}"
                
                result = await request_engine.request(
                    bypass_url, method=original_method
                )
                if result and result.status not in (403, 401, 404, 0):
                    logger.info(f"403 bypass via path '{new_path}': {url}")
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "bypass_method": f"path:{new_path}",
                    }
            except Exception:
                continue

        # Phase 3: Method bypasses
        for method in cls.METHOD_BYPASSES:
            if method == original_method:
                continue
            try:
                result = await request_engine.request(url, method=method)
                if result and result.status not in (403, 401, 405, 0):
                    logger.info(f"403 bypass via method {method}: {url}")
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "bypass_method": f"method:{method}",
                    }
            except Exception:
                continue

        return None


class StrategyAdapter:
    """Mid-scan strategy adaptation engine.
    
    Monitors endpoint health, vuln type success rates, and global signals
    to dynamically adjust testing strategy.
    
    Features:
    - Dead endpoint detection (skip after N consecutive failures)
    - Hot endpoint promotion (more testing on productive endpoints)
    - 403 bypass (15+ techniques via BypassTechniques)
    - Diminishing returns (stop testing unproductive type+endpoint combos)
    - Dynamic rate limiting adjustment
    - Priority recomputation every N tests
    - Global statistics and reporting
    """

    DEAD_ENDPOINT_THRESHOLD = 3        # Consecutive failures before marking dead
    DIMINISHING_RETURNS_THRESHOLD = 10 # Max failed payloads before skipping type
    ADAPTATION_INTERVAL = 50           # Tests between priority recomputations
    MAX_403_BYPASS_PER_URL = 2         # Max bypass attempts per URL
    HOT_ENDPOINT_THRESHOLD = 2         # Findings to mark endpoint as "hot"

    def __init__(self, memory=None):
        self.memory = memory
        self._endpoints: Dict[str, EndpointHealth] = {}
        self._vuln_stats: Dict[str, VulnTypeStats] = {}
        self._global_test_count = 0
        self._global_finding_count = 0
        self._last_adaptation_time = time.time()
        self._last_adaptation_count = 0
        self._403_bypass_attempts: Dict[str, int] = {}  # url -> attempt count
        self._bypass_successes: List[Dict] = []
        self._hot_endpoints: set = set()
        self._rate_limit_detected = False
        self._global_delay = 0.1

    def _get_endpoint(self, url: str) -> EndpointHealth:
        """Get or create endpoint health tracker."""
        # Normalize URL (strip query params for grouping)
        parsed = urlparse(url)
        key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if key not in self._endpoints:
            self._endpoints[key] = EndpointHealth(url=key)
        return self._endpoints[key]

    def _get_vuln_stats(self, vuln_type: str) -> VulnTypeStats:
        """Get or create vuln type stats tracker."""
        if vuln_type not in self._vuln_stats:
            self._vuln_stats[vuln_type] = VulnTypeStats(vuln_type=vuln_type)
        return self._vuln_stats[vuln_type]

    def record_test_result(
        self,
        url: str,
        vuln_type: str,
        status: int,
        was_confirmed: bool,
        confidence: int = 0,
        duration: float = 0.0,
        error_type: str = "success",
    ):
        """Record the result of a vulnerability test.
        
        Called after each test attempt to update all tracking state.
        """
        ep = self._get_endpoint(url)
        vs = self._get_vuln_stats(vuln_type)
        self._global_test_count += 1

        # Update endpoint health
        ep.total_tests += 1
        ep.last_test_time = time.time()
        ep.tested_types.add(vuln_type)

        if duration > 0:
            ep._response_times.append(duration)
            if len(ep._response_times) > 30:
                ep._response_times = ep._response_times[-20:]
            ep.avg_response_time = sum(ep._response_times) / len(ep._response_times)

        if status == 403:
            ep.status_403_count += 1
        elif status == 429:
            ep.status_429_count += 1
            self._rate_limit_detected = True
        elif error_type in ("timeout", "connection_error"):
            ep.timeout_count += 1

        # Track consecutive failures
        if was_confirmed:
            ep.consecutive_failures = 0
            ep.findings_count += 1
            self._global_finding_count += 1
            if ep.findings_count >= self.HOT_ENDPOINT_THRESHOLD:
                self._hot_endpoints.add(ep.url)
        elif status in (0, 403, 429) or error_type != "success":
            ep.consecutive_failures += 1
            if ep.consecutive_failures >= self.DEAD_ENDPOINT_THRESHOLD:
                ep.is_dead = True
                logger.debug(f"Endpoint marked dead: {ep.url}")
        else:
            # Got a response but no finding -- not a consecutive failure
            ep.consecutive_failures = 0

        # Update vuln type stats
        vs.total_tests += 1
        if was_confirmed:
            vs.confirmed_count += 1
        else:
            vs.rejected_count += 1
        if status == 403 and error_type == "waf_blocked":
            vs.waf_block_count += 1
        if confidence > 0:
            vs._confidences.append(confidence)
            if len(vs._confidences) > 50:
                vs._confidences = vs._confidences[-30:]
            vs.avg_confidence = sum(vs._confidences) / len(vs._confidences)
        vs.success_rate = vs.confirmed_count / vs.total_tests if vs.total_tests > 0 else 0

    def should_test_endpoint(self, url: str) -> bool:
        """Check if an endpoint should still be tested."""
        ep = self._get_endpoint(url)
        if ep.is_dead:
            return False
        return True

    def should_test_type(self, vuln_type: str, url: str) -> bool:
        """Check if a vuln type should be tested on an endpoint."""
        ep = self._get_endpoint(url)
        vs = self._get_vuln_stats(vuln_type)

        # Skip if endpoint is dead
        if ep.is_dead:
            return False

        # Skip if this type has 0% success after 15+ global tests AND waf blocks
        if vs.total_tests >= 15 and vs.success_rate == 0 and vs.waf_block_count > 5:
            logger.debug(f"Skipping {vuln_type}: 0% success + WAF blocks")
            return False

        return True

    def should_reduce_payloads(self, vuln_type: str, tested_count: int) -> bool:
        """Check if we should stop testing payloads (diminishing returns)."""
        vs = self._get_vuln_stats(vuln_type)

        # Allow more payloads for types with good success rate
        if vs.success_rate > 0.1:
            return tested_count >= self.DIMINISHING_RETURNS_THRESHOLD * 2

        return tested_count >= self.DIMINISHING_RETURNS_THRESHOLD

    def should_attempt_403_bypass(self, url: str) -> bool:
        """Check if we should try 403 bypass for this URL."""
        ep = self._get_endpoint(url)
        attempts = self._403_bypass_attempts.get(ep.url, 0)
        return (
            ep.status_403_count >= 2
            and attempts < self.MAX_403_BYPASS_PER_URL
        )

    async def try_bypass_403(self, request_engine, url: str, method: str = "GET") -> Optional[Dict]:
        """Attempt 403 bypass with multiple techniques."""
        ep = self._get_endpoint(url)
        self._403_bypass_attempts[ep.url] = self._403_bypass_attempts.get(ep.url, 0) + 1

        result = await BypassTechniques.attempt_bypass(
            request_engine, url, original_method=method
        )

        if result:
            self._bypass_successes.append({
                "url": url,
                "method": result.get("bypass_method", "unknown"),
                "status": result.get("status", 0),
            })
            # Revive endpoint
            ep.is_dead = False
            ep.consecutive_failures = 0
            logger.info(f"403 bypass success: {url} via {result.get('bypass_method')}")

        return result

    def get_dynamic_delay(self) -> float:
        """Get current recommended delay between requests."""
        if self._rate_limit_detected:
            return max(self._global_delay, 1.0)
        return self._global_delay

    def should_recompute_priorities(self) -> bool:
        """Check if it's time to recompute testing priorities."""
        tests_since = self._global_test_count - self._last_adaptation_count
        time_since = time.time() - self._last_adaptation_time
        return tests_since >= self.ADAPTATION_INTERVAL or time_since >= 120

    def recompute_priorities(self, vuln_types: List[str]) -> List[str]:
        """Recompute vuln type priority order based on observed results.
        
        Promotes types with high success rates and deprioritizes failed types.
        Returns reordered list of vuln types.
        """
        self._last_adaptation_count = self._global_test_count
        self._last_adaptation_time = time.time()

        def type_score(vt):
            vs = self._get_vuln_stats(vt)
            if vs.total_tests == 0:
                return 0.5  # Untested -- medium priority
            # Weighted: success rate + bonus for confirmed findings
            score = vs.success_rate * 0.6
            if vs.confirmed_count > 0:
                score += 0.3
            # Penalty for WAF blocks
            if vs.waf_block_count > vs.total_tests * 0.5:
                score -= 0.2
            return score

        scored = [(vt, type_score(vt)) for vt in vuln_types]
        scored.sort(key=lambda x: x[1], reverse=True)

        reordered = [vt for vt, _ in scored]
        logger.debug(f"Priority recomputed: {reordered[:5]}")
        return reordered

    def get_hot_endpoints(self) -> List[str]:
        """Get endpoints that have yielded multiple findings."""
        return list(self._hot_endpoints)

    def get_report_context(self) -> Dict:
        """Get strategy stats for report generation."""
        dead_count = sum(1 for e in self._endpoints.values() if e.is_dead)
        hot_count = len(self._hot_endpoints)

        top_types = sorted(
            self._vuln_stats.values(),
            key=lambda v: v.confirmed_count,
            reverse=True,
        )[:5]

        return {
            "total_tests": self._global_test_count,
            "total_findings": self._global_finding_count,
            "endpoints_tested": len(self._endpoints),
            "endpoints_dead": dead_count,
            "endpoints_hot": hot_count,
            "rate_limiting_detected": self._rate_limit_detected,
            "bypass_successes": len(self._bypass_successes),
            "bypass_details": self._bypass_successes[:10],
            "top_vuln_types": [
                {
                    "type": v.vuln_type,
                    "tests": v.total_tests,
                    "confirmed": v.confirmed_count,
                    "rate": f"{v.success_rate:.1%}",
                }
                for v in top_types
            ],
            "hot_endpoints": list(self._hot_endpoints)[:10],
        }

    def get_endpoint_summary(self) -> Dict[str, Dict]:
        """Get summary of all tracked endpoints."""
        return {
            url: {
                "tests": ep.total_tests,
                "findings": ep.findings_count,
                "dead": ep.is_dead,
                "403s": ep.status_403_count,
                "avg_response": round(ep.avg_response_time, 3),
            }
            for url, ep in self._endpoints.items()
        }

    # ── Checkpoint Refinement (Phase 3 Extension) ──────────────────────

    async def checkpoint_refine(
        self,
        progress_pct: float,
        findings: List,
        tested_types: set,
        all_endpoints: List,
        llm=None,
        budget=None,
    ) -> Dict:
        """Refine strategy at 30%, 60%, 90% progress checkpoints.

        Returns a strategy update dict with recommendations.
        """
        update = {
            "widen_scope": False,
            "narrow_scope": False,
            "skip_types": [],
            "promote_types": [],
            "new_tasks": [],
            "message": "",
        }

        finding_count = len(findings) if findings else 0
        confirmed_types = set()
        for f in (findings or []):
            vt = getattr(f, "vulnerability_type", "")
            if vt:
                confirmed_types.add(vt)

        # 30% checkpoint: early assessment
        if progress_pct <= 0.35:
            if finding_count == 0:
                update["widen_scope"] = True
                update["message"] = "0 findings at 30% — widening scope"
                # Promote untested types
                all_types = set(self._vuln_stats.keys())
                untested = [vt for vt in tested_types if vt not in all_types]
                update["promote_types"] = untested[:10]
            elif finding_count >= 3:
                update["narrow_scope"] = True
                update["promote_types"] = list(confirmed_types)
                update["message"] = f"{finding_count} findings at 30% — focusing on successful types"

        # 60% checkpoint: diminishing returns check
        elif progress_pct <= 0.65:
            # Skip types with 0% success after significant testing
            for vt, stats in self._vuln_stats.items():
                if stats.total_tests >= 10 and stats.confirmed_count == 0:
                    update["skip_types"].append(vt)

            # Propagate patterns from confirmed findings
            if findings:
                update["new_tasks"] = self._generate_pattern_tasks(
                    findings, all_endpoints
                )

            if update["skip_types"]:
                update["message"] = f"60% — skipping {len(update['skip_types'])} unproductive types"
            else:
                update["message"] = "60% checkpoint — strategy on track"

        # 90% checkpoint: final push on high-confidence targets only
        else:
            # Only keep types with proven success
            update["skip_types"] = [
                vt for vt, stats in self._vuln_stats.items()
                if stats.total_tests >= 5 and stats.confirmed_count == 0
            ]
            update["promote_types"] = list(confirmed_types)
            update["message"] = f"90% — final push on {len(confirmed_types)} proven types"

        # AI-assisted refinement if LLM available and budget permits
        if llm and budget and (not budget or budget.can_spend("reasoning", 500)):
            ai_suggestion = await self._ai_refine_strategy(
                progress_pct, findings, tested_types, llm
            )
            if ai_suggestion:
                update["ai_suggestion"] = ai_suggestion
                if budget:
                    budget.record("reasoning", 500, f"checkpoint_refine_{int(progress_pct*100)}%")

        return update

    async def _ai_refine_strategy(
        self,
        progress_pct: float,
        findings: List,
        tested_types: set,
        llm,
    ) -> Optional[str]:
        """Ask AI for strategy refinement suggestion."""
        try:
            finding_summary = []
            for f in (findings or [])[:10]:
                finding_summary.append(
                    f"  - {getattr(f, 'vulnerability_type', '?')} on "
                    f"{getattr(f, 'affected_endpoint', '?')}"
                )

            stats = self.get_report_context()
            prompt = f"""You are a penetration testing strategist. The scan is at {progress_pct:.0%} progress.

CURRENT STATUS:
- Tests run: {stats['total_tests']}
- Findings: {stats['total_findings']}
- Dead endpoints: {stats['endpoints_dead']}
- Hot endpoints: {stats['endpoints_hot']}
- Rate limiting detected: {stats['rate_limiting_detected']}

CONFIRMED FINDINGS:
{chr(10).join(finding_summary) if finding_summary else '  None yet'}

TESTED TYPES: {', '.join(list(tested_types)[:15])}

In 2-3 sentences, recommend what to focus on next. Be specific about vuln types and endpoint patterns."""

            if hasattr(llm, "generate"):
                return await llm.generate(prompt)
        except Exception as e:
            logger.debug(f"AI strategy refinement failed: {e}")
        return None

    def should_skip_endpoint_enhanced(self, url: str) -> tuple:
        """Enhanced endpoint skip check with reason.

        Returns (should_skip: bool, reason: str).
        """
        ep = self._get_endpoint(url)

        if ep.is_dead:
            return True, "dead_endpoint"

        if ep.timeout_count >= 5:
            ep.is_dead = True
            return True, "excessive_timeouts"

        if ep.status_403_count >= 5 and ep.findings_count == 0:
            return True, "persistent_403"

        if ep.total_tests >= 30 and ep.findings_count == 0:
            return True, "exhausted"

        return False, ""

    def propagate_finding_pattern(
        self,
        finding: Any,
        all_endpoints: List,
    ) -> List[Dict]:
        """Generate new test tasks from a confirmed finding pattern.

        When IDOR is found on /api/users/1, propagate to /api/orders/1, etc.
        When XSS is found on ?q=, test ?search=, ?query= on other endpoints.
        """
        return self._generate_pattern_tasks([finding], all_endpoints)

    def _generate_pattern_tasks(
        self,
        findings: List,
        all_endpoints: List,
    ) -> List[Dict]:
        """Internal: generate tasks from finding patterns."""
        tasks = []
        seen = set()

        for finding in (findings or []):
            vuln_type = getattr(finding, "vulnerability_type", "")
            param = getattr(finding, "parameter", "")
            url = getattr(finding, "affected_endpoint", getattr(finding, "url", ""))

            if not vuln_type:
                continue

            # Pattern 1: Same vuln type on similar endpoints
            parsed = urlparse(url)
            path_parts = [p for p in parsed.path.split("/") if p]

            for ep in (all_endpoints or []):
                ep_url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)

                # Skip the original endpoint
                if ep_url == url:
                    continue

                # Skip dead endpoints
                skip, _ = self.should_skip_endpoint_enhanced(ep_url)
                if skip:
                    continue

                ep_parsed = urlparse(ep_url)
                ep_path = ep_parsed.path.lower()

                # Match similar path structure
                if path_parts and any(part.lower() in ep_path for part in path_parts[:-1]):
                    task_key = f"{vuln_type}:{ep_url}"
                    if task_key not in seen:
                        seen.add(task_key)
                        tasks.append({
                            "task_type": "test_endpoint",
                            "url": ep_url,
                            "vuln_type": vuln_type,
                            "param": param,
                            "priority": 2,
                            "source": "pattern_propagation",
                            "parent_finding": getattr(finding, "id", ""),
                        })

            # Pattern 2: Same parameter name on other endpoints (XSS, SQLi)
            if param and vuln_type in ("xss_reflected", "sqli_error", "sqli_blind",
                                        "nosql_injection", "ssti"):
                for ep in (all_endpoints or []):
                    ep_url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                    ep_params = ep.get("params", []) if isinstance(ep, dict) else []

                    if ep_url == url:
                        continue

                    if param in ep_params or any(
                        p in ["q", "query", "search", "keyword", "s"]
                        for p in ep_params
                    ):
                        task_key = f"{vuln_type}:{ep_url}:{param}"
                        if task_key not in seen:
                            seen.add(task_key)
                            tasks.append({
                                "task_type": "test_endpoint",
                                "url": ep_url,
                                "vuln_type": vuln_type,
                                "param": param,
                                "priority": 2,
                                "source": "param_propagation",
                            })

        return tasks[:30]
