"""
NeuroSploit v3 - Per-Vulnerability-Type Specialist Agent

Each VulnTypeAgent wraps a single vulnerability type and delegates to
the parent AutonomousAgent's battle-tested testing methods. This avoids
duplicating the 526-payload, anti-hallucination testing pipeline.

Architecture: VulnTypeAgent holds a reference to the parent agent and
routes to the correct testing method based on vuln category.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable

from backend.core.agent_base import SpecialistAgent, AgentResult

logger = logging.getLogger(__name__)


class VulnTypeAgent(SpecialistAgent):
    """Specialist agent for testing a single vulnerability type.

    Wraps the parent AutonomousAgent's existing test methods:
    - INJECTION_TYPES → _test_vulnerability_type() / _test_reflected_xss() / _test_stored_xss()
    - INSPECTION_TYPES → inspection dispatch table
    - AI_DRIVEN_TYPES → _ai_dynamic_test()
    """

    def __init__(
        self,
        vuln_type: str,
        parent_agent: Any,  # AutonomousAgent
        test_targets: List[Dict],
        budget_allocation: float = 0.01,
        status_callback: Optional[Callable] = None,
    ):
        super().__init__(
            name=f"vuln_{vuln_type}",
            llm=parent_agent.llm,
            memory=parent_agent.memory,
            budget_allocation=budget_allocation,
            budget=parent_agent.token_budget,
        )
        self.vuln_type = vuln_type
        self.parent = parent_agent
        self.test_targets = test_targets
        self._status_callback = status_callback
        self._progress = 0
        self._targets_tested = 0
        self._targets_total = len(test_targets)
        self._findings_count = 0

    async def run(self, context: Dict) -> AgentResult:
        """Execute testing for this single vulnerability type."""
        result = AgentResult(agent_name=self.name, status="running")
        local_findings: List[Any] = []

        try:
            await self._emit_status("running")

            # Determine category
            is_injection = self.vuln_type in self.parent.INJECTION_TYPES
            is_inspection = self.vuln_type in self.parent.INSPECTION_TYPES
            is_ai_driven = self.vuln_type in self.parent.AI_DRIVEN_TYPES

            if is_inspection:
                await self._test_inspection()
            elif is_injection:
                await self._test_injection(local_findings)
            elif is_ai_driven:
                await self._test_ai_driven()
            else:
                # Unknown type - try injection as fallback
                await self._test_injection(local_findings)

            result.findings = self.findings
            self._findings_count = len(self.findings)
            result.data = {
                "vuln_type": self.vuln_type,
                "targets_tested": self._targets_tested,
                "findings_count": self._findings_count,
            }

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"VulnTypeAgent[{self.vuln_type}] error: {e}")
            result.error = str(e)

        await self._emit_status("completed" if not result.error else "failed")
        return result

    # ── Inspection dispatch ──────────────────────────────────────────

    async def _test_inspection(self):
        """Dispatch to parent inspection methods based on vuln type."""
        vt = self.vuln_type

        if vt in ("security_headers", "clickjacking", "insecure_cookie_flags"):
            await self.parent._test_security_headers(vt)
        elif vt == "cors_misconfig":
            await self.parent._test_cors()
        elif vt in ("http_methods", "information_disclosure", "version_disclosure",
                     "sensitive_data_exposure"):
            await self.parent._test_information_disclosure()
        elif vt in ("directory_listing", "debug_mode", "exposed_admin_panel", "exposed_api_docs"):
            await self.parent._test_misconfigurations()
        elif vt in ("source_code_disclosure", "backup_file_exposure", "api_key_exposure"):
            await self.parent._test_data_exposure()
        elif vt in ("ssl_issues", "cleartext_transmission", "weak_encryption", "weak_hashing"):
            await self.parent._test_ssl_crypto()
        elif vt == "graphql_introspection":
            await self.parent._test_graphql_introspection()
        elif vt == "csrf":
            await self.parent._test_csrf_inspection()

        self._targets_tested = 1
        self._progress = 100
        await self._emit_status("running")

    # ── Injection dispatch ───────────────────────────────────────────

    async def _test_injection(self, local_findings: List):
        """Test injection vuln type against all targets."""
        vt = self.vuln_type

        for i, target in enumerate(self.test_targets):
            if self.is_cancelled or self.parent.is_cancelled():
                break

            url = target.get("url", "")
            method = target.get("method", "GET")
            params = target.get("params", [])
            form_defaults = target.get("form_defaults", {})

            # Strategy: skip dead endpoints
            if self.parent.strategy and not self.parent.strategy.should_test_endpoint(url):
                continue

            finding = None

            # Special handlers for XSS
            if vt == "xss_reflected":
                finding = await self.parent._test_reflected_xss(url, params, method, form_defaults)
            elif vt == "xss_stored":
                # Stored XSS tests against forms
                forms = self.parent.recon.forms[:10]
                for form in forms:
                    if self.is_cancelled or self.parent.is_cancelled():
                        break
                    f = await self.parent._test_stored_xss(form)
                    if f:
                        await self.parent._add_finding(f)
                        self.findings.append(f)
                        self._findings_count += 1
                self._targets_tested = i + 1
                self._progress = int(((i + 1) / max(len(self.test_targets), 1)) * 100)
                await self._emit_status("running")
                continue
            else:
                # Generic injection test
                finding = await self.parent._test_vulnerability_type(
                    url, vt, method, params, form_defaults=form_defaults
                )

            if finding:
                await self.parent._add_finding(finding)
                self.findings.append(finding)
                self._findings_count += 1

                # Strategy: record success
                if self.parent.strategy:
                    self.parent.strategy.record_test_result(url, vt, 200, True, 0)
            elif self.parent.strategy:
                self.parent.strategy.record_test_result(url, vt, 0, False, 0)

            self._targets_tested = i + 1
            self._progress = int(((i + 1) / max(len(self.test_targets), 1)) * 100)
            await self._emit_status("running")

    # ── AI-driven dispatch ───────────────────────────────────────────

    async def _test_ai_driven(self):
        """Test AI-driven vuln type via parent LLM."""
        if not self.parent.llm.is_available():
            return

        await self.parent._ai_dynamic_test(
            f"Test the target {self.parent.target} for {self.vuln_type} vulnerability. "
            f"Analyze the application behavior, attempt exploitation, and report only confirmed findings."
        )
        self._targets_tested = 1
        self._progress = 100
        await self._emit_status("running")

    # ── Status ───────────────────────────────────────────────────────

    async def _emit_status(self, status: str):
        """Emit status update for dashboard."""
        if self._status_callback:
            try:
                await self._status_callback({
                    "type": "vuln_agent_update",
                    "name": self.name,
                    "vuln_type": self.vuln_type,
                    "status": status,
                    "progress": self._progress,
                    "targets_tested": self._targets_tested,
                    "targets_total": self._targets_total,
                    "findings_count": self._findings_count,
                    "tokens_used": self.tokens_used,
                    "duration": round(time.time() - self._start_time, 1) if self._start_time else 0,
                })
            except Exception as e:
                logger.debug(f"VulnTypeAgent status emit error: {e}")

    def get_status(self) -> Dict:
        """Dashboard-friendly status with vuln-specific info."""
        base = super().get_status()
        base.update({
            "vuln_type": self.vuln_type,
            "progress": self._progress,
            "targets_tested": self._targets_tested,
            "targets_total": self._targets_total,
            "findings_count": self._findings_count,
        })
        return base
