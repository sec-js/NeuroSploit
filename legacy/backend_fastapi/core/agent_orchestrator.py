"""
NeuroSploit v3 - Multi-Agent Orchestrator

Coordinates specialist agents in a CAI-inspired pattern:
  Phase 1: Parallel — ReconAgent + CVEHunterAgent
  Phase 2: Sequential — ExploitAgent (consumes recon output)
  Phase 3: Parallel — ValidatorAgent + ReportAgent

Manages handoffs, shared memory, and progress tracking.
Enabled via ENABLE_MULTI_AGENT=true in .env.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from core.agent_base import SpecialistAgent, AgentResult

logger = logging.getLogger(__name__)

# Lazy imports
_specialist = None


def _get_specialist_module():
    global _specialist
    if _specialist is None:
        try:
            from core import specialist_agents
            _specialist = specialist_agents
        except ImportError:
            _specialist = False
    return _specialist if _specialist else None


class AgentOrchestrator:
    """Coordinates specialist agents with handoff routing.

    Three execution phases:
    1. Intelligence gathering (Recon + CVE Hunter in parallel)
    2. Exploitation (ExploitAgent with enriched recon)
    3. Validation and reporting (Validator + Reporter in parallel)

    Handoff rules route output from one agent as input to the next.
    Shared memory allows agents to see each other's findings.
    """

    def __init__(
        self,
        llm=None,
        memory=None,
        budget=None,
        request_engine=None,
        config: Dict = None,
    ):
        self.llm = llm
        self.memory = memory
        self.budget = budget
        self.request_engine = request_engine
        self.config = config or {}

        self._agents: Dict[str, SpecialistAgent] = {}
        self._results: Dict[str, AgentResult] = {}
        self._phase = "idle"
        self._start_time: float = 0.0
        self._cancel_event = asyncio.Event()
        self._progress_callback = None

        self._init_agents()

    def _init_agents(self):
        """Initialize specialist agents with budget allocations."""
        spec = _get_specialist_module()
        if not spec:
            logger.warning("Specialist agents module not available")
            return

        budget_splits = self.config.get("budget_splits", {
            "recon": 0.20,
            "exploit": 0.35,
            "validator": 0.20,
            "cve_hunter": 0.10,
            "reporter": 0.15,
        })

        self._agents = {
            "recon": spec.ReconAgent(
                llm=self.llm, memory=self.memory,
                budget_allocation=budget_splits.get("recon", 0.20),
                budget=self.budget, request_engine=self.request_engine,
            ),
            "exploit": spec.ExploitAgent(
                llm=self.llm, memory=self.memory,
                budget_allocation=budget_splits.get("exploit", 0.35),
                budget=self.budget, request_engine=self.request_engine,
            ),
            "validator": spec.ValidatorAgent(
                llm=self.llm, memory=self.memory,
                budget_allocation=budget_splits.get("validator", 0.20),
                budget=self.budget, request_engine=self.request_engine,
            ),
            "cve_hunter": spec.CVEHunterAgent(
                llm=self.llm, memory=self.memory,
                budget_allocation=budget_splits.get("cve_hunter", 0.10),
                budget=self.budget, request_engine=self.request_engine,
            ),
            "reporter": spec.ReportAgent(
                llm=self.llm, memory=self.memory,
                budget_allocation=budget_splits.get("reporter", 0.15),
                budget=self.budget,
            ),
        }

    def set_progress_callback(self, callback):
        """Set callback for progress updates: callback(phase, pct, message)."""
        self._progress_callback = callback

    def _progress(self, phase: str, pct: float, message: str):
        """Report progress."""
        self._phase = phase
        if self._progress_callback:
            try:
                self._progress_callback(phase, pct, message)
            except Exception:
                pass

    async def run(
        self,
        target: str,
        recon_data: Any = None,
        initial_context: Dict = None,
    ) -> Dict:
        """Run the full multi-agent pipeline.

        Args:
            target: Target URL
            recon_data: Existing ReconData object (if available)
            initial_context: Additional context (headers, body, technologies)

        Returns:
            Dict with all findings, agent results, and statistics.
        """
        self._start_time = time.time()
        self._cancel_event.clear()
        context = initial_context or {}
        context["target"] = target

        # Extract basic info from recon_data
        if recon_data:
            context.setdefault("headers", getattr(recon_data, "headers", {}))
            context.setdefault("body", getattr(recon_data, "body", ""))
            context.setdefault("technologies",
                               getattr(recon_data, "technologies", []))
            context.setdefault("endpoints",
                               getattr(recon_data, "endpoints", []))

        all_findings = []
        pipeline_results = {}

        # ── Phase 1: Intelligence Gathering (Parallel) ──
        self._progress("phase1_intel", 0.0, "Starting intelligence gathering")

        if self._cancel_event.is_set():
            return self._build_result(all_findings, pipeline_results)

        phase1_tasks = []
        if "recon" in self._agents:
            phase1_tasks.append(
                ("recon", self._agents["recon"].execute(context))
            )
        if "cve_hunter" in self._agents:
            phase1_tasks.append(
                ("cve_hunter", self._agents["cve_hunter"].execute(context))
            )

        if phase1_tasks:
            results = await asyncio.gather(
                *[task for _, task in phase1_tasks],
                return_exceptions=True,
            )

            for (name, _), res in zip(phase1_tasks, results):
                if isinstance(res, Exception):
                    logger.error(f"Phase 1 agent {name} failed: {res}")
                    pipeline_results[name] = AgentResult(
                        agent_name=name, status="failed", error=str(res)
                    )
                else:
                    pipeline_results[name] = res
                    all_findings.extend(res.findings)

                    # Merge discovered endpoints into context
                    if name == "recon" and res.data.get("discovered_endpoints"):
                        existing = context.get("endpoints", [])
                        context["endpoints"] = list(set(
                            existing + res.data["discovered_endpoints"]
                        ))
                    if name == "recon" and res.data.get("version_findings"):
                        context["versions"] = res.data["version_findings"]

        self._progress("phase1_intel", 0.30,
                        f"Intel complete: {len(context.get('endpoints', []))} endpoints")

        # ── Phase 2: Exploitation (Sequential) ──
        if self._cancel_event.is_set():
            return self._build_result(all_findings, pipeline_results)

        self._progress("phase2_exploit", 0.30, "Starting exploitation phase")

        if "exploit" in self._agents:
            exploit_result = await self._agents["exploit"].execute(context)
            pipeline_results["exploit"] = exploit_result
            all_findings.extend(exploit_result.findings)

        self._progress("phase2_exploit", 0.65,
                        f"Exploitation complete: {len(all_findings)} findings")

        # ── Phase 3: Validation + Reporting (Parallel) ──
        if self._cancel_event.is_set():
            return self._build_result(all_findings, pipeline_results)

        self._progress("phase3_validate", 0.65, "Starting validation and reporting")

        phase3_context = {**context, "findings": all_findings}

        phase3_tasks = []
        if "validator" in self._agents and all_findings:
            phase3_tasks.append(
                ("validator", self._agents["validator"].execute(phase3_context))
            )
        if "reporter" in self._agents and all_findings:
            report_ctx = {**phase3_context, "recon_data": recon_data}
            phase3_tasks.append(
                ("reporter", self._agents["reporter"].execute(report_ctx))
            )

        if phase3_tasks:
            results = await asyncio.gather(
                *[task for _, task in phase3_tasks],
                return_exceptions=True,
            )

            for (name, _), res in zip(phase3_tasks, results):
                if isinstance(res, Exception):
                    logger.error(f"Phase 3 agent {name} failed: {res}")
                    pipeline_results[name] = AgentResult(
                        agent_name=name, status="failed", error=str(res)
                    )
                else:
                    pipeline_results[name] = res
                    # Validator may filter findings
                    if name == "validator" and res.findings:
                        all_findings = res.findings

        self._progress("complete", 1.0,
                        f"Pipeline complete: {len(all_findings)} validated findings")

        return self._build_result(all_findings, pipeline_results)

    def _build_result(
        self,
        findings: List,
        agent_results: Dict[str, AgentResult],
    ) -> Dict:
        """Build final pipeline result."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        total_tokens = sum(
            r.tokens_used for r in agent_results.values()
            if isinstance(r, AgentResult)
        )
        total_tasks = sum(
            r.tasks_completed for r in agent_results.values()
            if isinstance(r, AgentResult)
        )

        return {
            "findings": findings,
            "findings_count": len(findings),
            "agent_results": {
                name: {
                    "status": r.status,
                    "findings_count": len(r.findings),
                    "tasks_completed": r.tasks_completed,
                    "tokens_used": r.tokens_used,
                    "duration": round(r.duration, 1),
                    "error": r.error,
                }
                for name, r in agent_results.items()
                if isinstance(r, AgentResult)
            },
            "total_tokens": total_tokens,
            "total_tasks": total_tasks,
            "duration": round(elapsed, 1),
            "phase": self._phase,
        }

    def cancel(self):
        """Cancel all running agents."""
        self._cancel_event.set()
        for agent in self._agents.values():
            agent.cancel()

    def get_agents_status(self) -> List[Dict]:
        """Get status of all agents for dashboard."""
        return [agent.get_status() for agent in self._agents.values()]

    async def reason_about_handoff(
        self,
        current_agent: str,
        result: AgentResult,
    ) -> Optional[str]:
        """Use AI to decide which agent should handle next.

        Falls back to explicit handoff_to in AgentResult.
        """
        if result.handoff_to:
            return result.handoff_to

        if not self.llm or not hasattr(self.llm, "generate"):
            return None

        try:
            prompt = f"""Given the output of the {current_agent} agent:
- Status: {result.status}
- Findings: {len(result.findings)}
- Data keys: {list(result.data.keys())}

Which agent should handle the next step?
Options: recon, exploit, validator, cve_hunter, reporter, none

Reply with ONLY the agent name."""

            answer = await self.llm.generate(prompt)
            if answer:
                answer = answer.strip().lower()
                if answer in self._agents:
                    return answer
        except Exception:
            pass

        return None
