"""
NeuroSploit v3 - Per-Vulnerability-Type Agent Orchestrator

Coordinates up to N VulnTypeAgents running in parallel (default 10).
Each of the 100 vulnerability types gets its own agent that delegates
to the parent AutonomousAgent's existing testing methods.

Gated by ENABLE_VULN_AGENTS=true env var.
"""

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from backend.core.vuln_type_agent import VulnTypeAgent
from backend.core.agent_base import AgentResult

logger = logging.getLogger(__name__)

# Priority severity groups: critical types run first, then high, then rest
SEVERITY_GROUPS = {
    "critical": {
        "sqli_error", "sqli_union", "sqli_blind", "sqli_time",
        "command_injection", "auth_bypass", "ssrf", "ssti",
        "insecure_deserialization", "lfi", "rfi", "xxe", "jwt_manipulation",
    },
    "high": {
        "xss_reflected", "xss_stored", "xss_dom", "blind_xss",
        "csrf", "idor", "bola", "bfla", "privilege_escalation",
        "path_traversal", "cors_misconfig", "open_redirect",
        "file_upload", "nosql_injection", "ldap_injection",
    },
}


def _categorize_types(vuln_types: List[str]) -> tuple:
    """Split vuln types into (critical, high, rest) batches."""
    critical = [vt for vt in vuln_types if vt in SEVERITY_GROUPS["critical"]]
    high = [vt for vt in vuln_types if vt in SEVERITY_GROUPS["high"]]
    rest = [vt for vt in vuln_types if vt not in SEVERITY_GROUPS["critical"] and vt not in SEVERITY_GROUPS["high"]]
    return critical, high, rest


class VulnOrchestrator:
    """Parallel orchestrator for per-vulnerability-type agents.

    Creates one VulnTypeAgent per vuln type and runs them concurrently,
    gated by an asyncio.Semaphore to limit parallelism.
    """

    def __init__(
        self,
        parent_agent: Any,  # AutonomousAgent
        max_concurrent: int = 10,
        status_callback: Optional[Callable] = None,
        ws_broadcast: Optional[Callable] = None,
    ):
        self.parent = parent_agent
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._status_callback = status_callback
        self._ws_broadcast = ws_broadcast

        # Agent tracking
        self._agents: Dict[str, VulnTypeAgent] = {}
        self._results: Dict[str, AgentResult] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._start_time: float = 0
        self._cancelled = False

    async def run(
        self,
        vuln_types: List[str],
        test_targets: List[Dict],
        prioritized_types: Optional[List[str]] = None,
    ) -> Dict:
        """Run vuln type agents in priority batches (critical -> high -> rest).

        Each batch runs its agents in parallel (gated by semaphore).
        Batches execute sequentially so critical types finish first.

        Args:
            vuln_types: List of vulnerability type keys to test
            test_targets: List of {url, method, params, form_defaults} dicts
            prioritized_types: Optional ordering within batches

        Returns:
            Dict with findings_count, agent_statuses, stats
        """
        self._start_time = time.time()
        self._cancelled = False

        # Use prioritized ordering if provided, else original list
        ordered_types = prioritized_types or vuln_types

        # Create all agents upfront (for dashboard tracking)
        for vt in ordered_types:
            agent = VulnTypeAgent(
                vuln_type=vt,
                parent_agent=self.parent,
                test_targets=test_targets,
                budget_allocation=1.0 / max(len(ordered_types), 1),
                status_callback=self._ws_broadcast,
            )
            self._agents[vt] = agent

        # Categorize into priority batches
        critical_types, high_types, rest_types = _categorize_types(ordered_types)
        batches = [
            ("critical", critical_types),
            ("high", high_types),
            ("rest", rest_types),
        ]

        for batch_name, batch_types in batches:
            if self._cancelled or self.parent.is_cancelled():
                break
            if not batch_types:
                continue

            logger.info(f"VulnOrchestrator: Starting {batch_name} batch ({len(batch_types)} types)")

            # Broadcast batch start
            if self._ws_broadcast:
                await self._ws_broadcast({
                    "type": "vuln_batch_started",
                    "batch": batch_name,
                    "count": len(batch_types),
                })

            # Launch batch agents with semaphore gating
            batch_tasks = []
            for vt in batch_types:
                agent = self._agents[vt]
                task = asyncio.create_task(self._run_agent_gated(vt, agent))
                self._tasks[vt] = task
                batch_tasks.append(task)

            # Wait for this batch to complete before next
            await asyncio.gather(*batch_tasks, return_exceptions=True)

            logger.info(f"VulnOrchestrator: {batch_name} batch complete")

        # Collect results
        total_findings = sum(
            r.data.get("findings_count", 0)
            for r in self._results.values()
        )

        return {
            "findings_count": total_findings,
            "agent_statuses": self.get_all_agent_statuses(),
            "stats": self.get_stats(),
        }

    async def _run_agent_gated(self, vuln_type: str, agent: VulnTypeAgent):
        """Run a single agent, gated by the concurrency semaphore."""
        async with self._semaphore:
            if self._cancelled or self.parent.is_cancelled():
                result = AgentResult(agent_name=agent.name, status="cancelled")
                self._results[vuln_type] = result
                return

            try:
                result = await agent.execute({"vuln_type": vuln_type})
                self._results[vuln_type] = result

                # Broadcast completion
                if self._ws_broadcast:
                    await self._ws_broadcast({
                        "type": "vuln_agent_update",
                        "vuln_type": vuln_type,
                        "name": agent.name,
                        "status": result.status,
                        "findings_count": result.data.get("findings_count", 0),
                        "duration": round(result.duration, 1),
                        "progress": 100,
                        "targets_tested": result.data.get("targets_tested", 0),
                        "targets_total": len(agent.test_targets),
                        "tokens_used": result.tokens_used,
                    })

            except asyncio.CancelledError:
                self._results[vuln_type] = AgentResult(
                    agent_name=agent.name, status="cancelled"
                )
            except Exception as e:
                logger.error(f"VulnOrchestrator: agent {vuln_type} failed: {e}")
                self._results[vuln_type] = AgentResult(
                    agent_name=agent.name, status="failed", error=str(e)
                )

    def get_all_agent_statuses(self) -> List[Dict]:
        """Get status of all agents for dashboard display."""
        statuses = []
        for vt, agent in self._agents.items():
            status = agent.get_status()
            # Overlay result status if available
            if vt in self._results:
                status["status"] = self._results[vt].status
                if self._results[vt].error:
                    status["error"] = self._results[vt].error
                status["duration"] = round(self._results[vt].duration, 1)
            statuses.append(status)
        return statuses

    def get_stats(self) -> Dict:
        """Aggregate statistics for dashboard summary."""
        total = len(self._agents)
        completed = sum(1 for r in self._results.values() if r.status == "completed")
        failed = sum(1 for r in self._results.values() if r.status == "failed")
        cancelled = sum(1 for r in self._results.values() if r.status == "cancelled")
        running = total - len(self._results)
        findings_total = sum(
            r.data.get("findings_count", 0)
            for r in self._results.values()
        )
        elapsed = round(time.time() - self._start_time, 1) if self._start_time else 0

        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "cancelled": cancelled,
            "running": running,
            "findings_total": findings_total,
            "elapsed": elapsed,
        }

    def cancel(self):
        """Cancel all running agents."""
        self._cancelled = True
        for agent in self._agents.values():
            agent.cancel()
        for task in self._tasks.values():
            if not task.done():
                task.cancel()
