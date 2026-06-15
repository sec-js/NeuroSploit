"""
NeuroSploit v3 - Specialist Agent Base Class

Base class for all specialist sub-agents in the multi-agent system.
Inspired by CAI framework's Agent pattern with handoff support,
budget tracking, and shared memory access.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """Result from a specialist agent execution."""
    agent_name: str
    status: str = "pending"          # pending, running, completed, failed
    findings: List[Any] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    tasks_completed: int = 0
    tokens_used: int = 0
    duration: float = 0.0
    error: str = ""
    handoff_to: str = ""             # Agent name to hand off to
    handoff_context: Dict = field(default_factory=dict)


class SpecialistAgent:
    """Base class for specialist sub-agents.

    Each specialist agent has:
    - A name and role description
    - Access to shared memory (AgentMemory)
    - A token budget allocation
    - Handoff capability to transfer work to another agent
    - Tool exposure (as_tool) for orchestrator use
    """

    def __init__(
        self,
        name: str,
        llm=None,
        memory=None,
        budget_allocation: float = 0.0,
        budget=None,
    ):
        self.name = name
        self.llm = llm
        self.memory = memory
        self.budget_allocation = budget_allocation
        self.budget = budget
        self.findings: List[Any] = []
        self.tasks_completed: int = 0
        self.tokens_used: int = 0
        self._status = "idle"
        self._start_time: float = 0.0
        self._cancel_event = asyncio.Event()

    async def run(self, context: Dict) -> AgentResult:
        """Main execution loop — override in subclasses.

        Args:
            context: Dict with target info, recon data, prior findings, etc.

        Returns:
            AgentResult with findings, data, and optional handoff.
        """
        raise NotImplementedError(f"{self.name} must implement run()")

    async def execute(self, context: Dict) -> AgentResult:
        """Wrapper that handles timing, error catching, and status updates."""
        self._status = "running"
        self._start_time = time.time()
        self._cancel_event.clear()

        result = AgentResult(agent_name=self.name, status="running")

        try:
            result = await self.run(context)
            result.status = "completed"
        except asyncio.CancelledError:
            result.status = "cancelled"
            result.error = "Agent cancelled"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            logger.error(f"Agent {self.name} failed: {e}")

        result.duration = time.time() - self._start_time
        result.tokens_used = self.tokens_used
        result.tasks_completed = self.tasks_completed
        self._status = result.status

        return result

    def cancel(self):
        """Signal the agent to stop."""
        self._cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    async def handoff_to(
        self,
        target_agent: 'SpecialistAgent',
        context: Dict,
    ) -> AgentResult:
        """Transfer task to another specialist agent.

        The receiving agent gets full context from the sender.
        """
        handoff_context = {
            "from_agent": self.name,
            "findings_so_far": self.findings,
            "tokens_used": self.tokens_used,
            **context,
        }
        logger.info(f"Handoff: {self.name} → {target_agent.name}")
        return await target_agent.execute(handoff_context)

    def as_tool(self) -> Dict:
        """Expose this agent as a callable tool for the orchestrator.

        Returns a dict compatible with LLM tool/function calling.
        """
        return {
            "name": f"agent_{self.name}",
            "description": f"Specialist {self.name} agent",
            "parameters": {
                "type": "object",
                "properties": {
                    "context": {
                        "type": "string",
                        "description": "Task context for the agent",
                    }
                },
            },
            "handler": self.execute,
        }

    def get_status(self) -> Dict:
        """Dashboard-friendly status."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "name": self.name,
            "status": self._status,
            "tasks_completed": self.tasks_completed,
            "findings_count": len(self.findings),
            "tokens_used": self.tokens_used,
            "budget_allocation": self.budget_allocation,
            "elapsed": round(elapsed, 1),
        }

    async def _llm_call(self, prompt: str, category: str = "analysis",
                         estimated_tokens: int = 500) -> Optional[str]:
        """Helper: make an LLM call with budget tracking."""
        if not self.llm or not hasattr(self.llm, "generate"):
            return None

        if self.budget and not self.budget.can_spend(category, estimated_tokens):
            logger.debug(f"Agent {self.name}: budget exhausted for {category}")
            return None

        try:
            result = await self.llm.generate(prompt)
            if self.budget:
                self.budget.record(category, estimated_tokens,
                                   f"agent_{self.name}_{category}")
            self.tokens_used += estimated_tokens
            return result
        except Exception as e:
            logger.debug(f"Agent {self.name} LLM call failed: {e}")
            return None
