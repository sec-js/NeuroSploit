"""
NeuroSploit v3 - Agent Task Manager

Sub-task spawning and tracking system with priority queue.
Enables concurrent task execution with dependency awareness.

Inspired by CAI framework's agent-as-tool and task delegation patterns.
"""

import asyncio
import uuid
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Awaitable
from enum import Enum


class TaskType(Enum):
    """Types of agent sub-tasks."""
    TEST_ENDPOINT = "test_endpoint"
    VERIFY_FINDING = "verify_finding"
    SEARCH_CVE = "search_cve"
    GENERATE_POC = "generate_poc"
    CHAIN_EXPLORE = "chain_explore"
    DEEP_TEST = "deep_test"
    RECON_EXPAND = "recon_expand"
    BANNER_CHECK = "banner_check"
    MUTATE_TEST = "mutate_test"


class TaskStatus(Enum):
    """Task lifecycle states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Priority levels (lower number = higher priority)
PRIORITY_CRITICAL = 1   # RCE, auth bypass, chain exploitation
PRIORITY_HIGH = 2       # Confirmed reflection, SQL error, SSRF indicators
PRIORITY_MEDIUM = 3     # Standard vulnerability testing
PRIORITY_LOW = 4        # Info disclosure, header checks
PRIORITY_INFO = 5       # Enhancement, non-critical recon


@dataclass
class AgentTask:
    """A discrete task that can be assigned to the agent or a specialist."""
    id: str = ""
    task_type: str = TaskType.TEST_ENDPOINT.value
    priority: int = PRIORITY_MEDIUM
    target: str = ""
    parameters: Dict = field(default_factory=dict)
    status: str = TaskStatus.PENDING.value
    result: Any = None
    error: str = ""
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    source: str = ""  # What created this task (e.g., "chain_engine", "reasoning")

    def __post_init__(self):
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        if not self.created_at:
            self.created_at = time.time()

    def __lt__(self, other):
        """For PriorityQueue comparison — lower priority number = higher priority."""
        if not isinstance(other, AgentTask):
            return NotImplemented
        return self.priority < other.priority

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None


class AgentTaskManager:
    """Manages agent sub-tasks with priority queue and concurrent execution.

    Tasks are submitted with priorities and processed concurrently.
    Supports task cancellation, status tracking, and result collection.
    """

    MAX_QUEUE_SIZE = 500
    MAX_COMPLETED = 200

    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(
            maxsize=self.MAX_QUEUE_SIZE
        )
        self._running: Dict[str, AgentTask] = {}
        self._completed: List[AgentTask] = []
        self._failed: List[AgentTask] = []
        self._cancelled = False
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._total_submitted = 0
        self._total_completed = 0
        self._total_failed = 0

    # ── Task Submission ──

    async def submit(self, task: AgentTask) -> str:
        """Submit task to priority queue. Returns task ID."""
        if self._cancelled:
            return ""

        if self._queue.full():
            # Evict lowest-priority pending task
            # Note: PriorityQueue doesn't support removal, so we skip
            return ""

        try:
            self._queue.put_nowait(task)
            self._total_submitted += 1
            return task.id
        except asyncio.QueueFull:
            return ""

    def submit_sync(self, task: AgentTask) -> str:
        """Synchronous submit (for use in non-async contexts)."""
        try:
            self._queue.put_nowait(task)
            self._total_submitted += 1
            return task.id
        except (asyncio.QueueFull, Exception):
            return ""

    async def submit_batch(self, tasks: List[AgentTask]) -> List[str]:
        """Submit multiple tasks at once."""
        ids = []
        for task in tasks:
            tid = await self.submit(task)
            if tid:
                ids.append(tid)
        return ids

    # ── Task Execution ──

    async def run_tasks(self, executor: Callable[[AgentTask], Awaitable[Any]],
                        cancel_check: Optional[Callable[[], bool]] = None,
                        progress_callback: Optional[Callable[[Dict], Awaitable]] = None
                        ) -> List[AgentTask]:
        """Process queue with concurrent execution.

        Args:
            executor: Async function that executes a single task
            cancel_check: Optional function that returns True to stop
            progress_callback: Optional async callback for progress updates

        Returns:
            List of completed tasks
        """
        workers = []
        completed_in_run = []

        async def worker():
            while not self._cancelled:
                if cancel_check and cancel_check():
                    break

                try:
                    task = await asyncio.wait_for(
                        self._queue.get(), timeout=2.0
                    )
                except asyncio.TimeoutError:
                    # Check if queue is permanently empty
                    if self._queue.empty():
                        break
                    continue

                if self._cancelled or (cancel_check and cancel_check()):
                    break

                async with self._semaphore:
                    task.status = TaskStatus.RUNNING.value
                    task.started_at = time.time()
                    self._running[task.id] = task

                    try:
                        result = await executor(task)
                        task.result = result
                        task.status = TaskStatus.COMPLETED.value
                        task.completed_at = time.time()
                        self._total_completed += 1
                        completed_in_run.append(task)

                        # Bounded completed list
                        self._completed.append(task)
                        if len(self._completed) > self.MAX_COMPLETED:
                            self._completed = self._completed[-self.MAX_COMPLETED:]

                    except Exception as e:
                        task.error = str(e)
                        task.status = TaskStatus.FAILED.value
                        task.completed_at = time.time()
                        self._total_failed += 1
                        self._failed.append(task)

                    finally:
                        self._running.pop(task.id, None)

                    if progress_callback:
                        try:
                            await progress_callback(self.get_status())
                        except Exception:
                            pass

        # Spawn workers
        for _ in range(min(self.max_concurrent, max(1, self._queue.qsize()))):
            workers.append(asyncio.create_task(worker()))

        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        return completed_in_run

    async def drain(self, executor: Callable[[AgentTask], Awaitable[Any]],
                    cancel_check: Optional[Callable[[], bool]] = None,
                    timeout: float = 300.0) -> List[AgentTask]:
        """Run all queued tasks with a timeout."""
        try:
            return await asyncio.wait_for(
                self.run_tasks(executor, cancel_check),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            self.cancel()
            return list(self._completed[-50:])

    # ── Task Control ──

    def cancel(self):
        """Cancel all pending tasks."""
        self._cancelled = True
        # Drain queue
        while not self._queue.empty():
            try:
                task = self._queue.get_nowait()
                task.status = TaskStatus.CANCELLED.value
            except asyncio.QueueEmpty:
                break

    def reset(self):
        """Reset for new use."""
        self._cancelled = False
        self._queue = asyncio.PriorityQueue(maxsize=self.MAX_QUEUE_SIZE)
        self._running.clear()

    # ── Status & Queries ──

    def get_status(self) -> Dict:
        """Return task manager status for logging/dashboard."""
        return {
            "queued": self._queue.qsize(),
            "running": len(self._running),
            "completed": self._total_completed,
            "failed": self._total_failed,
            "total_submitted": self._total_submitted,
            "cancelled": self._cancelled,
        }

    @property
    def is_empty(self) -> bool:
        return self._queue.empty() and not self._running

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def running_count(self) -> int:
        return len(self._running)

    def get_completed_results(self, task_type: Optional[str] = None) -> List[Any]:
        """Get results from completed tasks, optionally filtered by type."""
        tasks = self._completed
        if task_type:
            tasks = [t for t in tasks if t.task_type == task_type]
        return [t.result for t in tasks if t.result is not None]

    def get_failed_tasks(self) -> List[AgentTask]:
        """Get failed tasks for retry or debugging."""
        return list(self._failed[-50:])


# ── Task Factory Helpers ──

def create_test_task(url: str, vuln_type: str, params: Dict = None,
                     priority: int = PRIORITY_MEDIUM,
                     source: str = "") -> AgentTask:
    """Create a test_endpoint task."""
    return AgentTask(
        task_type=TaskType.TEST_ENDPOINT.value,
        priority=priority,
        target=url,
        parameters={
            "vuln_type": vuln_type,
            "params": params or {},
        },
        source=source,
    )


def create_cve_task(software: str, version: str,
                    priority: int = PRIORITY_HIGH) -> AgentTask:
    """Create a search_cve task."""
    return AgentTask(
        task_type=TaskType.SEARCH_CVE.value,
        priority=priority,
        target=f"{software}/{version}",
        parameters={
            "software": software,
            "version": version,
        },
        source="cve_hunter",
    )


def create_chain_task(finding_type: str, finding_url: str,
                      chain_target: Dict,
                      priority: int = PRIORITY_HIGH) -> AgentTask:
    """Create a chain_explore task."""
    return AgentTask(
        task_type=TaskType.CHAIN_EXPLORE.value,
        priority=priority,
        target=finding_url,
        parameters={
            "source_vuln": finding_type,
            "chain_target": chain_target,
        },
        source="chain_engine",
    )


def create_deep_test_task(url: str, vuln_type: str, param: str,
                          mutation_context: Dict = None,
                          priority: int = PRIORITY_HIGH) -> AgentTask:
    """Create a deep_test task (re-test with mutations)."""
    return AgentTask(
        task_type=TaskType.DEEP_TEST.value,
        priority=priority,
        target=url,
        parameters={
            "vuln_type": vuln_type,
            "param": param,
            "mutation_context": mutation_context or {},
        },
        source="payload_mutator",
    )


def create_poc_task(finding_id: str, finding_type: str,
                    priority: int = PRIORITY_LOW) -> AgentTask:
    """Create a generate_poc task."""
    return AgentTask(
        task_type=TaskType.GENERATE_POC.value,
        priority=priority,
        target=finding_id,
        parameters={"vuln_type": finding_type},
        source="exploit_generator",
    )
