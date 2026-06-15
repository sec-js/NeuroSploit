"""
Reasoning Memory - Cross-scan storage of successful reasoning traces.

This is "pseudo-fine-tuning": instead of modifying model weights, we
accumulate successful reasoning chains and inject them as context
into future prompts. Over time, the system learns from its own
successful analyses.

Stores:
- Confirmed finding reasoning chains
- Failed hypothesis patterns (what didn't work and why)
- Technology-specific successful strategies
- Payload effectiveness per context
"""

import json
import logging
import time
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

MEMORY_FILE = "data/reasoning_memory.json"
MAX_TRACES = 500
MAX_FAILURES = 200
MAX_STRATEGIES = 100


@dataclass
class ReasoningTrace:
    """A successful reasoning chain from a confirmed finding."""
    vuln_type: str
    technology: str
    endpoint_pattern: str  # Normalized pattern (IDs removed)
    parameter: str
    reasoning_steps: List[str]
    payload_used: str
    evidence_summary: str
    confidence: float
    timestamp: float = 0.0
    scan_target: str = ""
    trace_id: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.trace_id:
            key = f"{self.vuln_type}_{self.endpoint_pattern}_{self.payload_used}"
            self.trace_id = hashlib.md5(key.encode()).hexdigest()[:10]


@dataclass
class FailureRecord:
    """A record of what didn't work and why."""
    vuln_type: str
    technology: str
    endpoint_pattern: str
    attempted_payloads: List[str]
    failure_reason: str  # "waf_blocked", "encoded", "no_reflection", "same_behavior", etc.
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


@dataclass
class StrategyRecord:
    """A successful technology-specific strategy."""
    technology: str
    vuln_types_found: List[str]
    priority_order: List[str]
    key_insights: List[str]
    scan_count: int = 1
    success_rate: float = 0.0
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


class ReasoningMemory:
    """
    Persistent storage and retrieval of reasoning experience.
    Learns from successful attacks and failed attempts to provide
    increasingly relevant context over time.
    """

    def __init__(self, memory_path: str = None):
        self.memory_path = Path(memory_path or MEMORY_FILE)
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)

        self._traces: List[Dict] = []
        self._failures: List[Dict] = []
        self._strategies: Dict[str, Dict] = {}  # tech -> StrategyRecord dict
        self._dirty = False

        self._load()

    def _load(self):
        """Load persisted memory."""
        if not self.memory_path.exists():
            return

        try:
            with open(self.memory_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._traces = data.get("traces", [])
            self._failures = data.get("failures", [])
            self._strategies = data.get("strategies", {})
            logger.info(
                f"ReasoningMemory: Loaded {len(self._traces)} traces, "
                f"{len(self._failures)} failures, {len(self._strategies)} strategies"
            )
        except Exception as e:
            logger.warning(f"ReasoningMemory: Failed to load: {e}")

    def _save(self):
        """Persist memory to disk."""
        if not self._dirty:
            return

        # Enforce size limits
        self._traces = self._traces[-MAX_TRACES:]
        self._failures = self._failures[-MAX_FAILURES:]

        try:
            data = {
                "traces": self._traces,
                "failures": self._failures,
                "strategies": self._strategies,
                "last_updated": time.time(),
                "stats": {
                    "total_traces": len(self._traces),
                    "total_failures": len(self._failures),
                    "technologies": list(self._strategies.keys())
                }
            }
            with open(self.memory_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            self._dirty = False
        except Exception as e:
            logger.warning(f"ReasoningMemory: Failed to save: {e}")

    # ── Recording ──────────────────────────────────────────────

    def record_success(self, trace: ReasoningTrace):
        """Record a successful reasoning chain from a confirmed finding."""
        trace_dict = asdict(trace)
        self._traces.append(trace_dict)
        self._dirty = True

        # Auto-save periodically
        if len(self._traces) % 10 == 0:
            self._save()

        logger.debug(
            f"ReasoningMemory: Recorded success - {trace.vuln_type} "
            f"on {trace.technology} ({trace.endpoint_pattern})"
        )

    def record_failure(self, failure: FailureRecord):
        """Record a failed attack attempt for future avoidance."""
        self._failures.append(asdict(failure))
        self._dirty = True

        if len(self._failures) % 20 == 0:
            self._save()

    def record_strategy(self, technology: str, vuln_types_found: List[str],
                         priority_order: List[str], insights: List[str]):
        """Record a successful scanning strategy for a technology."""
        tech_key = technology.lower()

        if tech_key in self._strategies:
            # Update existing
            existing = self._strategies[tech_key]
            existing["scan_count"] = existing.get("scan_count", 0) + 1
            existing["vuln_types_found"] = list(set(
                existing.get("vuln_types_found", []) + vuln_types_found
            ))
            # Merge insights
            existing_insights = set(existing.get("key_insights", []))
            for insight in insights:
                existing_insights.add(insight)
            existing["key_insights"] = list(existing_insights)[:20]
            existing["timestamp"] = time.time()

            # Recalculate priority based on accumulated experience
            if priority_order:
                existing["priority_order"] = priority_order
        else:
            self._strategies[tech_key] = asdict(StrategyRecord(
                technology=technology,
                vuln_types_found=vuln_types_found,
                priority_order=priority_order,
                key_insights=insights
            ))

        self._dirty = True
        self._save()

    # ── Retrieval ──────────────────────────────────────────────

    def get_relevant_traces(self, vuln_type: str, technology: str = "",
                              max_traces: int = 3) -> List[Dict]:
        """
        Retrieve relevant successful reasoning traces.
        Prioritizes exact vuln_type match, then technology match.
        """
        candidates = []

        for trace in self._traces:
            score = 0.0

            # Vuln type match (primary)
            if trace.get("vuln_type") == vuln_type:
                score += 5.0
            elif vuln_type.split("_")[0] in trace.get("vuln_type", ""):
                score += 2.0
            else:
                continue  # Skip irrelevant types

            # Technology match (secondary)
            if technology and technology.lower() in trace.get("technology", "").lower():
                score += 3.0

            # Recency boost
            age_days = (time.time() - trace.get("timestamp", 0)) / 86400
            if age_days < 7:
                score += 1.0
            elif age_days < 30:
                score += 0.5

            # High confidence boost
            if trace.get("confidence", 0) >= 0.9:
                score += 1.0

            candidates.append((score, trace))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [trace for _, trace in candidates[:max_traces]]

    def get_failure_patterns(self, vuln_type: str, technology: str = "",
                               max_patterns: int = 3) -> List[Dict]:
        """
        Retrieve relevant failure patterns to avoid.
        """
        candidates = []

        for failure in self._failures:
            if failure.get("vuln_type") != vuln_type:
                continue

            score = 1.0
            if technology and technology.lower() in failure.get("technology", "").lower():
                score += 2.0

            candidates.append((score, failure))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [f for _, f in candidates[:max_patterns]]

    def get_strategy_for_tech(self, technology: str) -> Optional[Dict]:
        """Get accumulated strategy knowledge for a technology."""
        tech_key = technology.lower()
        return self._strategies.get(tech_key)

    def get_context_for_testing(self, vuln_type: str, technology: str = "",
                                  max_chars: int = 1500) -> str:
        """
        Format reasoning memory into a prompt-ready context string.
        Includes successful traces and failure avoidance.
        """
        sections = []

        # Successful reasoning traces
        traces = self.get_relevant_traces(vuln_type, technology, max_traces=2)
        if traces:
            section = "## Successful Past Reasoning (from confirmed findings)\n"
            for i, trace in enumerate(traces, 1):
                section += f"\n### Past Success #{i}: {trace.get('vuln_type')} on {trace.get('technology', 'unknown')}\n"
                steps = trace.get("reasoning_steps", [])
                if steps:
                    for step in steps[:4]:
                        section += f"  - {step}\n"
                payload = trace.get("payload_used", "")
                if payload:
                    section += f"  Effective payload: {payload}\n"
                evidence = trace.get("evidence_summary", "")
                if evidence:
                    section += f"  Evidence: {evidence[:200]}\n"
            sections.append(section)

        # Failure avoidance
        failures = self.get_failure_patterns(vuln_type, technology, max_patterns=2)
        if failures:
            section = "## Failed Approaches to AVOID\n"
            for failure in failures:
                reason = failure.get("failure_reason", "unknown")
                endpoint = failure.get("endpoint_pattern", "")
                payloads = failure.get("attempted_payloads", [])[:3]
                section += f"  - {reason} on {endpoint}: payloads {payloads} did NOT work\n"
            sections.append(section)

        # Technology strategy
        if technology:
            strategy = self.get_strategy_for_tech(technology)
            if strategy:
                section = f"## Learned Strategy for {technology}\n"
                priority = strategy.get("priority_order", [])
                if priority:
                    section += f"  Priority order: {', '.join(priority[:8])}\n"
                insights = strategy.get("key_insights", [])
                for insight in insights[:3]:
                    section += f"  - {insight}\n"
                found = strategy.get("vuln_types_found", [])
                if found:
                    section += f"  Previously found: {', '.join(found[:5])}\n"
                sections.append(section)

        if not sections:
            return ""

        result = "\n=== REASONING MEMORY (Learned from past scans) ===\n"
        result += "Apply these lessons learned. Avoid previously failed approaches.\n\n"

        current_len = len(result)
        for section in sections:
            if current_len + len(section) > max_chars:
                remaining = max_chars - current_len - 20
                if remaining > 100:
                    result += section[:remaining] + "...\n"
                break
            result += section
            current_len += len(section)

        result += "\n=== END REASONING MEMORY ===\n"
        return result

    def get_strategy_context(self, technologies: List[str],
                               max_chars: int = 1000) -> str:
        """
        Format accumulated strategy knowledge for attack planning.
        """
        sections = []

        for tech in technologies[:3]:
            strategy = self.get_strategy_for_tech(tech)
            if strategy:
                section = f"### {tech} (tested {strategy.get('scan_count', 0)} times)\n"
                priority = strategy.get("priority_order", [])
                if priority:
                    section += f"  Recommended priority: {', '.join(priority[:6])}\n"
                found = strategy.get("vuln_types_found", [])
                if found:
                    section += f"  Previously successful: {', '.join(found[:5])}\n"
                insights = strategy.get("key_insights", [])
                for insight in insights[:2]:
                    section += f"  Insight: {insight}\n"
                sections.append(section)

        if not sections:
            return ""

        result = "\n=== ACCUMULATED STRATEGY KNOWLEDGE ===\n"
        current_len = len(result)
        for section in sections:
            if current_len + len(section) > max_chars:
                break
            result += section
            current_len += len(section)
        result += "=== END STRATEGY KNOWLEDGE ===\n"
        return result

    def get_stats(self) -> Dict:
        """Return memory statistics."""
        vuln_type_counts = {}
        for trace in self._traces:
            vt = trace.get("vuln_type", "unknown")
            vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1

        return {
            "total_traces": len(self._traces),
            "total_failures": len(self._failures),
            "technologies_known": list(self._strategies.keys()),
            "vuln_type_distribution": vuln_type_counts,
            "memory_file": str(self.memory_path),
            "file_exists": self.memory_path.exists()
        }

    def flush(self):
        """Force save to disk."""
        self._dirty = True
        self._save()
