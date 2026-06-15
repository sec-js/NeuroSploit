"""
NeuroSploit v3 - Token Budget Manager

Tracks and allocates LLM token budget across scan phases.
Implements graceful degradation when budget runs low.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class TokenExpenditure:
    """Record of a single token expenditure."""
    category: str
    tokens: int
    timestamp: float
    description: str = ""


class TokenBudget:
    """Tracks and allocates token budget across scan phases.

    Allocates budget by category and degrades gracefully:
      0-60% used  → full AI (all features enabled)
      60-80% used → reduced (skip optional AI: enhancement, reflection)
      80-95% used → minimal (only verification + critical reasoning)
      95%+ used   → technical_only (no AI calls, pattern-match only)
    """

    DEFAULT_ALLOCATIONS = {
        "reasoning": 0.15,      # 15% — think/plan/reflect cycles
        "analysis": 0.25,       # 25% — attack surface analysis, tool decisions
        "verification": 0.30,   # 30% — finding verification, AI confirmation
        "enhancement": 0.20,    # 20% — PoC generation, report enrichment
        "buffer": 0.10,         # 10% — emergency / overflow
    }

    DEGRADATION_THRESHOLDS = {
        "full": 0.0,
        "reduced": 0.60,
        "minimal": 0.80,
        "technical_only": 0.95,
    }

    def __init__(self, total_budget: int = 100_000):
        self.total = total_budget
        self.used = 0
        self.allocations = dict(self.DEFAULT_ALLOCATIONS)
        self._category_used: Dict[str, int] = {k: 0 for k in self.allocations}
        self._history: list = []
        self._start_time = time.time()

    # ── Budget Queries ──

    @property
    def remaining(self) -> int:
        return max(0, self.total - self.used)

    @property
    def usage_pct(self) -> float:
        if self.total <= 0:
            return 1.0
        return self.used / self.total

    def get_degradation_level(self) -> str:
        """Return current degradation level based on usage."""
        pct = self.usage_pct
        if pct >= self.DEGRADATION_THRESHOLDS["technical_only"]:
            return "technical_only"
        elif pct >= self.DEGRADATION_THRESHOLDS["minimal"]:
            return "minimal"
        elif pct >= self.DEGRADATION_THRESHOLDS["reduced"]:
            return "reduced"
        return "full"

    def can_spend(self, category: str, estimated_tokens: int) -> bool:
        """Check if category has budget remaining for this expenditure."""
        if category not in self.allocations:
            category = "buffer"

        cat_budget = int(self.total * self.allocations.get(category, 0.10))
        cat_used = self._category_used.get(category, 0)

        # Allow if within category budget
        if cat_used + estimated_tokens <= cat_budget:
            return True

        # Allow overflow into buffer if buffer has space
        buffer_budget = int(self.total * self.allocations["buffer"])
        buffer_used = self._category_used.get("buffer", 0)
        overflow_available = buffer_budget - buffer_used
        overage = (cat_used + estimated_tokens) - cat_budget

        return overage <= overflow_available

    def should_skip(self, category: str) -> bool:
        """Check if this category should be skipped at current degradation level."""
        level = self.get_degradation_level()

        if level == "technical_only":
            return True  # Skip all AI calls

        if level == "minimal":
            # Only allow verification and critical reasoning
            return category not in ("verification", "reasoning")

        if level == "reduced":
            # Skip enhancement and non-essential reasoning
            return category == "enhancement"

        return False  # full — allow everything

    # ── Budget Recording ──

    def record(self, category: str, tokens_used: int, description: str = ""):
        """Record token expenditure."""
        if category not in self._category_used:
            category = "buffer"

        self.used += tokens_used
        self._category_used[category] = self._category_used.get(category, 0) + tokens_used

        self._history.append(TokenExpenditure(
            category=category,
            tokens=tokens_used,
            timestamp=time.time(),
            description=description,
        ))

    # ── Reporting ──

    def get_status(self) -> Dict:
        """Return budget status for logging/dashboard."""
        return {
            "total": self.total,
            "used": self.used,
            "remaining": self.remaining,
            "usage_pct": round(self.usage_pct * 100, 1),
            "degradation_level": self.get_degradation_level(),
            "categories": {
                cat: {
                    "allocated": int(self.total * alloc),
                    "used": self._category_used.get(cat, 0),
                    "remaining": int(self.total * alloc) - self._category_used.get(cat, 0),
                }
                for cat, alloc in self.allocations.items()
            },
            "elapsed_seconds": round(time.time() - self._start_time, 1),
            "calls": len(self._history),
        }

    def get_category_remaining(self, category: str) -> int:
        """Return remaining tokens for a specific category."""
        alloc = self.allocations.get(category, 0.10)
        cat_budget = int(self.total * alloc)
        cat_used = self._category_used.get(category, 0)
        return max(0, cat_budget - cat_used)

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate (4 chars ≈ 1 token for English text)."""
        return max(1, len(text) // 4)

    def __repr__(self) -> str:
        return (f"TokenBudget(used={self.used}/{self.total} "
                f"[{self.usage_pct:.0%}] level={self.get_degradation_level()})")
