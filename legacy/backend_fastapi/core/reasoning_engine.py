"""
NeuroSploit v3 - Reasoning Engine

ReACT-inspired reasoning loop: Think → Plan → Act → Observe → Reflect.
Provides dedicated reasoning capability for strategic decision-making
throughout the pentest lifecycle, not just at verification time.

Inspired by CAI framework's dedicated Reasoner agent pattern.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from backend.core.token_budget import TokenBudget

try:
    from backend.core.vuln_engine.system_prompts import get_system_prompt
except ImportError:
    def get_system_prompt(ctx):
        return "You are an expert penetration tester."


@dataclass
class ReasoningResult:
    """Result of a reasoning step."""
    analysis: str
    recommended_action: str
    confidence: float  # 0.0 - 1.0
    reasoning_chain: List[str] = field(default_factory=list)
    skip_reason: str = ""  # Non-empty if reasoning was skipped (budget)


@dataclass
class AttackPlan:
    """Prioritized attack plan from strategic reasoning."""
    priority_vulns: List[str] = field(default_factory=list)
    endpoint_rankings: List[Dict] = field(default_factory=list)  # [{url, risk, types}]
    parameter_focus: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    chain_targets: List[Dict] = field(default_factory=list)
    checkpoint_pct: float = 0.0
    token_cost: int = 0


@dataclass
class Reflection:
    """Post-action reflection result."""
    should_continue: bool = True
    next_suggestion: str = ""
    learned_pattern: str = ""
    confidence_adjustment: float = 0.0  # -1.0 to +1.0


REASONING_SYSTEM_PROMPT = """You are an expert penetration testing strategist. Your role is PURELY analytical — you think deeply about attack strategy, NOT execute attacks.

CRITICAL RULES:
1. Base ALL recommendations on CONCRETE evidence from reconnaissance data
2. Never hallucinate vulnerabilities — only suggest TESTING, not claim findings
3. Prioritize by REAL risk (attack surface × likelihood × impact)
4. Consider WAF/defense evasion when recommending approaches
5. Account for token budget — suggest efficient testing strategies
6. Learn from findings so far — adapt strategy based on what worked/failed

OUTPUT FORMAT: Always respond in valid JSON."""


class ReasoningEngine:
    """Dedicated reasoning module — thinks before major decisions.

    Implements the CAI Reasoner pattern: a separate agent that only thinks,
    never acts. Called at strategic checkpoints throughout the scan.
    """

    def __init__(self, llm, token_budget: TokenBudget):
        self.llm = llm
        self.token_budget = token_budget
        self._reasoning_history: List[Dict] = []

    async def reason(self, context: str, question: str,
                     available_actions: List[str]) -> ReasoningResult:
        """Think step: analyze situation and recommend next action.

        Args:
            context: Current state (recon data, findings, progress)
            question: Specific decision to make
            available_actions: List of possible actions to choose from

        Returns:
            ReasoningResult with analysis and recommendation
        """
        if self.token_budget and self.token_budget.should_skip("reasoning"):
            return ReasoningResult(
                analysis="",
                recommended_action=available_actions[0] if available_actions else "",
                confidence=0.5,
                skip_reason=f"Budget level: {self.token_budget.get_degradation_level()}"
            )

        est_tokens = (self.token_budget.estimate_tokens(context) + 500) if self.token_budget else 1500
        if self.token_budget and not self.token_budget.can_spend("reasoning", est_tokens):
            return ReasoningResult(
                analysis="",
                recommended_action=available_actions[0] if available_actions else "",
                confidence=0.5,
                skip_reason="Insufficient reasoning budget"
            )

        prompt = f"""Analyze this situation and recommend the BEST next action.

**Current Context:**
{context[:3000]}

**Question:** {question}

**Available Actions:**
{json.dumps(available_actions[:20])}

**Previous Reasoning (last 3):**
{json.dumps(self._reasoning_history[-3:], default=str) if self._reasoning_history else "None yet"}

Respond in JSON:
{{
    "analysis": "Brief analysis of the situation (2-3 sentences)",
    "recommended_action": "The best action from available_actions",
    "confidence": 0.85,
    "reasoning_chain": ["step1: observation", "step2: inference", "step3: conclusion"]
}}"""

        try:
            response = await self.llm.generate(prompt, REASONING_SYSTEM_PROMPT)
            if self.token_budget:
                self.token_budget.record("reasoning", est_tokens, "reason()")

            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                data = json.loads(match.group())
                result = ReasoningResult(
                    analysis=data.get("analysis", ""),
                    recommended_action=data.get("recommended_action", ""),
                    confidence=min(1.0, max(0.0, float(data.get("confidence", 0.7)))),
                    reasoning_chain=data.get("reasoning_chain", []),
                )
                self._reasoning_history.append({
                    "question": question[:100],
                    "action": result.recommended_action,
                    "confidence": result.confidence,
                })
                return result
        except Exception:
            pass

        return ReasoningResult(
            analysis="Reasoning failed — using default",
            recommended_action=available_actions[0] if available_actions else "",
            confidence=0.5,
        )

    async def plan_attack(self, recon_summary: Dict, findings_so_far: List,
                          tested_types: set, progress_pct: float) -> AttackPlan:
        """Strategic planning: what to test next based on everything known.

        Called at 30%, 60%, 90% checkpoints to refine the attack plan.
        Replaces the single _ai_analyze_attack_surface() call at 50%.
        """
        if self.token_budget and self.token_budget.should_skip("reasoning"):
            return AttackPlan(checkpoint_pct=progress_pct)

        est_tokens = 2000
        if self.token_budget and not self.token_budget.can_spend("reasoning", est_tokens):
            return AttackPlan(checkpoint_pct=progress_pct)

        findings_summary = []
        for f in findings_so_far[:10]:
            findings_summary.append({
                "type": getattr(f, "vulnerability_type", "unknown"),
                "endpoint": getattr(f, "affected_endpoint", ""),
                "severity": getattr(f, "severity", "medium"),
                "confidence": getattr(f, "confidence_score", 0),
            })

        prompt = f"""You are replanning the attack strategy at {progress_pct:.0f}% scan progress.

**Reconnaissance:**
- Endpoints: {len(recon_summary.get('endpoints', []))}
- Technologies: {', '.join(recon_summary.get('technologies', [])[:10])}
- Forms: {len(recon_summary.get('forms', []))}
- Parameters: {len(recon_summary.get('parameters', {}))}

**Findings So Far ({len(findings_so_far)}):**
{json.dumps(findings_summary, indent=2)}

**Already Tested Types ({len(tested_types)}):**
{', '.join(sorted(tested_types)[:30])}

**Checkpoint Strategy:**
- At 30%: Widen scope if 0 findings, narrow if 3+ findings
- At 60%: Skip exhausted endpoints, propagate finding patterns
- At 90%: Focus only on high-confidence remaining targets

Respond in JSON:
{{
    "priority_vulns": ["vuln_type_1", "vuln_type_2"],
    "endpoint_rankings": [{{"url": "/api/users", "risk": "high", "types": ["idor", "bola"]}}],
    "parameter_focus": ["id", "file"],
    "attack_vectors": ["Test IDOR on all data endpoints", "Escalate SQLi to UNION"],
    "chain_targets": [{{"from": "ssrf", "to": "lfi", "endpoint": "/proxy"}}]
}}"""

        try:
            response = await self.llm.generate(prompt, REASONING_SYSTEM_PROMPT)
            if self.token_budget:
                self.token_budget.record("reasoning", est_tokens,
                                         f"plan_attack({progress_pct:.0f}%)")

            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                data = json.loads(match.group())
                return AttackPlan(
                    priority_vulns=data.get("priority_vulns", []),
                    endpoint_rankings=data.get("endpoint_rankings", []),
                    parameter_focus=data.get("parameter_focus", []),
                    attack_vectors=data.get("attack_vectors", []),
                    chain_targets=data.get("chain_targets", []),
                    checkpoint_pct=progress_pct,
                    token_cost=est_tokens,
                )
        except Exception:
            pass

        return AttackPlan(checkpoint_pct=progress_pct)

    async def reflect(self, action_taken: str, result_observed: str,
                      success: bool) -> Reflection:
        """Post-action reflection: lightweight learning from results.

        Called after significant testing actions to adapt strategy.
        Uses minimal tokens — just a short reasoning step.
        """
        if self.token_budget and self.token_budget.should_skip("reasoning"):
            return Reflection(should_continue=True)

        est_tokens = 300
        if self.token_budget and not self.token_budget.can_spend("reasoning", est_tokens):
            return Reflection(should_continue=True)

        prompt = f"""Quick reflection on test result:

Action: {action_taken[:200]}
Result: {result_observed[:300]}
Success: {success}

Respond in JSON (be brief):
{{
    "should_continue": true,
    "next_suggestion": "Try X next",
    "learned_pattern": "This type of endpoint responds to Y"
}}"""

        try:
            response = await self.llm.generate(prompt, REASONING_SYSTEM_PROMPT)
            if self.token_budget:
                self.token_budget.record("reasoning", est_tokens, "reflect()")

            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                data = json.loads(match.group())
                return Reflection(
                    should_continue=data.get("should_continue", True),
                    next_suggestion=data.get("next_suggestion", ""),
                    learned_pattern=data.get("learned_pattern", ""),
                )
        except Exception:
            pass

        return Reflection(should_continue=True)

    def get_history(self) -> List[Dict]:
        """Return reasoning history for context."""
        return self._reasoning_history[-10:]
