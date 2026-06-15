"""
NeuroSploit v3 - Adaptive Learner

Cross-scan adaptive learning from user TP/FP feedback on ALL vulnerability types.
Extends the pattern established by AccessControlLearner to cover the full 100-type spectrum.
The agent learns from user feedback to avoid repeating false positives
and to be more aggressive on confirmed true positive patterns.
"""
import json
import re
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

STORAGE_FILE = Path("data/adaptive_learning.json")
MAX_FEEDBACK = 1000
MAX_PATTERNS = 500
FP_THRESHOLD = 3  # After 3 FP feedbacks on same pattern, mark as known FP


@dataclass
class FeedbackRecord:
    """User feedback on a finding."""
    vuln_id: str
    vuln_type: str
    endpoint_pattern: str
    param: str = ""
    payload_pattern: str = ""
    is_true_positive: bool = True
    explanation: str = ""
    severity: str = "medium"
    domain: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class LearnedPattern:
    """A pattern learned from multiple feedback records."""
    endpoint_pattern: str
    vuln_type: str
    indicators: List[str] = field(default_factory=list)
    is_false_positive: bool = True
    confidence: float = 0.5
    feedback_count: int = 0
    domain: str = ""
    explanation_summary: str = ""
    last_updated: str = ""

    def __post_init__(self):
        if not self.last_updated:
            self.last_updated = datetime.utcnow().isoformat()


class AdaptiveLearner:
    """Cross-scan adaptive learning from user feedback on all vuln types."""

    def __init__(self):
        self._feedback: List[FeedbackRecord] = []
        self._patterns: Dict[str, List[LearnedPattern]] = {}  # vuln_type -> patterns
        self._metadata = {"total_feedback": 0, "total_patterns": 0}
        self._dirty = False
        self._load()

    def _load(self):
        """Load persisted learning data."""
        if not STORAGE_FILE.exists():
            return
        try:
            data = json.loads(STORAGE_FILE.read_text())
            for fb in data.get("feedback", []):
                self._feedback.append(FeedbackRecord(**fb))
            for vuln_type, patterns in data.get("patterns", {}).items():
                self._patterns[vuln_type] = [LearnedPattern(**p) for p in patterns]
            self._metadata = data.get("metadata", self._metadata)
        except Exception as e:
            logger.warning(f"Failed to load adaptive learning data: {e}")

    def _save(self):
        """Persist learning data to disk."""
        STORAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "feedback": [asdict(fb) for fb in self._feedback[-MAX_FEEDBACK:]],
            "patterns": {
                vt: [asdict(p) for p in patterns[-MAX_PATTERNS:]]
                for vt, patterns in self._patterns.items()
            },
            "metadata": {
                "total_feedback": len(self._feedback),
                "total_patterns": sum(len(p) for p in self._patterns.values()),
                "last_updated": datetime.utcnow().isoformat(),
            }
        }
        try:
            STORAGE_FILE.write_text(json.dumps(data, indent=2))
            self._dirty = False
        except Exception as e:
            logger.warning(f"Failed to save adaptive learning data: {e}")

    @staticmethod
    def _normalize_endpoint(url: str) -> str:
        """Replace IDs, UUIDs, and dates in URLs with {id} for generalization."""
        if not url:
            return ""
        # Replace UUIDs
        normalized = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{id}', url, flags=re.IGNORECASE
        )
        # Replace numeric IDs in path segments
        normalized = re.sub(r'/\d+(?=/|$|\?)', '/{id}', normalized)
        # Replace dates
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}', '{date}', normalized)
        return normalized

    def record_feedback(
        self,
        vuln_id: str,
        vuln_type: str,
        endpoint: str,
        param: str = "",
        payload: str = "",
        is_tp: bool = True,
        explanation: str = "",
        severity: str = "medium",
        domain: str = "",
    ):
        """Record user TP/FP feedback on a finding."""
        normalized_endpoint = self._normalize_endpoint(endpoint)

        record = FeedbackRecord(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            endpoint_pattern=normalized_endpoint,
            param=param,
            payload_pattern=self._categorize_payload(payload),
            is_true_positive=is_tp,
            explanation=explanation[:2000],
            severity=severity,
            domain=domain,
        )

        self._feedback.append(record)
        self._learn_from_feedback(record)
        self._save()

    @staticmethod
    def _categorize_payload(payload: str) -> str:
        """Categorize a payload into a pattern type."""
        if not payload:
            return ""
        p = payload.lower()
        if "<script" in p or "onerror" in p or "onload" in p:
            return "script_tag"
        if "union" in p and "select" in p:
            return "union_select"
        if "'" in p or '"' in p:
            return "quote_injection"
        if "../" in p or "..\\" in p:
            return "path_traversal"
        if "{{" in p or "${" in p:
            return "template_expression"
        if "http://" in p or "https://" in p:
            return "url_payload"
        return "generic"

    def _learn_from_feedback(self, record: FeedbackRecord):
        """Learn patterns from accumulated feedback."""
        vuln_type = record.vuln_type
        if vuln_type not in self._patterns:
            self._patterns[vuln_type] = []

        # Find existing pattern for this endpoint+vuln_type
        existing = None
        for pattern in self._patterns[vuln_type]:
            if (pattern.endpoint_pattern == record.endpoint_pattern and
                    pattern.domain == record.domain):
                existing = pattern
                break

        if existing:
            existing.feedback_count += 1
            existing.last_updated = datetime.utcnow().isoformat()

            # Recalculate FP/TP ratio
            fb_for_pattern = [
                fb for fb in self._feedback
                if fb.vuln_type == vuln_type
                and fb.endpoint_pattern == record.endpoint_pattern
                and fb.domain == record.domain
            ]
            fp_count = sum(1 for fb in fb_for_pattern if not fb.is_true_positive)
            tp_count = sum(1 for fb in fb_for_pattern if fb.is_true_positive)
            total = fp_count + tp_count

            if total > 0:
                fp_rate = fp_count / total
                existing.is_false_positive = fp_rate >= 0.6
                existing.confidence = max(fp_rate, 1.0 - fp_rate)

            # Update explanation summary
            if record.explanation:
                if existing.explanation_summary:
                    existing.explanation_summary = f"{existing.explanation_summary}; {record.explanation[:200]}"
                else:
                    existing.explanation_summary = record.explanation[:500]
                # Truncate if too long
                existing.explanation_summary = existing.explanation_summary[:1000]

            # Update indicators
            if record.param and record.param not in existing.indicators:
                existing.indicators.append(record.param)
        else:
            # Create new pattern
            new_pattern = LearnedPattern(
                endpoint_pattern=record.endpoint_pattern,
                vuln_type=vuln_type,
                indicators=[record.param] if record.param else [],
                is_false_positive=not record.is_true_positive,
                confidence=0.5,
                feedback_count=1,
                domain=record.domain,
                explanation_summary=record.explanation[:500],
            )
            self._patterns[vuln_type].append(new_pattern)

    def get_learning_context(self, vuln_type: str, domain: str = "") -> str:
        """Generate prompt context from learned patterns for a vuln type."""
        patterns = self._patterns.get(vuln_type, [])
        if not patterns:
            return ""

        # Filter by domain if specified
        relevant = patterns
        if domain:
            domain_patterns = [p for p in patterns if p.domain == domain]
            if domain_patterns:
                relevant = domain_patterns

        fp_patterns = [p for p in relevant if p.is_false_positive and p.confidence >= 0.6]
        tp_patterns = [p for p in relevant if not p.is_false_positive and p.confidence >= 0.6]

        if not fp_patterns and not tp_patterns:
            return ""

        parts = [f"\n## Adaptive Learning Context for {vuln_type}"]

        if fp_patterns:
            parts.append("### Known FALSE POSITIVE patterns (avoid these):")
            for p in fp_patterns[:5]:
                parts.append(f"- Endpoint pattern: {p.endpoint_pattern}")
                if p.explanation_summary:
                    parts.append(f"  Reason: {p.explanation_summary[:300]}")
                if p.indicators:
                    parts.append(f"  Indicators: {', '.join(p.indicators[:5])}")
                parts.append(f"  Confidence: {p.confidence:.0%} ({p.feedback_count} feedbacks)")

        if tp_patterns:
            parts.append("### Known TRUE POSITIVE patterns (be more aggressive):")
            for p in tp_patterns[:5]:
                parts.append(f"- Endpoint pattern: {p.endpoint_pattern}")
                if p.explanation_summary:
                    parts.append(f"  Details: {p.explanation_summary[:300]}")
                parts.append(f"  Confidence: {p.confidence:.0%} ({p.feedback_count} feedbacks)")

        return "\n".join(parts)

    def get_evaluation_hints(
        self, vuln_type: str, endpoint: str, param: str = "", response_body: str = ""
    ) -> Dict:
        """Get hints for the ValidationJudge based on learned patterns."""
        normalized = self._normalize_endpoint(endpoint)
        patterns = self._patterns.get(vuln_type, [])

        hints = {
            "likely_false_positive": False,
            "likely_true_positive": False,
            "confidence_adjustment": 0,
            "reason": "",
            "pattern_match": False,
        }

        for pattern in patterns:
            if pattern.endpoint_pattern == normalized:
                hints["pattern_match"] = True
                if pattern.is_false_positive and pattern.confidence >= 0.7:
                    hints["likely_false_positive"] = True
                    hints["confidence_adjustment"] = -int(pattern.confidence * 30)
                    hints["reason"] = f"Known FP pattern ({pattern.feedback_count} reports): {pattern.explanation_summary[:200]}"
                elif not pattern.is_false_positive and pattern.confidence >= 0.7:
                    hints["likely_true_positive"] = True
                    hints["confidence_adjustment"] = int(pattern.confidence * 15)
                    hints["reason"] = f"Known TP pattern ({pattern.feedback_count} reports)"
                break

        return hints

    def should_skip_test(self, vuln_type: str, endpoint: str, param: str = "") -> Tuple[bool, str]:
        """Check if this test should be skipped based on consistent FP feedback."""
        normalized = self._normalize_endpoint(endpoint)
        patterns = self._patterns.get(vuln_type, [])

        for pattern in patterns:
            if (pattern.endpoint_pattern == normalized and
                    pattern.is_false_positive and
                    pattern.feedback_count >= FP_THRESHOLD and
                    pattern.confidence >= 0.8):
                return True, f"Skipped: {pattern.feedback_count}x FP feedback on {vuln_type} for this endpoint pattern"

        return False, ""

    def suggest_alternatives(self, vuln_type: str, domain: str = "") -> List[str]:
        """Suggest alternative attack approaches based on TP patterns."""
        patterns = self._patterns.get(vuln_type, [])
        suggestions = []

        tp_patterns = [p for p in patterns if not p.is_false_positive]
        if domain:
            domain_tp = [p for p in tp_patterns if p.domain == domain]
            if domain_tp:
                tp_patterns = domain_tp

        for p in tp_patterns[:3]:
            if p.explanation_summary:
                suggestions.append(f"Try approach from confirmed finding: {p.explanation_summary[:200]}")
            if p.indicators:
                suggestions.append(f"Focus on parameters: {', '.join(p.indicators[:3])}")

        return suggestions

    def get_stats(self) -> Dict:
        """Get learning statistics."""
        stats = {}
        for vuln_type, patterns in self._patterns.items():
            fp_count = sum(1 for p in patterns if p.is_false_positive)
            tp_count = sum(1 for p in patterns if not p.is_false_positive)
            total_fb = sum(
                1 for fb in self._feedback if fb.vuln_type == vuln_type
            )
            stats[vuln_type] = {
                "fp_patterns": fp_count,
                "tp_patterns": tp_count,
                "total_feedback": total_fb,
            }
        return stats

    def get_feedback_for_vuln(self, vuln_id: str) -> List[Dict]:
        """Get all feedback records for a specific vulnerability."""
        return [asdict(fb) for fb in self._feedback if fb.vuln_id == vuln_id]
