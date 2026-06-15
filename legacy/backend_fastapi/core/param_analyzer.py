"""
NeuroSploit v3 - Parameter Semantic Analyzer

Understands parameter semantics for targeted vulnerability testing.
Classifies parameters by name/value patterns and recommends
which vulnerability types to prioritize for each parameter.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional


@dataclass
class ParamProfile:
    """Profile of a single parameter."""
    name: str
    category: str  # "id", "file", "url", "query", "auth", "code", "generic"
    risk_score: float  # 0.0 - 1.0
    priority_vulns: List[str] = field(default_factory=list)
    test_strategy: str = "default"
    value_hint: str = ""  # Observed value pattern


class ParameterAnalyzer:
    """Understands parameter semantics for targeted testing.

    Instead of testing all parameters equally (params[:5]), this module
    ranks parameters by attack potential and recommends specific vuln
    types to test for each parameter.
    """

    PARAM_SEMANTICS = {
        "id_params": {
            "names": ["id", "uid", "user_id", "userid", "account_id", "accountid",
                       "order_id", "orderid", "item_id", "itemid", "product_id",
                       "productid", "post_id", "comment_id", "doc_id", "resource_id",
                       "pid", "oid", "cid", "rid"],
            "vuln_types": ["idor", "bola", "bfla", "sqli_error", "sqli_blind"],
            "risk_score": 0.85,
            "test_strategy": "increment_decrement",
        },
        "file_params": {
            "names": ["file", "path", "filepath", "filename", "doc", "document",
                       "page", "include", "template", "tmpl", "tpl", "view",
                       "load", "read", "src", "source", "content", "folder",
                       "directory", "dir", "attachment"],
            "vuln_types": ["lfi", "path_traversal", "arbitrary_file_read", "rfi",
                           "file_upload"],
            "risk_score": 0.90,
            "test_strategy": "file_traversal",
        },
        "url_params": {
            "names": ["url", "redirect", "redirect_url", "redirect_uri", "next",
                       "return", "returnto", "return_url", "callback", "goto",
                       "link", "ref", "referer", "dest", "destination", "target",
                       "uri", "continue", "forward", "out", "checkout_url"],
            "vuln_types": ["ssrf", "open_redirect", "ssrf_cloud"],
            "risk_score": 0.85,
            "test_strategy": "url_injection",
        },
        "query_params": {
            "names": ["q", "query", "search", "keyword", "keywords", "term",
                       "filter", "find", "lookup", "s", "text", "input",
                       "name", "title", "description"],
            "vuln_types": ["sqli_error", "sqli_blind", "sqli_union", "nosql_injection",
                           "xss_reflected", "ssti"],
            "risk_score": 0.75,
            "test_strategy": "injection",
        },
        "auth_params": {
            "names": ["token", "auth", "auth_token", "access_token", "key",
                       "api_key", "apikey", "session", "session_id", "sessionid",
                       "jwt", "bearer", "secret", "password", "passwd", "pwd"],
            "vuln_types": ["jwt_manipulation", "auth_bypass", "session_fixation",
                           "broken_authentication"],
            "risk_score": 0.80,
            "test_strategy": "auth_manipulation",
        },
        "code_params": {
            "names": ["cmd", "exec", "command", "code", "eval", "expression",
                       "run", "shell", "execute", "ping", "ip", "host",
                       "hostname", "domain"],
            "vuln_types": ["command_injection", "ssti", "rce",
                           "expression_language_injection"],
            "risk_score": 0.95,
            "test_strategy": "code_execution",
        },
        "format_params": {
            "names": ["format", "type", "content_type", "output", "ext",
                       "mime", "render", "engine", "processor"],
            "vuln_types": ["ssti", "xxe", "insecure_deserialization"],
            "risk_score": 0.70,
            "test_strategy": "format_manipulation",
        },
        "sort_params": {
            "names": ["sort", "sortby", "sort_by", "order", "orderby",
                       "order_by", "column", "col", "field", "group",
                       "groupby", "group_by", "limit", "offset"],
            "vuln_types": ["sqli_error", "sqli_blind"],
            "risk_score": 0.65,
            "test_strategy": "sql_injection",
        },
    }

    # Value patterns that indicate specific vulnerability types
    VALUE_PATTERNS = {
        r"^\d+$": {"category": "numeric_id", "vulns": ["idor", "bola", "sqli_error"]},
        r"^[a-f0-9\-]{32,}$": {"category": "uuid", "vulns": ["idor"]},
        r"^https?://": {"category": "url_value", "vulns": ["ssrf", "open_redirect"]},
        r"[/\\]": {"category": "path_value", "vulns": ["lfi", "path_traversal"]},
        r"\.(?:php|asp|jsp|html|xml|json)$": {"category": "file_ext", "vulns": ["lfi", "rfi"]},
        r"^eyJ": {"category": "jwt_token", "vulns": ["jwt_manipulation"]},
        r"<[^>]+>": {"category": "html_value", "vulns": ["xss_reflected", "xss_stored"]},
        r"(?:SELECT|INSERT|UPDATE|DELETE)\s": {"category": "sql_fragment", "vulns": ["sqli_error"]},
    }

    def classify_parameter(self, name: str, value: str = "") -> ParamProfile:
        """Classify a parameter by name + value analysis."""
        name_lower = name.lower().strip()

        # Check name-based semantics
        for category, config in self.PARAM_SEMANTICS.items():
            if name_lower in config["names"]:
                return ParamProfile(
                    name=name,
                    category=category.replace("_params", ""),
                    risk_score=config["risk_score"],
                    priority_vulns=list(config["vuln_types"]),
                    test_strategy=config["test_strategy"],
                )

        # Check partial name matches
        for category, config in self.PARAM_SEMANTICS.items():
            for pattern_name in config["names"]:
                if pattern_name in name_lower or name_lower in pattern_name:
                    return ParamProfile(
                        name=name,
                        category=category.replace("_params", ""),
                        risk_score=config["risk_score"] * 0.8,  # Lower confidence for partial match
                        priority_vulns=list(config["vuln_types"]),
                        test_strategy=config["test_strategy"],
                    )

        # Check value-based patterns
        if value:
            for pattern, info in self.VALUE_PATTERNS.items():
                if re.search(pattern, value, re.IGNORECASE):
                    return ParamProfile(
                        name=name,
                        category=info["category"],
                        risk_score=0.65,
                        priority_vulns=info["vulns"],
                        test_strategy="value_based",
                        value_hint=info["category"],
                    )

        # Generic parameter — still testable
        return ParamProfile(
            name=name,
            category="generic",
            risk_score=0.40,
            priority_vulns=["xss_reflected", "sqli_error"],
            test_strategy="default",
        )

    def rank_parameters(self, params: Dict[str, str]) -> List[Tuple[str, float, List[str]]]:
        """Rank parameters by attack potential.

        Args:
            params: Dict of param_name → param_value

        Returns:
            Sorted list of (name, risk_score, priority_vulns), highest risk first
        """
        rankings = []
        for name, value in params.items():
            profile = self.classify_parameter(name, value if isinstance(value, str) else "")
            rankings.append((name, profile.risk_score, profile.priority_vulns))

        # Sort by risk score descending
        rankings.sort(key=lambda x: x[1], reverse=True)
        return rankings

    def get_test_strategy(self, param_name: str) -> str:
        """Return recommended test strategy for a parameter."""
        profile = self.classify_parameter(param_name)
        return profile.test_strategy

    def get_vuln_types_for_param(self, param_name: str, param_value: str = "",
                                  max_types: int = 5) -> List[str]:
        """Return vuln types most relevant to this parameter."""
        profile = self.classify_parameter(param_name, param_value)
        return profile.priority_vulns[:max_types]

    def get_high_risk_params(self, params: Dict[str, str],
                              threshold: float = 0.7) -> List[str]:
        """Return only parameters above the risk threshold."""
        rankings = self.rank_parameters(params)
        return [name for name, score, _ in rankings if score >= threshold]
