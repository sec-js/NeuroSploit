"""
NeuroSploit v3 - Endpoint Classifier

Classifies endpoints by function type (auth, upload, api, admin, etc.)
and assigns risk scores + priority vulnerability types for targeted testing.
Replaces linear endpoint iteration with risk-ranked testing order.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class EndpointProfile:
    """Classification result for a single endpoint."""
    url: str
    endpoint_type: str  # "auth", "upload", "api", "admin", "search", "data", "static", "generic"
    risk_score: float   # 0.0 - 1.0
    priority_vulns: List[str] = field(default_factory=list)
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    has_auth_indicators: bool = False
    has_file_handling: bool = False
    has_user_input: bool = False
    tech_hints: List[str] = field(default_factory=list)


class EndpointClassifier:
    """Classifies endpoints by function and assigns risk scores.

    Instead of testing all endpoints equally, this module ranks them
    by type and attack potential, directing more testing effort at
    high-value targets (admin panels, auth endpoints, file uploads).
    """

    ENDPOINT_TYPES = {
        "auth": {
            "indicators": [
                "/login", "/auth", "/signin", "/sign-in", "/register",
                "/signup", "/sign-up", "/password", "/forgot", "/reset",
                "/logout", "/signout", "/sign-out", "/oauth", "/sso",
                "/token", "/session", "/2fa", "/mfa", "/verify",
                "/activate", "/confirm", "/callback",
            ],
            "priority_vulns": [
                "auth_bypass", "brute_force", "weak_password",
                "credential_stuffing", "session_fixation",
                "jwt_manipulation", "broken_authentication",
            ],
            "risk_weight": 0.90,
        },
        "upload": {
            "indicators": [
                "/upload", "/file", "/import", "/attachment", "/media",
                "/image", "/avatar", "/photo", "/document", "/asset",
                "/resource", "/blob", "/storage",
            ],
            "priority_vulns": [
                "file_upload", "xxe", "path_traversal",
                "arbitrary_file_read", "rfi", "command_injection",
            ],
            "risk_weight": 0.85,
        },
        "admin": {
            "indicators": [
                "/admin", "/manage", "/dashboard", "/panel", "/console",
                "/control", "/backend", "/cms", "/wp-admin", "/administrator",
                "/phpmyadmin", "/cpanel", "/webadmin", "/sysadmin",
                "/management", "/internal", "/debug", "/monitoring",
            ],
            "priority_vulns": [
                "auth_bypass", "privilege_escalation", "default_credentials",
                "exposed_admin_panel", "idor", "bfla",
            ],
            "risk_weight": 0.95,
        },
        "api": {
            "indicators": [
                "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
                "/json", "/xml", "/soap", "/rpc", "/grpc", "/webhook",
                "/ws/", "/websocket",
            ],
            "priority_vulns": [
                "idor", "bola", "bfla", "jwt_manipulation",
                "mass_assignment", "sqli_error", "nosql_injection",
                "api_rate_limiting", "broken_authentication",
            ],
            "risk_weight": 0.80,
        },
        "search": {
            "indicators": [
                "/search", "/query", "/find", "/lookup", "/filter",
                "/browse", "/explore", "/autocomplete", "/suggest",
            ],
            "param_indicators": ["q", "query", "search", "keyword", "s", "term"],
            "priority_vulns": [
                "sqli_error", "sqli_blind", "xss_reflected",
                "nosql_injection", "ssti", "xss_stored",
            ],
            "risk_weight": 0.75,
        },
        "data": {
            "indicators": [
                "/users", "/accounts", "/orders", "/profile", "/settings",
                "/preferences", "/billing", "/payment", "/invoice",
                "/transaction", "/subscription", "/notification",
                "/message", "/comment", "/post", "/article",
            ],
            "priority_vulns": [
                "idor", "bola", "mass_assignment",
                "data_exposure", "information_disclosure",
                "privilege_escalation",
            ],
            "risk_weight": 0.75,
        },
        "redirect": {
            "indicators": [
                "/redirect", "/goto", "/out", "/external", "/link",
                "/url", "/forward", "/return", "/next", "/continue",
            ],
            "param_indicators": ["url", "redirect", "next", "return", "goto", "dest"],
            "priority_vulns": [
                "open_redirect", "ssrf", "ssrf_cloud",
            ],
            "risk_weight": 0.70,
        },
        "download": {
            "indicators": [
                "/download", "/export", "/report", "/generate",
                "/pdf", "/csv", "/xlsx", "/print",
            ],
            "priority_vulns": [
                "lfi", "path_traversal", "arbitrary_file_read",
                "ssrf", "command_injection", "ssti",
            ],
            "risk_weight": 0.80,
        },
    }

    # Response header indicators for tech detection
    TECH_INDICATORS = {
        "php": ["x-powered-by: php", ".php", "phpsessid"],
        "asp": ["x-powered-by: asp", "x-aspnet-version", ".aspx", ".asp"],
        "java": ["x-powered-by: servlet", "jsessionid", ".jsp", ".do", ".action"],
        "python": ["x-powered-by: flask", "x-powered-by: django", "csrftoken"],
        "node": ["x-powered-by: express", "connect.sid"],
        "ruby": ["x-powered-by: phusion", "_session_id", ".rb"],
        "wordpress": ["wp-", "wordpress", "wp-content", "wp-json"],
        "drupal": ["drupal", "sites/default"],
        "joomla": ["joomla", "administrator/index.php"],
    }

    def classify(self, url: str, method: str = "GET",
                 params: List[str] = None,
                 response_headers: Dict = None) -> EndpointProfile:
        """Classify a single endpoint and return its profile."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        params = params or list(parse_qs(parsed.query).keys())

        best_type = "generic"
        best_score = 0.30
        best_vulns = ["xss_reflected", "sqli_error"]

        for etype, config in self.ENDPOINT_TYPES.items():
            score = 0.0

            # Path-based matching
            for indicator in config["indicators"]:
                if indicator in path:
                    score = max(score, config["risk_weight"])
                    break

            # Parameter-based matching
            param_indicators = config.get("param_indicators", [])
            if params and param_indicators:
                for p in params:
                    if p.lower() in param_indicators:
                        score = max(score, config["risk_weight"] * 0.9)
                        break

            if score > best_score:
                best_score = score
                best_type = etype
                best_vulns = list(config["priority_vulns"])

        # Boost for dangerous methods
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            best_score = min(1.0, best_score + 0.05)

        # Boost for parameters (more params = more attack surface)
        if params:
            param_boost = min(0.10, len(params) * 0.02)
            best_score = min(1.0, best_score + param_boost)

        # Detect tech hints from headers
        tech_hints = []
        if response_headers:
            header_str = str(response_headers).lower()
            for tech, indicators in self.TECH_INDICATORS.items():
                if any(ind in header_str for ind in indicators):
                    tech_hints.append(tech)

        return EndpointProfile(
            url=url,
            endpoint_type=best_type,
            risk_score=round(best_score, 2),
            priority_vulns=best_vulns,
            method=method,
            params=params or [],
            has_auth_indicators=best_type == "auth",
            has_file_handling=best_type in ("upload", "download"),
            has_user_input=best_type in ("search", "data", "api"),
            tech_hints=tech_hints,
        )

    def rank_endpoints(self, endpoints: List[Dict]) -> List[Tuple[Dict, float]]:
        """Rank a list of endpoints by risk score.

        Args:
            endpoints: List of dicts with at minimum 'url' key,
                       optionally 'method', 'params', 'headers'.

        Returns:
            List of (endpoint_dict, risk_score) sorted by risk descending.
        """
        ranked = []
        for ep in endpoints:
            url = ep.get("url", ep.get("endpoint", ""))
            method = ep.get("method", "GET")
            params = ep.get("params", [])
            headers = ep.get("headers", ep.get("response_headers", {}))

            profile = self.classify(url, method, params, headers)
            ep["_profile"] = profile
            ranked.append((ep, profile.risk_score))

        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def get_endpoint_vuln_priorities(self, url: str, method: str = "GET",
                                      params: List[str] = None) -> List[str]:
        """Return vuln types most likely to succeed on this endpoint."""
        profile = self.classify(url, method, params)
        return profile.priority_vulns

    def get_high_risk_endpoints(self, endpoints: List[Dict],
                                 threshold: float = 0.7) -> List[Dict]:
        """Filter endpoints to only high-risk ones."""
        ranked = self.rank_endpoints(endpoints)
        return [ep for ep, score in ranked if score >= threshold]

    def get_endpoint_test_budget(self, risk_score: float,
                                  base_types: int = 5) -> int:
        """Return how many vuln types to test based on risk score.

        High-risk endpoints get more testing effort.
        """
        if risk_score >= 0.90:
            return base_types * 3     # 15 types for admin/auth
        elif risk_score >= 0.80:
            return base_types * 2     # 10 types for api/upload
        elif risk_score >= 0.70:
            return int(base_types * 1.5)  # 7 types for search/data
        return base_types              # 5 types for generic
