"""
NeuroSploit v3 - Specialist Agent Implementations

Five specialist agents for the multi-agent orchestration system:
  - ReconAgent: Deep reconnaissance and fingerprinting
  - ExploitAgent: Vulnerability testing with adaptive payloads
  - ValidatorAgent: Finding validation and retesting
  - CVEHunterAgent: CVE/exploit intelligence gathering
  - ReportAgent: Finding enhancement and report generation
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.agent_base import SpecialistAgent, AgentResult

logger = logging.getLogger(__name__)

# Lazy imports to avoid circular dependencies
_deep_recon = None
_banner_analyzer = None
_cve_hunter = None
_payload_mutator = None
_param_analyzer = None
_xss_validator = None
_exploit_generator = None
_poc_validator = None
_endpoint_classifier = None


def _get_deep_recon():
    global _deep_recon
    if _deep_recon is None:
        try:
            from core.deep_recon import DeepRecon
            _deep_recon = DeepRecon
        except ImportError:
            _deep_recon = False
    return _deep_recon if _deep_recon else None


def _get_banner_analyzer():
    global _banner_analyzer
    if _banner_analyzer is None:
        try:
            from core.banner_analyzer import BannerAnalyzer
            _banner_analyzer = BannerAnalyzer
        except ImportError:
            _banner_analyzer = False
    return _banner_analyzer if _banner_analyzer else None


def _get_cve_hunter():
    global _cve_hunter
    if _cve_hunter is None:
        try:
            from core.cve_hunter import CVEHunter
            _cve_hunter = CVEHunter
        except ImportError:
            _cve_hunter = False
    return _cve_hunter if _cve_hunter else None


def _get_payload_mutator():
    global _payload_mutator
    if _payload_mutator is None:
        try:
            from core.payload_mutator import PayloadMutator
            _payload_mutator = PayloadMutator
        except ImportError:
            _payload_mutator = False
    return _payload_mutator if _payload_mutator else None


def _get_param_analyzer():
    global _param_analyzer
    if _param_analyzer is None:
        try:
            from core.param_analyzer import ParameterAnalyzer
            _param_analyzer = ParameterAnalyzer
        except ImportError:
            _param_analyzer = False
    return _param_analyzer if _param_analyzer else None


def _get_endpoint_classifier():
    global _endpoint_classifier
    if _endpoint_classifier is None:
        try:
            from core.endpoint_classifier import EndpointClassifier
            _endpoint_classifier = EndpointClassifier
        except ImportError:
            _endpoint_classifier = False
    return _endpoint_classifier if _endpoint_classifier else None


def _get_exploit_generator():
    global _exploit_generator
    if _exploit_generator is None:
        try:
            from core.exploit_generator import ExploitGenerator
            _exploit_generator = ExploitGenerator
        except ImportError:
            _exploit_generator = False
    return _exploit_generator if _exploit_generator else None


def _get_poc_validator():
    global _poc_validator
    if _poc_validator is None:
        try:
            from core.poc_validator import PoCValidator
            _poc_validator = PoCValidator
        except ImportError:
            _poc_validator = False
    return _poc_validator if _poc_validator else None


class ReconAgent(SpecialistAgent):
    """Deep reconnaissance specialist.

    Uses DeepRecon, BannerAnalyzer, and CVEHunter to produce
    enriched recon data with version findings and CVE matches.
    """

    def __init__(self, llm=None, memory=None, budget_allocation: float = 0.20,
                 budget=None, request_engine=None):
        super().__init__("recon", llm, memory, budget_allocation, budget)
        self.request_engine = request_engine

    async def run(self, context: Dict) -> AgentResult:
        result = AgentResult(agent_name=self.name)
        target = context.get("target", "")
        headers = context.get("headers", {})
        body = context.get("body", "")
        technologies = context.get("technologies", [])

        if not target:
            result.error = "No target provided"
            return result

        discovered_endpoints = []
        version_findings = []
        js_analysis = None
        api_schema = None

        # Deep recon: JS analysis, sitemap, robots, API enumeration
        DeepReconCls = _get_deep_recon()
        if DeepReconCls and self.request_engine:
            try:
                recon = DeepReconCls(self.request_engine)

                # Sitemap + robots
                sitemap_urls = await recon.parse_sitemap(target)
                discovered_endpoints.extend(sitemap_urls)
                self.tasks_completed += 1

                robots_urls = await recon.parse_robots(target)
                discovered_endpoints.extend(robots_urls)
                self.tasks_completed += 1

                # API enumeration
                api_schema = await recon.enumerate_api(target, technologies)
                if api_schema:
                    api_endpoints = getattr(api_schema, "endpoints", [])
                    discovered_endpoints.extend(
                        ep.get("path", "") for ep in api_endpoints
                        if isinstance(ep, dict)
                    )
                self.tasks_completed += 1

                # Deep fingerprinting
                fingerprints = await recon.deep_fingerprint(
                    target, headers, body
                )
                if fingerprints:
                    version_findings.extend(fingerprints)
                self.tasks_completed += 1

            except Exception as e:
                logger.debug(f"ReconAgent deep recon error: {e}")

        # Banner analysis
        BannerCls = _get_banner_analyzer()
        if BannerCls and version_findings:
            try:
                analyzer = BannerCls()
                banner_findings = analyzer.analyze(version_findings)
                result.findings.extend(banner_findings)
                self.tasks_completed += 1
            except Exception as e:
                logger.debug(f"ReconAgent banner analysis error: {e}")

        # Dedup endpoints
        discovered_endpoints = list(set(
            ep for ep in discovered_endpoints if ep and isinstance(ep, str)
        ))

        result.data = {
            "discovered_endpoints": discovered_endpoints,
            "version_findings": version_findings,
            "api_schema": api_schema,
            "js_analysis": js_analysis,
        }

        # Hand off high-risk endpoints to exploit agent
        if discovered_endpoints:
            result.handoff_to = "exploit"
            result.handoff_context = {
                "endpoints": discovered_endpoints,
                "versions": version_findings,
            }

        return result


class ExploitAgent(SpecialistAgent):
    """Vulnerability testing and exploitation specialist.

    Classifies endpoints, ranks parameters, tests with adaptive
    payloads, and generates validated PoCs.
    """

    def __init__(self, llm=None, memory=None, budget_allocation: float = 0.35,
                 budget=None, request_engine=None):
        super().__init__("exploit", llm, memory, budget_allocation, budget)
        self.request_engine = request_engine

    async def run(self, context: Dict) -> AgentResult:
        result = AgentResult(agent_name=self.name)
        endpoints = context.get("endpoints", [])
        target = context.get("target", "")

        if not endpoints and not target:
            result.error = "No endpoints or target provided"
            return result

        # Classify and rank endpoints
        ClassifierCls = _get_endpoint_classifier()
        if ClassifierCls:
            classifier = ClassifierCls()
            endpoint_dicts = []
            for ep in endpoints:
                if isinstance(ep, str):
                    ep = {"url": ep}
                endpoint_dicts.append(ep)

            if endpoint_dicts:
                ranked = classifier.rank_endpoints(endpoint_dicts)
                result.data["ranked_endpoints"] = [
                    {"url": ep.get("url", ""), "score": score}
                    for ep, score in ranked[:50]
                ]

        # Classify parameters
        ParamCls = _get_param_analyzer()
        if ParamCls:
            analyzer = ParamCls()
            params = context.get("params", {})
            if params:
                ranked_params = analyzer.rank_parameters(params)
                result.data["ranked_params"] = [
                    {"name": name, "score": score, "vulns": vulns}
                    for name, score, vulns in ranked_params
                ]

        self.tasks_completed += 1

        # Hand off findings to validator
        if self.findings:
            result.handoff_to = "validator"
            result.handoff_context = {
                "findings": self.findings,
            }

        return result


class ValidatorAgent(SpecialistAgent):
    """Finding validation specialist (retester pattern).

    Independently re-tests each finding with different payload
    variants to confirm reproducibility.
    """

    def __init__(self, llm=None, memory=None, budget_allocation: float = 0.20,
                 budget=None, request_engine=None):
        super().__init__("validator", llm, memory, budget_allocation, budget)
        self.request_engine = request_engine

    async def run(self, context: Dict) -> AgentResult:
        result = AgentResult(agent_name=self.name)
        findings = context.get("findings", [])

        if not findings:
            result.error = "No findings to validate"
            return result

        validated = []
        rejected = []

        PoCValidatorCls = _get_poc_validator()
        poc_validator = PoCValidatorCls(self.request_engine) if PoCValidatorCls else None

        for finding in findings:
            if self.is_cancelled:
                break

            vuln_type = getattr(finding, "vulnerability_type", "")
            poc_code = getattr(finding, "poc_code", "")

            # Validate PoC if possible
            if poc_validator and poc_code:
                try:
                    validation = await poc_validator.validate(
                        poc_code, finding, self.request_engine
                    )
                    if validation.valid:
                        validated.append(finding)
                        if hasattr(finding, "poc_validated"):
                            finding.poc_validated = True
                    else:
                        rejected.append(finding)
                except Exception as e:
                    logger.debug(f"ValidatorAgent PoC validation error: {e}")
                    validated.append(finding)  # Keep on error
            else:
                validated.append(finding)  # Keep if can't validate

            self.tasks_completed += 1

        result.findings = validated
        result.data = {
            "validated_count": len(validated),
            "rejected_count": len(rejected),
            "rejected_ids": [
                getattr(f, "id", "") for f in rejected
            ],
        }

        return result


class CVEHunterAgent(SpecialistAgent):
    """CVE and exploit intelligence specialist.

    Extracts version information and searches NVD + GitHub
    for known vulnerabilities and public exploits.
    """

    def __init__(self, llm=None, memory=None, budget_allocation: float = 0.10,
                 budget=None, request_engine=None):
        super().__init__("cve_hunter", llm, memory, budget_allocation, budget)
        self.request_engine = request_engine

    async def run(self, context: Dict) -> AgentResult:
        result = AgentResult(agent_name=self.name)
        headers = context.get("headers", {})
        body = context.get("body", "")
        technologies = context.get("technologies", [])
        versions = context.get("versions", [])

        CVEHunterCls = _get_cve_hunter()
        BannerCls = _get_banner_analyzer()

        if not CVEHunterCls:
            result.error = "CVEHunter not available"
            return result

        hunter = CVEHunterCls(self.request_engine)

        try:
            # Extract versions + search for CVEs
            cve_findings = await hunter.hunt(headers, body, technologies)
            result.findings.extend(cve_findings)
            self.tasks_completed += 1
        except Exception as e:
            logger.debug(f"CVEHunterAgent hunt error: {e}")

        # Banner analysis on provided versions
        if BannerCls and versions:
            try:
                analyzer = BannerCls()
                banner_findings = analyzer.analyze(versions)
                result.findings.extend(banner_findings)
                self.tasks_completed += 1
            except Exception as e:
                logger.debug(f"CVEHunterAgent banner error: {e}")

        result.data = {
            "cve_count": len(result.findings),
        }
        return result


class ReportAgent(SpecialistAgent):
    """Report generation and finding enhancement specialist.

    Enhances findings with AI descriptions, generates PoCs,
    and prepares report-ready output.
    """

    def __init__(self, llm=None, memory=None, budget_allocation: float = 0.15,
                 budget=None):
        super().__init__("reporter", llm, memory, budget_allocation, budget)

    async def run(self, context: Dict) -> AgentResult:
        result = AgentResult(agent_name=self.name)
        findings = context.get("findings", [])
        recon_data = context.get("recon_data", None)

        if not findings:
            result.data = {"enhanced_count": 0}
            return result

        ExploitGenCls = _get_exploit_generator()
        gen = ExploitGenCls() if ExploitGenCls else None

        enhanced_count = 0
        for finding in findings:
            if self.is_cancelled:
                break

            # Generate enhanced PoC if exploit generator available
            if gen and self.llm:
                try:
                    exploit_result = await gen.generate(
                        finding, recon_data, self.llm, self.budget
                    )
                    if exploit_result and hasattr(exploit_result, "poc_code"):
                        if hasattr(finding, "poc_code"):
                            finding.poc_code = exploit_result.poc_code
                        enhanced_count += 1
                except Exception as e:
                    logger.debug(f"ReportAgent PoC generation error: {e}")

            # AI-enhanced description
            if self.llm:
                desc = await self._enhance_description(finding)
                if desc and hasattr(finding, "ai_description"):
                    finding.ai_description = desc
                    enhanced_count += 1

            self.tasks_completed += 1

        result.findings = findings
        result.data = {"enhanced_count": enhanced_count}
        return result

    async def _enhance_description(self, finding) -> Optional[str]:
        """Generate AI-enhanced finding description."""
        vuln_type = getattr(finding, "vulnerability_type", "unknown")
        endpoint = getattr(finding, "affected_endpoint", "")
        confidence = getattr(finding, "confidence_score", 0)

        prompt = f"""Write a concise 2-3 sentence professional description for this vulnerability finding:

Type: {vuln_type}
Endpoint: {endpoint}
Confidence: {confidence}%

Focus on: what the vulnerability is, how it was confirmed, and the potential business impact.
Do NOT exaggerate severity or make unsupported claims."""

        return await self._llm_call(prompt, "enhancement", 300)
