"""
NeuroSploit v3 - Researcher AI Agent

Dedicated 0-day research agent that uses Kali Linux sandbox for tool execution,
AI-driven tool selection/installation, and hypothesis-driven vulnerability discovery.

Architecture:
  - Reasoning loop: Observe → Hypothesize → Plan Tools → Execute in Sandbox → Analyze → Confirm/Reject
  - AI selects tools from ToolRegistry (56+ tools), installs on demand in Kali container
  - Each hypothesis generates targeted test plans with sandbox-executed tool chains
  - Findings feed through existing ValidationJudge pipeline for confirmation
  - Enabled via ENABLE_RESEARCHER_AI=true + enable_kali_sandbox=true per scan

Key difference from standard agent streams:
  - Standard streams use hardcoded payload sets → Researcher uses AI-generated test plans
  - Standard streams test known vuln types → Researcher hypothesizes unknown vulnerabilities
  - Standard streams run tools locally → Researcher executes everything in Kali sandbox
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# Optional imports with guards
try:
    from core.kali_sandbox import KaliSandbox
    from core.tool_registry import ToolRegistry
    HAS_KALI = True
except ImportError:
    HAS_KALI = False

try:
    from core.sandbox_manager import SandboxResult
    HAS_SANDBOX_RESULT = True
except ImportError:
    HAS_SANDBOX_RESULT = False


# ── Data Classes ──────────────────────────────────────────────────────────

@dataclass
class ResearchHypothesis:
    """A hypothesis about a potential vulnerability to test."""
    id: str
    title: str
    description: str
    target_endpoint: str
    vuln_category: str  # e.g., "logic_flaw", "race_condition", "auth_bypass", "injection"
    confidence: float  # 0.0-1.0 how likely this is exploitable
    tools_needed: List[str] = field(default_factory=list)
    test_commands: List[str] = field(default_factory=list)
    expected_indicators: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, testing, confirmed, rejected
    evidence: str = ""
    reasoning: str = ""


@dataclass
class ToolExecution:
    """Record of a tool execution in the sandbox."""
    tool: str
    command: str
    purpose: str
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    findings_extracted: List[Dict] = field(default_factory=list)


@dataclass
class ResearchResult:
    """Final result from a research session."""
    hypotheses_tested: int = 0
    hypotheses_confirmed: int = 0
    tools_used: Set[str] = field(default_factory=set)
    tools_installed: Set[str] = field(default_factory=set)
    findings: List[Dict] = field(default_factory=list)
    tool_executions: List[ToolExecution] = field(default_factory=list)
    total_duration: float = 0.0
    token_usage: int = 0


# ── System Prompts ────────────────────────────────────────────────────────

RESEARCHER_SYSTEM_PROMPT = """You are an elite security researcher focused on discovering 0-day vulnerabilities and novel attack vectors.

CRITICAL RULES:
1. Think like an adversary — look for UNUSUAL behaviors, edge cases, race conditions, logic flaws
2. Don't just run scanners — REASON about the application architecture and hypothesize weaknesses
3. Base hypotheses on CONCRETE observations from recon data, not speculation
4. For each hypothesis, design SPECIFIC tool commands to test it
5. Analyze tool output carefully — distinguish between false positives and real findings
6. Chain findings — one weakness may unlock access to deeper vulnerabilities
7. Use the Kali sandbox tools strategically, not exhaustively

TOOL SELECTION STRATEGY:
- Use nuclei with specific templates for known-CVE testing
- Use sqlmap for targeted injection points only (not blind scans)
- Use ffuf/gobuster for hidden endpoint discovery
- Use nmap -sV -sC for service fingerprinting
- Use curl for precise manual verification of hypotheses
- Use custom scripts (python3, bash) for logic flaw testing
- NEVER run tools with default broad scans — always TARGET specific endpoints/params

OUTPUT FORMAT: Always respond in valid JSON."""


HYPOTHESIS_PROMPT = """Based on the following reconnaissance data, generate security research hypotheses.

**Target:** {target}

**Reconnaissance:**
- Endpoints ({endpoint_count}): {endpoints}
- Technologies: {technologies}
- Parameters: {parameters}
- Response headers: {headers}
- Existing findings: {existing_findings}

**Already tested hypotheses:** {tested_hypotheses}

Generate 3-5 NEW hypotheses about potential vulnerabilities. Focus on:
1. Logic flaws that automated scanners miss (race conditions, TOCTOU, business logic)
2. Misconfigurations specific to the detected tech stack
3. Chained attacks combining multiple weak signals
4. Known CVEs for detected software versions
5. Custom code vulnerabilities visible through error messages or behavior

Respond in JSON:
{{
    "hypotheses": [
        {{
            "id": "H001",
            "title": "Race condition in cart checkout",
            "description": "The checkout flow may be vulnerable to TOCTOU if price validation happens before payment processing",
            "target_endpoint": "/checkout/process",
            "vuln_category": "logic_flaw",
            "confidence": 0.6,
            "tools_needed": ["curl", "python3"],
            "test_commands": [
                "curl -X POST '{target}/checkout/process' -d 'item=1&qty=1' -H 'Cookie: session=xxx' &",
                "for i in $(seq 1 10); do curl -X POST '{target}/checkout/process' -d 'item=1&qty=1' -H 'Cookie: session=xxx' & done; wait"
            ],
            "expected_indicators": ["duplicate order", "negative balance", "status 500", "inconsistent qty"],
            "reasoning": "Cart endpoint accepts concurrent requests. If no mutex/lock on inventory check, TOCTOU may allow double-spend."
        }}
    ]
}}"""


TOOL_PLAN_PROMPT = """Plan the tool execution for testing this hypothesis in a Kali Linux sandbox.

**Hypothesis:** {hypothesis_title}
**Description:** {hypothesis_desc}
**Target endpoint:** {target_endpoint}
**Category:** {vuln_category}
**Available tools (pre-installed):** nuclei, naabu, httpx, subfinder, katana, ffuf, gobuster, dalfox, nikto, sqlmap, nmap, curl, python3, bash
**Installable tools:** wpscan, dirb, hydra, testssl, sslscan, dirsearch, wfuzz, arjun, wafw00f, gau, gitleaks, commix, sslyze

Design 1-5 targeted tool commands to test this hypothesis. Each command should:
- Target ONLY the specific endpoint/parameter in question
- Have clear expected output that would confirm/deny the hypothesis
- Include proper timeouts and output format flags

Respond in JSON:
{{
    "tools_needed": ["tool1", "tool2"],
    "commands": [
        {{
            "tool": "curl",
            "command": "curl -s -o /dev/null -w '%{{http_code}}' -X POST ...",
            "purpose": "Test if endpoint accepts method override",
            "timeout": 30,
            "success_indicators": ["405", "200 with different response"],
            "failure_indicators": ["403", "404", "identical response"]
        }}
    ],
    "analysis_notes": "If command 1 returns 200, proceed with command 2 to extract data"
}}"""


ANALYZE_RESULTS_PROMPT = """Analyze the results of testing hypothesis: {hypothesis_title}

**Hypothesis:** {hypothesis_desc}
**Expected indicators:** {expected_indicators}

**Tool execution results:**
{tool_results}

Based on the actual results:
1. Was the hypothesis confirmed, partially confirmed, or rejected?
2. What evidence supports your conclusion?
3. If confirmed, what is the severity and impact?
4. Are there follow-up hypotheses to test?

Respond in JSON:
{{
    "verdict": "confirmed|partially_confirmed|rejected",
    "confidence": 0.85,
    "evidence_summary": "The response contained...",
    "severity": "critical|high|medium|low|info",
    "impact": "An attacker could...",
    "follow_up_hypotheses": ["Test if same flaw exists on /api/v2/checkout"],
    "poc_steps": ["Step 1: ...", "Step 2: ..."]
}}"""


class ResearcherAgent:
    """AI-driven 0-day vulnerability researcher using Kali sandbox.

    The researcher operates in a hypothesis-driven loop:
    1. OBSERVE: Analyze recon data and existing findings
    2. HYPOTHESIZE: Generate targeted hypotheses about potential vulns
    3. PLAN: Design tool execution plans for each hypothesis
    4. EXECUTE: Run tools in Kali sandbox
    5. ANALYZE: Evaluate results and confirm/reject hypotheses
    6. ITERATE: Generate follow-up hypotheses from discoveries

    Unlike the standard 3-stream agent, the researcher:
    - Uses AI reasoning at every step (not just verification)
    - Runs ALL tools in sandboxed Kali containers (no local execution)
    - Focuses on novel/unknown vulns, not just known patterns
    - Chains findings to discover deeper attack paths
    """

    MAX_HYPOTHESES = 15  # Max hypotheses per research session
    MAX_TOOL_EXECUTIONS = 30  # Max individual tool runs
    MAX_ITERATIONS = 5  # Max hypothesis generation rounds

    def __init__(
        self,
        llm,
        scan_id: str,
        target: str,
        log_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
        finding_callback: Optional[Callable] = None,
        recon_data: Optional[Dict] = None,
        existing_findings: Optional[List] = None,
        token_budget=None,
    ):
        self.llm = llm
        self.scan_id = scan_id
        self.target = target
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.finding_callback = finding_callback
        self.recon_data = recon_data or {}
        self.existing_findings = existing_findings or []
        self.token_budget = token_budget

        # State
        self._sandbox: Optional[Any] = None
        self._tool_registry = ToolRegistry() if HAS_KALI else None
        self._hypotheses: List[ResearchHypothesis] = []
        self._tested_hypotheses: Set[str] = set()
        self._tool_executions: List[ToolExecution] = []
        self._findings: List[Dict] = []
        self._tools_used: Set[str] = set()
        self._tools_installed: Set[str] = set()
        self._cancelled = False
        self._token_usage = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def initialize(self) -> Tuple[bool, str]:
        """Initialize the Kali sandbox for this research session."""
        if not HAS_KALI:
            return False, "Kali sandbox not available (missing core.kali_sandbox)"

        self._sandbox = KaliSandbox(
            scan_id=f"research-{self.scan_id}",
            image=os.getenv("KALI_SANDBOX_IMAGE", "neurosploit-kali:latest"),
        )
        ok, msg = await self._sandbox.initialize()
        if ok:
            await self._log("success", f"[RESEARCHER] Kali sandbox ready: {msg}")
        else:
            await self._log("warning", f"[RESEARCHER] Sandbox init failed: {msg}")
        return ok, msg

    async def shutdown(self):
        """Destroy the sandbox container."""
        if self._sandbox:
            await self._sandbox.stop()
            self._sandbox = None

    def cancel(self):
        """Signal cancellation."""
        self._cancelled = True

    # ------------------------------------------------------------------
    # Main Research Loop
    # ------------------------------------------------------------------
    async def run(self) -> ResearchResult:
        """Execute the full research pipeline.

        Returns ResearchResult with all findings and metadata.
        """
        start_time = time.time()
        result = ResearchResult()

        if not self._sandbox or not self._sandbox.is_available:
            await self._log("error", "[RESEARCHER] No sandbox available, cannot run")
            return result

        await self._log("info", "=" * 60)
        await self._log("info", "  AI RESEARCHER — 0-Day Discovery Mode")
        await self._log("info", f"  Target: {self.target}")
        await self._log("info", f"  Sandbox: {self._sandbox.container_name}")
        await self._log("info", "=" * 60)

        try:
            # Iteration loop: observe → hypothesize → test → analyze → repeat
            for iteration in range(self.MAX_ITERATIONS):
                if self._cancelled:
                    break
                if len(self._hypotheses) >= self.MAX_HYPOTHESES:
                    await self._log("info", "[RESEARCHER] Max hypotheses reached")
                    break
                if len(self._tool_executions) >= self.MAX_TOOL_EXECUTIONS:
                    await self._log("info", "[RESEARCHER] Max tool executions reached")
                    break

                progress_base = int((iteration / self.MAX_ITERATIONS) * 100)
                await self._progress(progress_base, f"Research iteration {iteration + 1}")

                # 1. Generate hypotheses
                await self._log("info", f"[RESEARCHER] Iteration {iteration + 1}: Generating hypotheses...")
                new_hypotheses = await self._generate_hypotheses()

                if not new_hypotheses:
                    await self._log("info", "[RESEARCHER] No new hypotheses generated, research complete")
                    break

                await self._log("info", f"[RESEARCHER] Generated {len(new_hypotheses)} hypotheses")

                # 2. Test each hypothesis
                for i, hypothesis in enumerate(new_hypotheses):
                    if self._cancelled:
                        break

                    sub_progress = progress_base + int(((i + 1) / len(new_hypotheses)) * (100 / self.MAX_ITERATIONS))
                    await self._progress(min(sub_progress, 95), f"Testing: {hypothesis.title[:40]}...")

                    await self._log("info", f"[RESEARCHER] Testing H{hypothesis.id}: {hypothesis.title}")
                    await self._log("info", f"  Category: {hypothesis.vuln_category} | Confidence: {hypothesis.confidence:.0%}")

                    # Plan tools
                    tool_plan = await self._plan_tools(hypothesis)
                    if not tool_plan:
                        hypothesis.status = "rejected"
                        hypothesis.evidence = "Failed to generate tool plan"
                        continue

                    # Execute tools in sandbox
                    tool_results = await self._execute_tool_plan(hypothesis, tool_plan)

                    # Analyze results
                    verdict = await self._analyze_results(hypothesis, tool_results)

                    if verdict.get("verdict") == "confirmed":
                        hypothesis.status = "confirmed"
                        hypothesis.evidence = verdict.get("evidence_summary", "")
                        await self._create_finding(hypothesis, verdict)
                        await self._log("success",
                            f"  CONFIRMED: {hypothesis.title} "
                            f"[{verdict.get('severity', 'medium').upper()}]"
                        )
                    elif verdict.get("verdict") == "partially_confirmed":
                        hypothesis.status = "confirmed"
                        hypothesis.evidence = verdict.get("evidence_summary", "")
                        await self._create_finding(hypothesis, verdict)
                        await self._log("warning",
                            f"  PARTIAL: {hypothesis.title} — needs manual verification"
                        )
                    else:
                        hypothesis.status = "rejected"
                        hypothesis.evidence = verdict.get("evidence_summary", "No exploitable behavior observed")
                        await self._log("info", f"  Rejected: {hypothesis.title}")

                    self._tested_hypotheses.add(hypothesis.id)

                    # Follow-up hypotheses from analysis
                    follow_ups = verdict.get("follow_up_hypotheses", [])
                    if follow_ups:
                        await self._log("info", f"  {len(follow_ups)} follow-up hypotheses queued")

        except Exception as e:
            await self._log("error", f"[RESEARCHER] Research error: {e}")

        # Finalize
        await self._progress(100, "Research complete")
        result.hypotheses_tested = len(self._tested_hypotheses)
        result.hypotheses_confirmed = sum(1 for h in self._hypotheses if h.status == "confirmed")
        result.tools_used = self._tools_used.copy()
        result.tools_installed = self._tools_installed.copy()
        result.findings = self._findings.copy()
        result.tool_executions = self._tool_executions.copy()
        result.total_duration = time.time() - start_time
        result.token_usage = self._token_usage

        await self._log("info", "=" * 60)
        await self._log("info", "  RESEARCH COMPLETE")
        await self._log("info", f"  Hypotheses tested: {result.hypotheses_tested}")
        await self._log("info", f"  Confirmed: {result.hypotheses_confirmed}")
        await self._log("info", f"  Findings: {len(result.findings)}")
        await self._log("info", f"  Tools used: {', '.join(sorted(result.tools_used)) or 'none'}")
        await self._log("info", f"  Duration: {result.total_duration:.1f}s")
        await self._log("info", "=" * 60)

        return result

    # ------------------------------------------------------------------
    # Step 1: Hypothesis Generation
    # ------------------------------------------------------------------
    async def _generate_hypotheses(self) -> List[ResearchHypothesis]:
        """Use AI to generate research hypotheses from recon data."""
        endpoints = self.recon_data.get("endpoints", [])
        endpoint_strs = []
        for ep in endpoints[:20]:
            if isinstance(ep, dict):
                endpoint_strs.append(f"{ep.get('method', 'GET')} {ep.get('url', ep.get('path', ''))}")
            else:
                endpoint_strs.append(str(ep))

        params = self.recon_data.get("parameters", {})
        if isinstance(params, dict):
            param_str = json.dumps(dict(list(params.items())[:20]))
        elif isinstance(params, list):
            param_str = ", ".join(str(p) for p in params[:20])
        else:
            param_str = str(params)[:500]

        technologies = self.recon_data.get("technologies", [])
        headers = self.recon_data.get("response_headers", {})

        existing = []
        for f in self.existing_findings[:10]:
            if isinstance(f, dict):
                existing.append(f"{f.get('vulnerability_type', '?')}: {f.get('title', '?')}")
            else:
                existing.append(f"{getattr(f, 'vulnerability_type', '?')}: {getattr(f, 'title', '?')}")

        tested = [f"{h.id}: {h.title} ({h.status})" for h in self._hypotheses[-10:]]

        prompt = HYPOTHESIS_PROMPT.format(
            target=self.target,
            endpoint_count=len(endpoints),
            endpoints="\n".join(endpoint_strs[:15]),
            technologies=", ".join(technologies[:10]),
            parameters=param_str[:500],
            headers=json.dumps(dict(list(headers.items())[:10]) if isinstance(headers, dict) else {})[:500],
            existing_findings="\n".join(existing) if existing else "None yet",
            tested_hypotheses="\n".join(tested) if tested else "None yet",
        )

        try:
            response = await self.llm.generate(prompt, RESEARCHER_SYSTEM_PROMPT)
            self._token_usage += len(prompt.split()) + len(response.split())

            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                data = json.loads(match.group())
                hypotheses = []
                for h_data in data.get("hypotheses", []):
                    h_id = h_data.get("id", f"H{len(self._hypotheses) + len(hypotheses) + 1:03d}")

                    # Skip already tested
                    if h_id in self._tested_hypotheses:
                        continue

                    hypothesis = ResearchHypothesis(
                        id=h_id,
                        title=h_data.get("title", "Unknown hypothesis"),
                        description=h_data.get("description", ""),
                        target_endpoint=h_data.get("target_endpoint", self.target),
                        vuln_category=h_data.get("vuln_category", "unknown"),
                        confidence=min(1.0, max(0.0, float(h_data.get("confidence", 0.5)))),
                        tools_needed=h_data.get("tools_needed", []),
                        test_commands=h_data.get("test_commands", []),
                        expected_indicators=h_data.get("expected_indicators", []),
                        reasoning=h_data.get("reasoning", ""),
                    )
                    hypotheses.append(hypothesis)
                    self._hypotheses.append(hypothesis)

                return hypotheses
        except Exception as e:
            await self._log("warning", f"[RESEARCHER] Hypothesis generation failed: {e}")

        return []

    # ------------------------------------------------------------------
    # Step 2: Tool Planning
    # ------------------------------------------------------------------
    async def _plan_tools(self, hypothesis: ResearchHypothesis) -> Optional[Dict]:
        """Use AI to plan specific tool executions for a hypothesis."""
        prompt = TOOL_PLAN_PROMPT.format(
            hypothesis_title=hypothesis.title,
            hypothesis_desc=hypothesis.description,
            target_endpoint=hypothesis.target_endpoint,
            vuln_category=hypothesis.vuln_category,
        )

        try:
            response = await self.llm.generate(prompt, RESEARCHER_SYSTEM_PROMPT)
            self._token_usage += len(prompt.split()) + len(response.split())

            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception as e:
            await self._log("warning", f"[RESEARCHER] Tool planning failed for {hypothesis.id}: {e}")

        # Fallback: use hypothesis test_commands directly
        if hypothesis.test_commands:
            return {
                "tools_needed": hypothesis.tools_needed,
                "commands": [
                    {
                        "tool": hypothesis.tools_needed[0] if hypothesis.tools_needed else "curl",
                        "command": cmd,
                        "purpose": f"Test hypothesis: {hypothesis.title}",
                        "timeout": 60,
                        "success_indicators": hypothesis.expected_indicators,
                        "failure_indicators": [],
                    }
                    for cmd in hypothesis.test_commands[:5]
                ],
            }
        return None

    # ------------------------------------------------------------------
    # Step 3: Sandbox Execution
    # ------------------------------------------------------------------
    async def _execute_tool_plan(
        self, hypothesis: ResearchHypothesis, plan: Dict
    ) -> List[ToolExecution]:
        """Execute tool plan commands inside Kali sandbox."""
        results = []
        tools_needed = plan.get("tools_needed", [])

        # Install required tools first
        for tool in tools_needed:
            if tool not in self._tools_installed and self._tool_registry:
                if self._tool_registry.is_known(tool):
                    await self._log("info", f"  [SANDBOX] Ensuring tool: {tool}")
                    ok = await self._sandbox._ensure_tool(tool)
                    if ok:
                        self._tools_installed.add(tool)
                        await self._log("success", f"  [SANDBOX] Tool ready: {tool}")
                    else:
                        await self._log("warning", f"  [SANDBOX] Failed to install: {tool}")

        # Execute commands
        for cmd_spec in plan.get("commands", [])[:5]:
            if self._cancelled:
                break

            tool_name = cmd_spec.get("tool", "raw")
            command = cmd_spec.get("command", "")
            purpose = cmd_spec.get("purpose", "")
            timeout = min(cmd_spec.get("timeout", 120), 300)  # Cap at 5 min

            if not command:
                continue

            # Sanitize: replace target placeholder
            command = command.replace("{target}", self.target)

            await self._log("info", f"  [SANDBOX] Running {tool_name}: {purpose[:60]}")
            self._tools_used.add(tool_name)

            sandbox_result = await self._sandbox.execute_raw(command, timeout=timeout)

            exec_record = ToolExecution(
                tool=tool_name,
                command=command,
                purpose=purpose,
                exit_code=sandbox_result.exit_code,
                stdout=sandbox_result.stdout[:5000],  # Cap output
                stderr=sandbox_result.stderr[:2000],
                duration=sandbox_result.duration_seconds,
            )

            # Extract structured findings if available
            if sandbox_result.findings:
                exec_record.findings_extracted = sandbox_result.findings

            results.append(exec_record)
            self._tool_executions.append(exec_record)

            # Quick check for success indicators
            success_indicators = cmd_spec.get("success_indicators", [])
            for indicator in success_indicators:
                if indicator.lower() in (sandbox_result.stdout or "").lower():
                    await self._log("warning",
                        f"  [SANDBOX] Possible hit: '{indicator}' found in output"
                    )

        return results

    # ------------------------------------------------------------------
    # Step 4: Result Analysis
    # ------------------------------------------------------------------
    async def _analyze_results(
        self, hypothesis: ResearchHypothesis, tool_results: List[ToolExecution]
    ) -> Dict:
        """Use AI to analyze tool execution results and verdict the hypothesis."""
        if not tool_results:
            return {"verdict": "rejected", "evidence_summary": "No tool output to analyze"}

        # Format tool results for AI
        results_text = []
        for tr in tool_results:
            output_preview = tr.stdout[:1500] if tr.stdout else "(empty)"
            error_preview = tr.stderr[:500] if tr.stderr else ""
            results_text.append(
                f"**{tr.tool}** ({tr.purpose}):\n"
                f"  Command: {tr.command[:200]}\n"
                f"  Exit code: {tr.exit_code}\n"
                f"  Duration: {tr.duration:.1f}s\n"
                f"  Output:\n```\n{output_preview}\n```\n"
                + (f"  Errors: {error_preview}\n" if error_preview else "")
            )

        prompt = ANALYZE_RESULTS_PROMPT.format(
            hypothesis_title=hypothesis.title,
            hypothesis_desc=hypothesis.description,
            expected_indicators=", ".join(hypothesis.expected_indicators),
            tool_results="\n---\n".join(results_text),
        )

        try:
            response = await self.llm.generate(prompt, RESEARCHER_SYSTEM_PROMPT)
            self._token_usage += len(prompt.split()) + len(response.split())

            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception as e:
            await self._log("warning", f"[RESEARCHER] Analysis failed for {hypothesis.id}: {e}")

        return {"verdict": "rejected", "evidence_summary": "Analysis failed"}

    # ------------------------------------------------------------------
    # Step 5: Finding Creation
    # ------------------------------------------------------------------
    async def _create_finding(self, hypothesis: ResearchHypothesis, verdict: Dict):
        """Create a finding from a confirmed hypothesis."""
        severity = verdict.get("severity", "medium")
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        # Build PoC from tool commands
        poc_steps = verdict.get("poc_steps", [])
        tool_cmds = [te.command for te in self._tool_executions
                     if any(te.purpose and hypothesis.title[:20] in te.purpose
                            for _ in [1])]

        poc_code = ""
        if poc_steps:
            poc_code = "# PoC Steps (verified in Kali sandbox)\n"
            for i, step in enumerate(poc_steps, 1):
                poc_code += f"# Step {i}: {step}\n"
        elif tool_cmds:
            poc_code = "# Verified tool commands:\n" + "\n".join(tool_cmds[:5])

        finding = {
            "title": hypothesis.title,
            "severity": severity,
            "vulnerability_type": hypothesis.vuln_category,
            "description": hypothesis.description,
            "affected_endpoint": hypothesis.target_endpoint,
            "evidence": hypothesis.evidence or verdict.get("evidence_summary", ""),
            "impact": verdict.get("impact", ""),
            "poc_code": poc_code,
            "confidence_score": int(verdict.get("confidence", 0.7) * 100),
            "source": "researcher_agent",
            "sandbox_verified": True,
            "reasoning": hypothesis.reasoning,
            "tools_used": list(self._tools_used),
        }

        self._findings.append(finding)

        # Notify via callback
        if self.finding_callback:
            try:
                await self.finding_callback(finding)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _log(self, level: str, message: str):
        """Send log message."""
        if self.log_callback:
            try:
                await self.log_callback(level, message)
            except Exception:
                pass
        logger.log(
            {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR,
             "success": logging.INFO, "debug": logging.DEBUG}.get(level, logging.INFO),
            message,
        )

    async def _progress(self, pct: int, phase: str):
        """Send progress update."""
        if self.progress_callback:
            try:
                await self.progress_callback(min(pct, 100), f"Researcher: {phase}")
            except Exception:
                pass

    def get_status(self) -> Dict:
        """Return current research status for dashboard."""
        return {
            "hypotheses_total": len(self._hypotheses),
            "hypotheses_tested": len(self._tested_hypotheses),
            "hypotheses_confirmed": sum(1 for h in self._hypotheses if h.status == "confirmed"),
            "hypotheses_rejected": sum(1 for h in self._hypotheses if h.status == "rejected"),
            "tool_executions": len(self._tool_executions),
            "tools_used": sorted(self._tools_used),
            "tools_installed": sorted(self._tools_installed),
            "findings": len(self._findings),
            "sandbox_available": self._sandbox.is_available if self._sandbox else False,
            "token_usage": self._token_usage,
        }
