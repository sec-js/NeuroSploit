"""
CLI Agent Runner - Executes AI CLI tools (Claude Code, Gemini CLI, Codex CLI) inside
Kali Linux Docker containers for autonomous penetration testing.

Architecture:
1. Detects OAuth token from SmartRouter
2. Creates per-scan Kali container via ContainerPool
3. Installs Node.js + selected CLI tool
4. Uploads methodology file + instructions
5. Runs CLI in non-interactive mode (background process)
6. Polls output file, extracts findings in real-time
7. Findings flow through existing validation pipeline

Follows ResearcherAgent pattern (lifecycle, callbacks, sandbox integration).
"""
import os
import time
import asyncio
import logging
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Provider Definitions
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CLIProvider:
    """Definition of a CLI tool that can run inside the Kali container."""
    id: str
    name: str
    npm_package: str
    command: str
    auth_env: str                 # Env var for the OAuth/API token
    non_interactive_flags: str    # Flags for non-interactive mode
    model_flag: str               # Flag to specify model
    needs_nodejs: bool = True     # Most CLI tools are npm-based
    install_cmd: Optional[str] = None  # Override for non-npm install
    prompt_method: str = "stdin"  # "stdin", "flag", "file"
    extra_setup: Optional[str] = None  # Extra setup commands after install


CLI_PROVIDERS: Dict[str, CLIProvider] = {
    "claude_code": CLIProvider(
        id="claude_code",
        name="Claude Code",
        npm_package="@anthropic-ai/claude-code",
        command="claude",
        auth_env="ANTHROPIC_API_KEY",
        non_interactive_flags="--print --dangerously-skip-permissions --verbose",
        model_flag="--model",
        prompt_method="stdin",
    ),
    "gemini_cli": CLIProvider(
        id="gemini_cli",
        name="Gemini CLI",
        npm_package="@anthropic-ai/claude-code",  # Gemini CLI uses same approach
        command="gemini",
        auth_env="GEMINI_API_KEY",
        non_interactive_flags="--sandbox",
        model_flag="--model",
        prompt_method="stdin",
        install_cmd="npm install -g @anthropic-ai/claude-code",  # fallback to claude if gemini CLI not available
    ),
    "codex_cli": CLIProvider(
        id="codex_cli",
        name="OpenAI Codex CLI",
        npm_package="@openai/codex",
        command="codex",
        auth_env="OPENAI_API_KEY",
        non_interactive_flags="--full-auto --quiet",
        model_flag="--model",
        prompt_method="stdin",
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
# Result Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CLIAgentResult:
    """Result of a CLI agent run."""
    findings: List[Dict] = field(default_factory=list)
    raw_output: str = ""
    duration: float = 0.0
    exit_code: int = -1
    tools_used: List[str] = field(default_factory=list)
    phases_completed: List[str] = field(default_factory=list)
    total_output_lines: int = 0
    cli_provider: str = ""
    error: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Agent Runner
# ═══════════════════════════════════════════════════════════════════════════════

class CLIAgentRunner:
    """
    Runs an AI CLI tool inside a Kali Linux container for penetration testing.

    Lifecycle:
        runner = CLIAgentRunner(...)
        ok, msg = await runner.initialize()  # Container + CLI install
        result = await runner.run()          # Execute + poll findings
        await runner.shutdown()              # Cleanup
    """

    WORK_DIR = "/opt/pentest"
    OUTPUT_LOG = "/opt/pentest/output.log"
    FINDINGS_LOG = "/opt/pentest/findings.jsonl"

    def __init__(
        self,
        scan_id: str,
        target: str,
        cli_provider_id: str = "claude_code",
        methodology_path: Optional[str] = None,
        preferred_model: Optional[str] = None,
        log_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
        finding_callback: Optional[Callable] = None,
        auth_headers: Optional[Dict] = None,
        max_runtime: Optional[int] = None,
        token_budget: Optional[Any] = None,
        llm: Optional[Any] = None,
    ):
        self.scan_id = scan_id
        self.target = target
        self.cli_provider_id = cli_provider_id
        self.methodology_path = methodology_path or os.getenv(
            "METHODOLOGY_FILE", "/opt/Prompts-PenTest/pentestcompleto_en.md"
        )
        self.preferred_model = preferred_model
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.finding_callback = finding_callback
        self.auth_headers = auth_headers or {}
        self.token_budget = token_budget
        self.llm = llm

        # Runtime config
        self.max_runtime = max_runtime or int(os.getenv("CLI_AGENT_MAX_RUNTIME", "1800"))
        self.poll_interval = 3      # seconds between output checks
        self.stale_timeout = 300    # kill if no new output for 5 min
        self.ai_extract_interval = 300  # AI extraction every 5 min

        # State
        self._sandbox = None
        self._provider: Optional[CLIProvider] = None
        self._oauth_token: Optional[str] = None
        self._cli_pid: Optional[str] = None
        self._cancelled = False
        self._output_offset = 0
        self._last_output_time = 0.0
        self._start_time = 0.0
        self._all_output: List[str] = []

        # Parser
        from backend.core.cli_output_parser import CLIOutputParser
        self._parser = CLIOutputParser()

        # Recon data (set by autonomous_agent before run, for auto_pentest integration)
        self.recon_data: Optional[Dict] = None
        self.existing_findings: Optional[List] = None

    # ── Logging Helpers ────────────────────────────────────────────────────

    async def _log(self, level: str, message: str):
        if self.log_callback:
            try:
                await self.log_callback(level, f"[CLI-AGENT] {message}")
            except Exception:
                pass
        logger.log(
            getattr(logging, level.upper(), logging.INFO),
            f"[CLI-AGENT] {message}"
        )

    async def _progress(self, pct: int, phase: str):
        if self.progress_callback:
            try:
                await self.progress_callback(pct, phase)
            except Exception:
                pass

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def initialize(self) -> Tuple[bool, str]:
        """Initialize: create container, install CLI, upload files."""
        try:
            # 1. Resolve provider
            self._provider = CLI_PROVIDERS.get(self.cli_provider_id)
            if not self._provider:
                return False, f"Unknown CLI provider: {self.cli_provider_id}"

            await self._log("info", f"Provider: {self._provider.name}")

            # 2. Get OAuth token from SmartRouter
            self._oauth_token = self._get_oauth_token(self.cli_provider_id)
            if not self._oauth_token:
                # Try API key from env
                env_key = self._provider.auth_env
                self._oauth_token = os.getenv(env_key, "")
                if not self._oauth_token:
                    return False, (
                        f"No OAuth token or API key found for {self._provider.name}. "
                        f"Connect via Providers page or set {env_key} in .env"
                    )
                await self._log("info", "Using API key from environment")
            else:
                await self._log("info", "Using OAuth token from SmartRouter")

            # 3. Create Kali sandbox container
            await self._log("info", "Creating Kali sandbox container...")
            try:
                from core.container_pool import get_pool
                pool = get_pool()
                self._sandbox = await pool.get_or_create(
                    scan_id=f"cli-agent-{self.scan_id}",
                    enable_vpn=False,
                )
                await self._log("info", f"Container ready: {getattr(self._sandbox, 'container_name', 'kali')}")
            except Exception as e:
                return False, f"Failed to create Kali container: {e}"

            # 4. Install Node.js + CLI tool
            await self._log("info", "Installing Node.js...")
            await self._progress(2, "Installing Node.js")
            result = await self._sandbox.execute_raw(
                "which node > /dev/null 2>&1 && echo 'exists' || "
                "(apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs npm > /dev/null 2>&1 && echo 'installed')",
                timeout=120,
            )
            if "exists" in result.stdout:
                await self._log("info", "Node.js already available")
            elif "installed" in result.stdout:
                await self._log("info", "Node.js installed successfully")
            else:
                return False, f"Failed to install Node.js: {result.stderr[:200]}"

            await self._log("info", f"Installing {self._provider.name} CLI...")
            await self._progress(4, f"Installing {self._provider.name}")
            install_cmd = self._provider.install_cmd or f"npm install -g {self._provider.npm_package}"
            result = await self._sandbox.execute_raw(install_cmd, timeout=180)

            # Verify CLI is available
            verify = await self._sandbox.execute_raw(f"which {self._provider.command}", timeout=10)
            if verify.exit_code != 0:
                # Try npx fallback
                verify2 = await self._sandbox.execute_raw(
                    f"npx --yes {self._provider.npm_package} --version", timeout=60
                )
                if verify2.exit_code != 0:
                    return False, f"CLI tool '{self._provider.command}' not found after installation"
                await self._log("info", f"CLI available via npx")
            else:
                await self._log("info", f"CLI installed: {verify.stdout.strip()}")

            # 5. Extra setup if needed
            if self._provider.extra_setup:
                await self._sandbox.execute_raw(self._provider.extra_setup, timeout=60)

            # 6. Upload files
            await self._log("info", "Uploading methodology and instructions...")
            await self._progress(6, "Uploading files")
            await self._upload_files()

            # 7. Inject OAuth token as env var
            await self._inject_token()

            await self._log("info", "Initialization complete")
            await self._progress(8, "Ready to start")
            return True, "CLI Agent initialized successfully"

        except Exception as e:
            logger.exception("[CLI-AGENT] Initialization failed")
            return False, f"Initialization error: {e}"

    async def run(self) -> CLIAgentResult:
        """Execute the CLI agent and poll for findings."""
        if not self._sandbox or not self._provider:
            return CLIAgentResult(error="Not initialized")

        self._start_time = time.time()
        self._last_output_time = self._start_time

        try:
            # Start CLI process
            await self._log("info", f"Starting {self._provider.name} against {self.target}")
            await self._progress(10, f"{self._provider.name} starting")

            pid = await self._start_cli_process()
            if not pid:
                return CLIAgentResult(error="Failed to start CLI process")

            self._cli_pid = pid
            await self._log("info", f"CLI process started (PID: {pid})")

            # Poll output loop
            result = await self._poll_output_loop()
            return result

        except asyncio.CancelledError:
            await self._log("warning", "Run cancelled")
            await self._kill_cli_process()
            return CLIAgentResult(error="Cancelled")
        except Exception as e:
            logger.exception("[CLI-AGENT] Run failed")
            await self._log("error", f"Run error: {e}")
            return CLIAgentResult(error=str(e))

    async def shutdown(self):
        """Cleanup: kill CLI process and destroy container."""
        await self._kill_cli_process()

        if self._sandbox:
            try:
                from core.container_pool import get_pool
                await get_pool().destroy(f"cli-agent-{self.scan_id}")
                await self._log("info", "Container destroyed")
            except Exception as e:
                logger.warning(f"[CLI-AGENT] Cleanup error: {e}")
            self._sandbox = None

    def cancel(self):
        """Signal cancellation."""
        self._cancelled = True

    # ── Container Setup (Private) ──────────────────────────────────────────

    def _get_oauth_token(self, provider_id: str) -> Optional[str]:
        """Retrieve OAuth token from SmartRouter ProviderRegistry."""
        try:
            from backend.core.smart_router import get_registry
            registry = get_registry()
            if not registry:
                return None

            accounts = registry.get_active_accounts(provider_id)
            if not accounts:
                return None

            # Use first active account
            account = accounts[0]
            credential = registry.get_credential(account.id)
            if credential:
                logger.info(f"[CLI-AGENT] Got OAuth token for {provider_id} (account: {account.label})")
                return credential
            return None

        except Exception as e:
            logger.debug(f"[CLI-AGENT] SmartRouter token retrieval failed: {e}")
            return None

    async def _upload_files(self):
        """Upload methodology file, instructions, and CLAUDE.md to container."""
        from backend.core.cli_instructions_builder import (
            build_instructions, build_claude_md, load_methodology
        )

        # Create work directory
        await self._sandbox.execute_raw(f"mkdir -p {self.WORK_DIR}", timeout=5)

        # Load and upload methodology
        methodology = load_methodology(self.methodology_path)
        if methodology:
            await self._sandbox.upload_file(
                methodology.encode("utf-8"),
                f"{self.WORK_DIR}/methodology.md",
            )
            await self._log("info", f"Uploaded methodology ({len(methodology)} chars)")
        else:
            await self._log("warning", "No methodology file available")

        # Build and upload instructions
        extra_context = None
        if self.recon_data:
            # Include recon context if available (auto_pentest integration)
            endpoints = self.recon_data.get("endpoints", [])[:20]
            techs = self.recon_data.get("technologies", [])
            extra_parts = []
            if techs:
                extra_parts.append(f"Detected technologies: {', '.join(techs)}")
            if endpoints:
                ep_list = "\n".join(
                    f"- {e.get('method', 'GET')} {e.get('url', '')}" for e in endpoints[:15]
                )
                extra_parts.append(f"Discovered endpoints:\n{ep_list}")
            if self.existing_findings:
                extra_parts.append(
                    f"Already found {len(self.existing_findings)} vulnerabilities. "
                    f"Focus on areas not yet tested."
                )
            extra_context = "\n".join(extra_parts)

        instructions = build_instructions(
            target=self.target,
            auth_headers=self.auth_headers if self.auth_headers else None,
            methodology_path=f"{self.WORK_DIR}/methodology.md",
            extra_context=extra_context,
        )
        await self._sandbox.upload_file(
            instructions.encode("utf-8"),
            f"{self.WORK_DIR}/instructions.md",
        )

        # Build and upload CLAUDE.md (auto-read by Claude Code)
        claude_md = build_claude_md(
            target=self.target,
            auth_headers=self.auth_headers if self.auth_headers else None,
        )
        await self._sandbox.upload_file(
            claude_md.encode("utf-8"),
            f"{self.WORK_DIR}/CLAUDE.md",
        )

    async def _inject_token(self):
        """Inject OAuth/API token as environment variable in container."""
        if not self._oauth_token or not self._provider:
            return

        # Write to .bashrc so it's available to background processes
        env_var = self._provider.auth_env
        # Use base64 encoding to safely pass token with special chars
        import base64
        encoded = base64.b64encode(self._oauth_token.encode()).decode()
        await self._sandbox.execute_raw(
            f'echo \'export {env_var}="$(echo {encoded} | base64 -d)"\' >> /root/.bashrc',
            timeout=5,
        )
        # Also write to a env file that can be sourced
        await self._sandbox.execute_raw(
            f'echo \'export {env_var}="$(echo {encoded} | base64 -d)"\' > {self.WORK_DIR}/.env',
            timeout=5,
        )
        await self._log("info", f"Token injected as ${env_var}")

    # ── Execution (Private) ────────────────────────────────────────────────

    async def _start_cli_process(self) -> Optional[str]:
        """Start the CLI tool as a background process in the container."""
        provider = self._provider
        if not provider:
            return None

        # Build model flag
        model_part = ""
        if self.preferred_model and provider.model_flag:
            model_part = f"{provider.model_flag} {self.preferred_model}"

        # Build the prompt - read instructions file
        prompt_input = f"cat {self.WORK_DIR}/instructions.md"

        # Build CLI command based on provider
        if provider.id == "claude_code":
            cli_cmd = (
                f"cd {self.WORK_DIR} && "
                f"source {self.WORK_DIR}/.env && "
                f"{provider.command} {provider.non_interactive_flags} "
                f"{model_part} "
                f"\"$(cat {self.WORK_DIR}/instructions.md)\""
            )
        elif provider.id == "codex_cli":
            cli_cmd = (
                f"cd {self.WORK_DIR} && "
                f"source {self.WORK_DIR}/.env && "
                f"{provider.command} {provider.non_interactive_flags} "
                f"{model_part} "
                f"\"$(cat {self.WORK_DIR}/instructions.md)\""
            )
        else:
            # Generic fallback
            cli_cmd = (
                f"cd {self.WORK_DIR} && "
                f"source {self.WORK_DIR}/.env && "
                f"{provider.command} {provider.non_interactive_flags} "
                f"{model_part} "
                f"\"$(cat {self.WORK_DIR}/instructions.md)\""
            )

        # Run as background process with output capture
        full_cmd = (
            f"nohup bash -c '{cli_cmd}' "
            f"> {self.OUTPUT_LOG} 2>&1 & echo $!"
        )

        result = await self._sandbox.execute_raw(full_cmd, timeout=15)
        pid = result.stdout.strip().split('\n')[-1].strip()

        if pid and pid.isdigit():
            return pid

        await self._log("error", f"Failed to get PID. stdout: {result.stdout[:200]}, stderr: {result.stderr[:200]}")
        return None

    async def _poll_output_loop(self) -> CLIAgentResult:
        """Main polling loop: read output, parse findings, check process status."""
        last_ai_extract = time.time()
        all_findings: List[Dict] = []
        raw_output_parts: List[str] = []

        while not self._cancelled:
            elapsed = time.time() - self._start_time

            # Check max runtime
            if elapsed > self.max_runtime:
                await self._log("warning", f"Max runtime ({self.max_runtime}s) exceeded, stopping")
                await self._kill_cli_process()
                break

            # Read new output
            new_text = await self._read_new_output()
            if new_text:
                self._last_output_time = time.time()
                raw_output_parts.append(new_text)

                # Log interesting lines (not every line to avoid spam)
                for line in new_text.split('\n'):
                    line_s = line.strip()
                    if not line_s:
                        continue
                    # Always log phase markers and findings
                    if any(kw in line_s for kw in [
                        '[PHASE]', '[COMPLETE]', '[FINDING]', '[VULNERABILITY]',
                        'FINDING_START', 'FINDING_END', '[critical]', '[high]',
                        'Confirmed', 'Vulnerability found',
                    ]):
                        await self._log("info", line_s[:300])
                    elif len(self._all_output) % 20 == 0:
                        # Log every 20th line as debug
                        await self._log("debug", line_s[:200])

                # Parse findings from new output
                parsed = self._parser.parse_chunk(new_text)
                for finding in parsed:
                    finding_dict = finding.to_dict()
                    finding_dict["affected_endpoint"] = finding_dict.get("affected_endpoint") or self.target
                    all_findings.append(finding_dict)

                    # Emit finding through callback
                    if self.finding_callback:
                        try:
                            await self.finding_callback(finding_dict)
                        except Exception as e:
                            logger.debug(f"Finding callback error: {e}")

                    await self._log("success",
                        f"Finding: {finding.title} [{finding.severity.upper()}]")

            # Check stale timeout (no output for too long)
            stale_elapsed = time.time() - self._last_output_time
            if stale_elapsed > self.stale_timeout:
                await self._log("warning", f"No output for {int(stale_elapsed)}s, stopping")
                await self._kill_cli_process()
                break

            # AI extraction on accumulated unparsed text (every 5 min)
            if (time.time() - last_ai_extract > self.ai_extract_interval
                    and self.llm and self._parser.get_unparsed_text(clear=False)):
                last_ai_extract = time.time()
                await self._run_ai_extraction(all_findings)

            # Check if CLI process is still running
            if not await self._is_process_alive():
                await self._log("info", "CLI process has exited")
                # Read any remaining output
                remaining = await self._read_new_output()
                if remaining:
                    raw_output_parts.append(remaining)
                    parsed = self._parser.parse_chunk(remaining)
                    for finding in parsed:
                        finding_dict = finding.to_dict()
                        finding_dict["affected_endpoint"] = finding_dict.get("affected_endpoint") or self.target
                        all_findings.append(finding_dict)
                        if self.finding_callback:
                            try:
                                await self.finding_callback(finding_dict)
                            except Exception:
                                pass
                break

            # Update progress (time-based heuristic)
            pct = min(90, 10 + int((elapsed / self.max_runtime) * 80))
            phase = f"{self._provider.name} testing ({int(elapsed)}s)"
            if self._parser.phases:
                phase = f"{self._parser.phases[-1]} ({int(elapsed)}s)"
            await self._progress(pct, phase)

            await asyncio.sleep(self.poll_interval)

        # Final AI extraction on any remaining unparsed text
        if self.llm:
            await self._run_ai_extraction(all_findings)

        # Get exit code
        exit_code = -1
        try:
            if self._cli_pid:
                result = await self._sandbox.execute_raw(
                    f"wait {self._cli_pid} 2>/dev/null; echo $?", timeout=5
                )
                code = result.stdout.strip().split('\n')[-1].strip()
                if code.isdigit():
                    exit_code = int(code)
        except Exception:
            pass

        duration = time.time() - self._start_time
        raw_output = "\n".join(raw_output_parts)

        await self._log("info",
            f"Completed: {len(all_findings)} findings, "
            f"{self._parser.total_findings} total parsed, "
            f"{int(duration)}s elapsed")
        await self._progress(95, "CLI Agent complete")

        return CLIAgentResult(
            findings=all_findings,
            raw_output=raw_output[:500000],  # Cap raw output at 500KB
            duration=duration,
            exit_code=exit_code,
            phases_completed=self._parser.phases,
            total_output_lines=len(self._all_output),
            cli_provider=self.cli_provider_id,
        )

    async def _read_new_output(self) -> str:
        """Read new output from the CLI's log file since last check."""
        try:
            # Use dd to read from offset (more reliable than tail -c +N)
            result = await self._sandbox.execute_raw(
                f"dd if={self.OUTPUT_LOG} bs=1 skip={self._output_offset} 2>/dev/null",
                timeout=10,
            )
            if result.stdout:
                self._output_offset += len(result.stdout.encode('utf-8'))
                self._all_output.extend(result.stdout.split('\n'))
                return result.stdout
        except Exception as e:
            logger.debug(f"[CLI-AGENT] Read output error: {e}")
        return ""

    async def _is_process_alive(self) -> bool:
        """Check if the CLI process is still running."""
        if not self._cli_pid:
            return False
        try:
            result = await self._sandbox.execute_raw(
                f"kill -0 {self._cli_pid} 2>/dev/null && echo alive || echo dead",
                timeout=5,
            )
            return "alive" in result.stdout
        except Exception:
            return False

    async def _kill_cli_process(self):
        """Kill the CLI process in the container."""
        if not self._cli_pid or not self._sandbox:
            return
        try:
            await self._sandbox.execute_raw(
                f"kill {self._cli_pid} 2>/dev/null; sleep 1; kill -9 {self._cli_pid} 2>/dev/null",
                timeout=10,
            )
            await self._log("info", f"CLI process {self._cli_pid} killed")
        except Exception as e:
            logger.debug(f"[CLI-AGENT] Kill error: {e}")

    async def _run_ai_extraction(self, all_findings: List[Dict]):
        """Run AI-assisted finding extraction on unparsed text."""
        unparsed = self._parser.get_unparsed_text(clear=True)
        if not unparsed or len(unparsed) < 200:
            return

        try:
            from backend.core.cli_output_parser import ai_extract_findings
            ai_findings = await ai_extract_findings(unparsed, self.llm)
            for finding in ai_findings:
                finding_dict = finding.to_dict()
                # Check for duplicates
                h = f"{finding.title}|{finding.endpoint}|{finding.severity}"
                existing_hashes = {
                    f"{f.get('title', '')}|{f.get('affected_endpoint', '')}|{f.get('severity', '')}"
                    for f in all_findings
                }
                if h not in existing_hashes:
                    finding_dict["affected_endpoint"] = finding_dict.get("affected_endpoint") or self.target
                    all_findings.append(finding_dict)
                    if self.finding_callback:
                        try:
                            await self.finding_callback(finding_dict)
                        except Exception:
                            pass
                    await self._log("success",
                        f"AI-extracted: {finding.title} [{finding.severity.upper()}]")
        except Exception as e:
            logger.debug(f"[CLI-AGENT] AI extraction error: {e}")

    # ── Status ──────────────────────────────────────────────────────────────

    def get_status(self) -> Dict:
        """Return current runner status."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "provider": self.cli_provider_id,
            "provider_name": self._provider.name if self._provider else "",
            "target": self.target,
            "running": self._cli_pid is not None and not self._cancelled,
            "elapsed": int(elapsed),
            "findings_count": self._parser.total_findings,
            "phases": self._parser.phases,
            "output_lines": len(self._all_output),
            "is_complete": self._parser.is_complete,
        }
