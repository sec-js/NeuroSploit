"""
NeuroSploit v3 - Kali Linux Per-Scan Sandbox

Each scan gets its own Docker container based on kalilinux/kali-rolling.
Tools installed on-demand the first time they are requested.
Container destroyed when scan completes.
"""

import asyncio
import hashlib
import io
import json
import logging
import os
import re
import shlex
import tarfile
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, Set

logger = logging.getLogger(__name__)

try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

from core.sandbox_manager import (
    BaseSandbox, SandboxResult,
    parse_nuclei_jsonl, parse_naabu_output,
)
from core.tool_registry import ToolRegistry


class KaliSandbox(BaseSandbox):
    """Per-scan Docker container based on Kali Linux.
    
    Lifecycle: create -> install tools on demand -> execute -> destroy.
    Each instance owns exactly one container named 'neurosploit-{scan_id}'.
    """

    DEFAULT_TIMEOUT = 300
    MAX_OUTPUT = 2 * 1024 * 1024  # 2MB

    def __init__(
        self,
        scan_id: str,
        image: str = "neurosploit-kali:latest",
        memory_limit: str = "2g",
        cpu_limit: float = 2.0,
        network_mode: str = "bridge",
        enable_vpn: bool = False,
    ):
        self.scan_id = scan_id
        self.container_name = f"neurosploit-{scan_id}"
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network_mode = network_mode
        self.enable_vpn = enable_vpn

        self._client = None
        self._container = None
        self._available = False
        self._installed_tools: Set[str] = set()
        self._tool_registry = ToolRegistry()
        self._created_at: Optional[datetime] = None
        self._vpn_connected = False
        self._vpn_config_path: Optional[str] = None

    async def initialize(self) -> Tuple[bool, str]:
        """Create and start a new Kali container for this scan."""
        if not HAS_DOCKER:
            return False, "Docker SDK not installed"

        try:
            self._client = docker.from_env()
            self._client.ping()
        except Exception as e:
            return False, f"Docker not available: {e}"

        # Check if container already exists (resume after crash)
        try:
            existing = self._client.containers.get(self.container_name)
            if existing.status == "running":
                self._container = existing
                self._available = True
                self._created_at = datetime.utcnow()
                return True, f"Resumed existing container {self.container_name}"
            else:
                existing.remove(force=True)
        except NotFound:
            pass

        # Check image exists
        try:
            self._client.images.get(self.image)
        except NotFound:
            return False, (
                f"Kali sandbox image '{self.image}' not found. "
                "Build with: docker build -f docker/Dockerfile.kali -t neurosploit-kali:latest docker/"
            )

        # Create container
        try:
            cpu_quota = int(self.cpu_limit * 100000)
            run_kwargs: Dict[str, Any] = dict(
                image=self.image,
                command="sleep infinity",
                name=self.container_name,
                detach=True,
                network_mode=self.network_mode,
                mem_limit=self.memory_limit,
                cpu_period=100000,
                cpu_quota=cpu_quota,
                cap_add=["NET_RAW", "NET_ADMIN"],
                security_opt=["no-new-privileges:true"],
                labels={
                    "neurosploit.scan_id": self.scan_id,
                    "neurosploit.type": "kali-sandbox",
                },
            )
            if self.enable_vpn:
                run_kwargs["devices"] = ["/dev/net/tun:/dev/net/tun"]
            self._container = self._client.containers.run(**run_kwargs)
            self._available = True
            self._created_at = datetime.utcnow()
            logger.info(f"Created Kali container {self.container_name} for scan {self.scan_id}")
            return True, f"Container {self.container_name} started"
        except Exception as e:
            return False, f"Failed to create container: {e}"

    @property
    def is_available(self) -> bool:
        return self._available and self._container is not None

    @property
    def container_id(self) -> Optional[str]:
        """Short Docker container ID."""
        return self._container.short_id if self._container else None

    @property
    def image_digest(self) -> Optional[str]:
        """Docker image digest (sha256 prefix)."""
        if not self._container:
            return None
        try:
            return self._container.image.id[:19]
        except Exception:
            return None

    async def stop(self):
        """Stop and remove this scan's container."""
        if self._container:
            try:
                self._container.stop(timeout=10)
            except Exception:
                pass
            try:
                self._container.remove(force=True)
                logger.info(f"Destroyed container {self.container_name}")
            except Exception as e:
                logger.warning(f"Error removing {self.container_name}: {e}")
            self._container = None
            self._available = False

    async def health_check(self) -> Dict:
        """Run health check on this container."""
        if not self.is_available:
            return {"status": "unavailable", "scan_id": self.scan_id, "tools": []}

        result = await self._exec(
            "nuclei -version 2>&1; naabu -version 2>&1; nmap --version 2>&1 | head -1",
            timeout=15,
        )
        tools = []
        output = (result.stdout or "").lower()
        for tool in ["nuclei", "naabu", "nmap"]:
            if tool in output:
                tools.append(tool)

        uptime = 0.0
        if self._created_at:
            uptime = (datetime.utcnow() - self._created_at).total_seconds()

        return {
            "status": "healthy" if tools else "degraded",
            "scan_id": self.scan_id,
            "container": self.container_name,
            "tools": tools,
            "installed_tools": sorted(self._installed_tools),
            "uptime_seconds": uptime,
        }

    # ------------------------------------------------------------------
    # Low-level execution
    # ------------------------------------------------------------------
    async def _exec(self, command: str, timeout: int = DEFAULT_TIMEOUT) -> SandboxResult:
        """Execute command inside this container via docker exec."""
        task_id = hashlib.md5(f"{time.time()}-{command[:50]}".encode()).hexdigest()[:8]
        started_at = datetime.utcnow().isoformat()

        if not self.is_available:
            return SandboxResult(
                tool="kali", command=command, exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error="Container not available",
                task_id=task_id, started_at=started_at,
                completed_at=datetime.utcnow().isoformat(),
            )

        started = time.time()
        try:
            exec_result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._container.exec_run(
                    cmd=["bash", "-c", command],
                    stdout=True, stderr=True, demux=True,
                ),
            )

            duration = time.time() - started
            completed_at = datetime.utcnow().isoformat()
            stdout_raw, stderr_raw = exec_result.output
            stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
            stderr = (stderr_raw or b"").decode("utf-8", errors="replace")

            if len(stdout) > self.MAX_OUTPUT:
                stdout = stdout[: self.MAX_OUTPUT] + "\n... [truncated]"
            if len(stderr) > self.MAX_OUTPUT:
                stderr = stderr[: self.MAX_OUTPUT] + "\n... [truncated]"

            return SandboxResult(
                tool="kali", command=command,
                exit_code=exec_result.exit_code,
                stdout=stdout, stderr=stderr,
                duration_seconds=round(duration, 2),
                task_id=task_id, started_at=started_at,
                completed_at=completed_at,
            )
        except Exception as e:
            duration = time.time() - started
            return SandboxResult(
                tool="kali", command=command, exit_code=-1,
                stdout="", stderr="", duration_seconds=round(duration, 2),
                error=str(e),
                task_id=task_id, started_at=started_at,
                completed_at=datetime.utcnow().isoformat(),
            )

    # ------------------------------------------------------------------
    # On-demand tool installation
    # ------------------------------------------------------------------
    async def _ensure_tool(self, tool: str) -> bool:
        """Ensure a tool is installed in this container. Returns True if available."""
        if tool in self._installed_tools:
            return True

        # Check if already present in the base image
        check = await self._exec(f"which {shlex.quote(tool)} 2>/dev/null", timeout=10)
        if check.exit_code == 0 and check.stdout.strip():
            self._installed_tools.add(tool)
            return True

        # Get install recipe from registry
        recipe = self._tool_registry.get_install_command(tool)
        if not recipe:
            logger.warning(f"No install recipe for '{tool}' in Kali container")
            return False

        logger.info(f"[{self.container_name}] Installing {tool}...")
        result = await self._exec(recipe, timeout=300)
        if result.exit_code == 0:
            self._installed_tools.add(tool)
            logger.info(f"[{self.container_name}] Installed {tool} successfully")
            return True
        else:
            logger.warning(
                f"[{self.container_name}] Failed to install {tool}: "
                f"{(result.stderr or result.stdout or '')[:300]}"
            )
            return False

    # ------------------------------------------------------------------
    # High-level tool APIs (same signatures as SandboxManager)
    # ------------------------------------------------------------------
    async def run_nuclei(
        self, target, templates=None, severity=None,
        tags=None, rate_limit=150, timeout=600,
    ) -> SandboxResult:
        await self._ensure_tool("nuclei")
        cmd_parts = [
            "nuclei", "-u", shlex.quote(target),
            "-jsonl", "-rate-limit", str(rate_limit),
            "-silent", "-no-color",
        ]
        if templates:
            cmd_parts.extend(["-t", shlex.quote(templates)])
        if severity:
            cmd_parts.extend(["-severity", shlex.quote(severity)])
        if tags:
            cmd_parts.extend(["-tags", shlex.quote(tags)])

        result = await self._exec(" ".join(cmd_parts) + " 2>/dev/null", timeout=timeout)
        result.tool = "nuclei"
        if result.stdout:
            result.findings = parse_nuclei_jsonl(result.stdout)
        return result

    async def run_naabu(
        self, target, ports=None, top_ports=None,
        scan_type="s", rate=1000, timeout=300,
    ) -> SandboxResult:
        await self._ensure_tool("naabu")
        cmd_parts = [
            "naabu", "-host", shlex.quote(target),
            "-json", "-rate", str(rate), "-silent", "-no-color",
        ]
        if ports:
            cmd_parts.extend(["-p", shlex.quote(str(ports))])
        elif top_ports:
            cmd_parts.extend(["-top-ports", str(top_ports)])
        else:
            cmd_parts.extend(["-top-ports", "1000"])
        if scan_type:
            cmd_parts.extend(["-scan-type", scan_type])

        result = await self._exec(" ".join(cmd_parts) + " 2>/dev/null", timeout=timeout)
        result.tool = "naabu"
        if result.stdout:
            result.findings = parse_naabu_output(result.stdout)
        return result

    async def run_httpx(self, targets, timeout=120) -> SandboxResult:
        await self._ensure_tool("httpx")
        if isinstance(targets, str):
            targets = [targets]
        target_str = "\\n".join(shlex.quote(t) for t in targets)
        command = (
            f'echo -e "{target_str}" | httpx -silent -json '
            f'-title -tech-detect -status-code -content-length '
            f'-follow-redirects -no-color 2>/dev/null'
        )
        result = await self._exec(command, timeout=timeout)
        result.tool = "httpx"
        if result.stdout:
            findings = []
            for line in result.stdout.strip().split("\\n"):
                try:
                    data = json.loads(line)
                    findings.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "technologies": data.get("tech", []),
                        "content_length": data.get("content_length", 0),
                        "webserver": data.get("webserver", ""),
                    })
                except (json.JSONDecodeError, ValueError):
                    continue
            result.findings = findings
        return result

    async def run_subfinder(self, domain, timeout=120) -> SandboxResult:
        await self._ensure_tool("subfinder")
        command = f"subfinder -d {shlex.quote(domain)} -silent -no-color 2>/dev/null"
        result = await self._exec(command, timeout=timeout)
        result.tool = "subfinder"
        if result.stdout:
            subs = [s.strip() for s in result.stdout.strip().split("\\n") if s.strip()]
            result.findings = [{"subdomain": s} for s in subs]
        return result

    async def run_nmap(self, target, ports=None, scripts=True, timeout=300) -> SandboxResult:
        await self._ensure_tool("nmap")
        cmd_parts = ["nmap", "-sV"]
        if scripts:
            cmd_parts.append("-sC")
        if ports:
            cmd_parts.extend(["-p", shlex.quote(str(ports))])
        cmd_parts.extend(["-oN", "/dev/stdout", shlex.quote(target)])
        result = await self._exec(" ".join(cmd_parts) + " 2>/dev/null", timeout=timeout)
        result.tool = "nmap"
        return result

    async def run_tool(self, tool, args, timeout=300) -> SandboxResult:
        """Run any tool (validates whitelist, installs on demand)."""
        # Load whitelist from config
        allowed_tools = set()
        try:
            with open("config/config.json") as f:
                cfg = json.load(f)
            allowed_tools = set(cfg.get("sandbox", {}).get("tools", []))
        except Exception:
            pass

        if not allowed_tools:
            allowed_tools = {
                "nuclei", "naabu", "nmap", "httpx", "subfinder", "katana",
                "dnsx", "ffuf", "gobuster", "dalfox", "nikto", "sqlmap",
                "whatweb", "curl", "dig", "whois", "masscan", "dirsearch",
                "wfuzz", "arjun", "wafw00f", "waybackurls",
            }

        if tool not in allowed_tools:
            return SandboxResult(
                tool=tool, command=f"{tool} {args}", exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error=f"Tool '{tool}' not in allowed list",
            )

        if not await self._ensure_tool(tool):
            return SandboxResult(
                tool=tool, command=f"{tool} {args}", exit_code=-1,
                stdout="", stderr="", duration_seconds=0,
                error=f"Could not install '{tool}' in Kali container",
            )

        result = await self._exec(f"{shlex.quote(tool)} {args} 2>&1", timeout=timeout)
        result.tool = tool
        return result

    async def execute_raw(self, command, timeout=300) -> SandboxResult:
        result = await self._exec(command, timeout=timeout)
        result.tool = "raw"
        return result

    # ------------------------------------------------------------------
    # File upload
    # ------------------------------------------------------------------
    async def upload_file(self, file_bytes: bytes, dest_path: str) -> bool:
        """Upload a file into the container via docker put_archive."""
        if not self.is_available:
            return False

        tar_stream = io.BytesIO()
        fname = os.path.basename(dest_path)
        tarinfo = tarfile.TarInfo(name=fname)
        tarinfo.size = len(file_bytes)
        tarinfo.mode = 0o600

        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.addfile(tarinfo, io.BytesIO(file_bytes))

        tar_stream.seek(0)
        dest_dir = os.path.dirname(dest_path) or "/"

        try:
            await self._exec(f"mkdir -p {shlex.quote(dest_dir)}", timeout=10)
            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,
                lambda: self._container.put_archive(dest_dir, tar_stream),
            )
            return bool(success)
        except Exception as e:
            logger.warning(f"Failed to upload file to {dest_path}: {e}")
            return False

    # ------------------------------------------------------------------
    # VPN lifecycle
    # ------------------------------------------------------------------
    async def connect_vpn(
        self,
        config_bytes: bytes,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Upload .ovpn config and start OpenVPN inside the container."""
        if not self.is_available:
            return False, "Container not available"

        ovpn_path = "/etc/openvpn/client.ovpn"
        if not await self.upload_file(config_bytes, ovpn_path):
            return False, "Failed to upload .ovpn config"

        self._vpn_config_path = ovpn_path

        # Write auth file if credentials provided
        if username and password:
            auth_content = f"{username}\n{password}\n".encode()
            auth_path = "/etc/openvpn/auth.txt"
            if not await self.upload_file(auth_content, auth_path):
                return False, "Failed to upload credentials"
            await self._exec(f"chmod 600 {auth_path}", timeout=5)
            # Append auth-user-pass directive if not present
            await self._exec(
                f"grep -q 'auth-user-pass' {ovpn_path} || "
                f"echo 'auth-user-pass {auth_path}' >> {ovpn_path}",
                timeout=5,
            )
            # Replace bare auth-user-pass with path version
            await self._exec(
                f"sed -i 's|auth-user-pass$|auth-user-pass {auth_path}|' {ovpn_path}",
                timeout=5,
            )

        # Create TUN device if missing
        await self._exec(
            "mkdir -p /dev/net && "
            "[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200; "
            "chmod 600 /dev/net/tun",
            timeout=5,
        )

        # Kill any existing OpenVPN
        await self._exec("pkill -9 openvpn 2>/dev/null", timeout=5)

        # Start OpenVPN
        result = await self._exec(
            f"openvpn --config {ovpn_path} --daemon "
            f"--log /var/log/openvpn.log "
            f"--writepid /var/run/openvpn.pid",
            timeout=15,
        )
        if result.exit_code != 0:
            return False, f"OpenVPN start failed: {result.stderr or result.stdout}"

        # Wait up to 20s for tun interface
        for _ in range(20):
            await asyncio.sleep(1)
            check = await self._exec("ip addr show tun0 2>/dev/null", timeout=5)
            if check.exit_code == 0 and "inet " in check.stdout:
                self._vpn_connected = True
                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", check.stdout)
                ip = match.group(1) if match else "unknown"
                return True, f"VPN connected. Tunnel IP: {ip}"

        # Timeout - check log
        log_result = await self._exec("tail -30 /var/log/openvpn.log 2>/dev/null", timeout=5)
        return False, f"VPN timed out. Log: {(log_result.stdout or '')[-500:]}"

    async def disconnect_vpn(self) -> Tuple[bool, str]:
        """Kill OpenVPN process inside the container."""
        if not self.is_available:
            return False, "Container not available"

        await self._exec(
            "kill $(cat /var/run/openvpn.pid 2>/dev/null) 2>/dev/null; "
            "pkill -9 openvpn 2>/dev/null",
            timeout=10,
        )
        self._vpn_connected = False
        return True, "VPN disconnected"

    async def get_vpn_status(self) -> Dict:
        """Check VPN status inside the container."""
        if not self.is_available:
            return {"connected": False, "ip": None, "interface": None}

        connected = False
        ip_addr = None

        proc_check = await self._exec("pgrep -a openvpn", timeout=5)
        if proc_check.exit_code == 0 and proc_check.stdout.strip():
            connected = True

        if connected:
            tun_check = await self._exec("ip addr show tun0 2>/dev/null", timeout=5)
            if tun_check.exit_code == 0:
                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", tun_check.stdout)
                if match:
                    ip_addr = match.group(1)
            else:
                connected = False  # Process alive but no interface yet

        self._vpn_connected = connected
        return {"connected": connected, "ip": ip_addr, "interface": "tun0" if connected else None}
