#!/usr/bin/env python3
"""
Quick test: Run the autonomous agent against testphp.vulnweb.com
in AUTO_PENTEST mode with all new Phase 1-5 modules active.
"""

import asyncio
import sys
import os
import time
import json
from datetime import datetime

# Load env
from dotenv import load_dotenv
load_dotenv()

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from backend.core.autonomous_agent import AutonomousAgent, OperationMode


async def log_callback(level: str, message: str):
    """Print agent logs with timestamp."""
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {
        "info": "\033[36m[INFO]\033[0m",
        "warning": "\033[33m[WARN]\033[0m",
        "error": "\033[31m[ERR]\033[0m",
        "success": "\033[32m[OK]\033[0m",
        "debug": "\033[90m[DBG]\033[0m",
    }.get(level, f"[{level.upper()}]")
    print(f"  {ts} {prefix} {message}")


async def progress_callback(progress: int, phase: str):
    """Print progress updates."""
    bar_len = 30
    filled = int(bar_len * progress / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\r  [{bar}] {progress}% - {phase}", end="", flush=True)
    if progress >= 100:
        print()


async def finding_callback(finding: dict):
    """Print finding in real-time."""
    sev = finding.get("severity", "?")
    title = finding.get("title", "?")
    confidence = finding.get("confidence_score", 0)
    print(f"\n  \033[31m🔥 FINDING [{sev.upper()}] {title} (confidence: {confidence}%)\033[0m\n")


async def main():
    target = "http://testphp.vulnweb.com"
    print("=" * 70)
    print(f"  NeuroSploit v3 — Agent Test Run")
    print(f"  Target: {target}")
    print(f"  Mode: AUTO_PENTEST")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

    start = time.time()

    agent = AutonomousAgent(
        target=target,
        mode=OperationMode.AUTO_PENTEST,
        log_callback=log_callback,
        progress_callback=progress_callback,
        finding_callback=finding_callback,
        scan_id="test-run-001",
    )

    async with agent:
        report = await agent.run()

    elapsed = time.time() - start

    print()
    print("=" * 70)
    print(f"  RESULTS")
    print("=" * 70)

    findings = report.get("findings", [])
    if isinstance(findings, list):
        print(f"  Total findings: {len(findings)}")
        for i, f in enumerate(findings):
            if isinstance(f, dict):
                sev = f.get("severity", "?")
                title = f.get("title", "?")
                conf = f.get("confidence_score", 0)
                vtype = f.get("vulnerability_type", "?")
                ep = f.get("affected_endpoint", "?")
                print(f"  {i+1}. [{sev.upper():8s}] {title}")
                print(f"     Type: {vtype} | Endpoint: {ep[:60]} | Confidence: {conf}%")
    else:
        print(f"  Findings: {findings}")

    # Summary stats
    summary = report.get("summary", report.get("executive_summary", ""))
    if summary:
        print(f"\n  Summary: {str(summary)[:200]}")

    print(f"\n  Duration: {elapsed:.1f}s")
    print(f"  Token budget: {'active' if agent.token_budget else 'unlimited'}")
    print(f"  Reasoning engine: {'active' if agent.reasoning_engine else 'disabled'}")
    print(f"  Endpoint classifier: {'active' if agent.endpoint_classifier else 'disabled'}")
    print(f"  Param analyzer: {'active' if agent.param_analyzer else 'disabled'}")
    print(f"  Payload mutator: {'active' if agent.payload_mutator else 'disabled'}")
    print(f"  Deep recon: {'active' if agent.deep_recon else 'disabled'}")
    print(f"  CVE hunter: {'active' if agent.cve_hunter else 'disabled'}")
    print(f"  Banner analyzer: {'active' if agent.banner_analyzer else 'disabled'}")
    print(f"  Exploit generator: {'active' if agent.exploit_generator else 'disabled'}")
    print(f"  XSS validator: {'active' if agent.xss_validator else 'disabled'}")
    print(f"  Multi-agent: {'active' if agent._orchestrator else 'disabled'}")
    print("=" * 70)

    # Save report to file
    report_path = f"reports/test_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs("reports", exist_ok=True)
    try:
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"  Report saved: {report_path}")
    except Exception as e:
        print(f"  Report save error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
