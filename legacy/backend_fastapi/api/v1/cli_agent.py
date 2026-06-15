"""
CLI Agent API - Endpoints for CLI agent provider detection and methodology listing.
"""
import os
import glob
import logging
from typing import List, Dict, Optional
from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cli-agent", tags=["CLI Agent"])

# CLI providers that can run as autonomous agents
CLI_AGENT_PROVIDER_IDS = ["claude_code", "gemini_cli", "codex_cli"]


@router.get("/providers")
async def get_cli_providers() -> Dict:
    """List available CLI agent providers with connection status from SmartRouter."""
    providers = []

    try:
        from backend.core.smart_router import get_registry
        registry = get_registry()
    except Exception:
        registry = None

    for pid in CLI_AGENT_PROVIDER_IDS:
        provider_info = {
            "id": pid,
            "name": pid,
            "connected": False,
            "account_label": None,
            "source": None,
        }

        if registry:
            provider = registry.get_provider(pid)
            if provider:
                provider_info["name"] = provider.name
                accounts = registry.get_active_accounts(pid)
                if accounts:
                    provider_info["connected"] = True
                    provider_info["account_label"] = accounts[0].label
                    provider_info["source"] = accounts[0].source

        providers.append(provider_info)

    # Also check env var API keys as fallback
    env_fallbacks = {
        "claude_code": "ANTHROPIC_API_KEY",
        "gemini_cli": "GEMINI_API_KEY",
        "codex_cli": "OPENAI_API_KEY",
    }
    for p in providers:
        if not p["connected"]:
            env_key = env_fallbacks.get(p["id"], "")
            if env_key and os.getenv(env_key, ""):
                p["connected"] = True
                p["source"] = "env_var"
                p["account_label"] = f"${env_key}"

    enabled = os.getenv("ENABLE_CLI_AGENT", "false").lower() == "true"

    return {
        "enabled": enabled,
        "providers": providers,
        "connected_count": sum(1 for p in providers if p["connected"]),
    }


@router.get("/methodologies")
async def list_methodologies() -> Dict:
    """List available methodology .md files for CLI agent."""
    methodologies: List[Dict] = []
    seen_paths: set = set()

    # 1. Check METHODOLOGY_FILE env var (default)
    default_path = os.getenv("METHODOLOGY_FILE", "")
    if default_path and os.path.exists(default_path):
        size = os.path.getsize(default_path)
        methodologies.append({
            "name": os.path.basename(default_path),
            "path": default_path,
            "size": size,
            "size_human": _human_size(size),
            "is_default": True,
        })
        seen_paths.add(os.path.abspath(default_path))

    # 2. Scan /opt/Prompts-PenTest/ for .md files
    prompts_dir = "/opt/Prompts-PenTest"
    if os.path.isdir(prompts_dir):
        for md_file in sorted(glob.glob(os.path.join(prompts_dir, "*.md"))):
            abs_path = os.path.abspath(md_file)
            if abs_path in seen_paths:
                continue
            seen_paths.add(abs_path)

            name = os.path.basename(md_file)
            size = os.path.getsize(md_file)

            # Only include pentest-related files (skip research reports, etc.)
            name_lower = name.lower()
            if any(kw in name_lower for kw in ["pentest", "prompt", "bugbounty", "methodology", "chunk"]):
                methodologies.append({
                    "name": name,
                    "path": md_file,
                    "size": size,
                    "size_human": _human_size(size),
                    "is_default": False,
                })

    # 3. Check data/ directory
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
    if os.path.isdir(data_dir):
        for md_file in glob.glob(os.path.join(data_dir, "*methodology*.md")):
            abs_path = os.path.abspath(md_file)
            if abs_path not in seen_paths:
                seen_paths.add(abs_path)
                size = os.path.getsize(md_file)
                methodologies.append({
                    "name": os.path.basename(md_file),
                    "path": md_file,
                    "size": size,
                    "size_human": _human_size(size),
                    "is_default": False,
                })

    return {
        "methodologies": methodologies,
        "total": len(methodologies),
    }


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
