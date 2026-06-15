"""
NeuroSploit v3 - Smart Router Package

Gated by ENABLE_SMART_ROUTER=true env var.
Provides SmartRouter singleton for LLM request routing.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

HAS_SMART_ROUTER = False
_router_instance = None
_registry_instance = None
_refresher_instance = None

if os.getenv("ENABLE_SMART_ROUTER", "false").lower() == "true":
    try:
        from .provider_registry import ProviderRegistry, Provider, Account
        from .token_extractor import TokenExtractor
        from .router import SmartRouter
        from .token_refresher import TokenRefresher
        HAS_SMART_ROUTER = True
        logger.info("SmartRouter: Module loaded successfully")
    except ImportError as e:
        logger.warning(f"SmartRouter: Failed to load: {e}")


async def init_router():
    """Initialize the SmartRouter singleton. Called from main.py startup."""
    global _router_instance, _registry_instance, _refresher_instance

    if not HAS_SMART_ROUTER:
        return

    try:
        _registry_instance = ProviderRegistry()

        # Auto-detect CLI tokens that were never detected before
        extractor = TokenExtractor()
        auto_detected = 0
        for token in extractor.detect_all():
            # Only add if provider has no accounts yet
            provider = _registry_instance.get_provider(token.provider_id)
            if provider and not provider.accounts:
                _registry_instance.add_account(
                    provider_id=token.provider_id,
                    label=token.label,
                    credential=token.token,
                    credential_type=token.credential_type,
                    source="cli_detect",
                    refresh_token=token.refresh_token,
                    expires_at=token.expires_at,
                )
                auto_detected += 1
        if auto_detected:
            logger.info(f"SmartRouter: Auto-detected {auto_detected} new CLI provider(s)")
            print(f"[SmartRouter] Auto-detected {auto_detected} new CLI provider(s)")

        _router_instance = SmartRouter(_registry_instance)

        # Discover Gemini CLI project ID (needed for Cloud Code Assist API)
        try:
            project = await _router_instance.discover_gemini_project()
            if project:
                print(f"[SmartRouter] Gemini CLI project: {project}")
        except Exception as e:
            logger.debug(f"SmartRouter: Gemini project discovery skipped: {e}")

        _refresher_instance = TokenRefresher(_registry_instance)
        await _refresher_instance.start()

        # Log connected providers with details
        status = _registry_instance.get_all_status()
        connected = [s for s in status if s["connected"]]
        connected_names = [f"{s['name']}({s['default_model']})" for s in connected]
        logger.info(f"SmartRouter: Initialized ({len(connected)}/{len(status)} connected)")
        print(f"[SmartRouter] {len(connected)}/{len(status)} providers connected: {', '.join(connected_names) or 'none'}")
    except Exception as e:
        logger.error(f"SmartRouter: Init failed: {e}")
        print(f"[SmartRouter] Init failed: {e}")
        _router_instance = None


async def shutdown_router():
    """Shutdown the SmartRouter. Called from main.py shutdown."""
    global _refresher_instance
    if _refresher_instance:
        await _refresher_instance.stop()
        _refresher_instance = None


def get_router() -> Optional["SmartRouter"]:
    """Get the SmartRouter singleton (or None if disabled)."""
    return _router_instance


def get_registry() -> Optional["ProviderRegistry"]:
    """Get the ProviderRegistry singleton (or None if disabled)."""
    return _registry_instance


def get_extractor() -> Optional["TokenExtractor"]:
    """Get a new TokenExtractor instance (or None if disabled)."""
    if not HAS_SMART_ROUTER:
        return None
    return TokenExtractor()
