"""
NeuroSploit v3 - Multi-Channel Notification Manager

Sends scan event alerts to Discord, Telegram, and WhatsApp (Twilio).
Hooks into the existing WebSocket broadcast infrastructure as event source.
All channels are disabled by default (opt-in via .env).
Uses only aiohttp (already a dependency) for HTTP calls.
"""

import asyncio
import base64
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import aiohttp

logger = logging.getLogger(__name__)


class NotificationEvent(Enum):
    SCAN_STARTED = "scan_started"
    VULN_FOUND = "vuln_found"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"


# Severity → Discord embed color
SEVERITY_COLORS = {
    "critical": 0xFF0000,
    "high": 0xFF6600,
    "medium": 0xFFCC00,
    "low": 0x33CC33,
    "info": 0x3399FF,
}


class NotificationManager:
    """Async multi-channel notification dispatcher.

    Sends fire-and-forget notifications to configured channels.
    Never blocks the scan flow — all errors are swallowed and logged.
    """

    def __init__(self):
        self.reload_config()

    def reload_config(self):
        """(Re)load configuration from environment variables."""
        self.enabled = os.getenv("ENABLE_NOTIFICATIONS", "false").lower() == "true"

        # Discord
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()

        # Telegram
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

        # WhatsApp (Twilio)
        self.twilio_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
        self.twilio_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
        self.twilio_from = os.getenv("TWILIO_FROM_NUMBER", "").strip()
        self.twilio_to = os.getenv("TWILIO_TO_NUMBER", "").strip()

        # Severity filter
        raw = os.getenv("NOTIFICATION_SEVERITY_FILTER", "critical,high").strip()
        self.severity_filter = set(s.strip() for s in raw.split(",") if s.strip())

    @property
    def has_discord(self) -> bool:
        return bool(self.discord_webhook)

    @property
    def has_telegram(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)

    @property
    def has_whatsapp(self) -> bool:
        return bool(self.twilio_sid and self.twilio_token and self.twilio_from and self.twilio_to)

    async def notify(self, event: NotificationEvent, data: Dict[str, Any]):
        """Send notification to all configured channels.

        For VULN_FOUND events, respects the severity filter.
        """
        if not self.enabled:
            return

        # Severity filter for vulnerability findings
        if event == NotificationEvent.VULN_FOUND:
            severity = data.get("severity", "").lower()
            if severity not in self.severity_filter:
                return

        tasks = []
        if self.has_discord:
            tasks.append(self._send_discord(event, data))
        if self.has_telegram:
            tasks.append(self._send_telegram(event, data))
        if self.has_whatsapp:
            tasks.append(self._send_whatsapp(event, data))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Discord ──────────────────────────────────────────────────────

    async def _send_discord(self, event: NotificationEvent, data: Dict):
        """Send Discord webhook with rich embed."""
        try:
            embed = self._build_discord_embed(event, data)
            payload = {"embeds": [embed]}

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.discord_webhook,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status not in (200, 204):
                        body = await resp.text()
                        logger.warning(f"Discord notification failed ({resp.status}): {body[:200]}")
        except Exception as e:
            logger.warning(f"Discord notification error: {e}")

    def _build_discord_embed(self, event: NotificationEvent, data: Dict) -> Dict:
        """Build Discord embed object."""
        ts = datetime.utcnow().isoformat()

        if event == NotificationEvent.SCAN_STARTED:
            return {
                "title": "Scan Started",
                "description": f"Target: `{data.get('target', 'unknown')}`",
                "color": 0x3399FF,
                "timestamp": ts,
                "footer": {"text": "NeuroSploit v3"},
            }

        elif event == NotificationEvent.VULN_FOUND:
            severity = data.get("severity", "medium").lower()
            return {
                "title": f"{severity.upper()}: {data.get('title', 'Vulnerability Found')}",
                "description": data.get("description", "")[:500] or f"Endpoint: `{data.get('endpoint', '')}`",
                "color": SEVERITY_COLORS.get(severity, 0xFFCC00),
                "fields": [
                    {"name": "Severity", "value": severity.upper(), "inline": True},
                    {"name": "Type", "value": data.get("vulnerability_type", "unknown"), "inline": True},
                    {"name": "Endpoint", "value": f"`{data.get('endpoint', 'N/A')}`", "inline": False},
                ],
                "timestamp": ts,
                "footer": {"text": "NeuroSploit v3"},
            }

        elif event == NotificationEvent.SCAN_COMPLETED:
            total = data.get("total_vulnerabilities", 0)
            crit = data.get("critical", 0)
            high = data.get("high", 0)
            med = data.get("medium", 0)
            return {
                "title": "Scan Completed",
                "description": (
                    f"**{total}** vulnerabilities found\n"
                    f"Critical: **{crit}** | High: **{high}** | Medium: **{med}**"
                ),
                "color": 0x00CC00 if total == 0 else 0xFF6600,
                "timestamp": ts,
                "footer": {"text": "NeuroSploit v3"},
            }

        elif event == NotificationEvent.SCAN_FAILED:
            return {
                "title": "Scan Failed",
                "description": f"Error: {data.get('error', 'Unknown error')[:500]}",
                "color": 0xFF0000,
                "timestamp": ts,
                "footer": {"text": "NeuroSploit v3"},
            }

        return {"title": event.value, "color": 0x999999, "timestamp": ts}

    # ── Telegram ─────────────────────────────────────────────────────

    async def _send_telegram(self, event: NotificationEvent, data: Dict):
        """Send Telegram message via Bot API."""
        try:
            text = self._build_telegram_text(event, data)
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": text,
                "parse_mode": "Markdown",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.warning(f"Telegram notification failed ({resp.status}): {body[:200]}")
        except Exception as e:
            logger.warning(f"Telegram notification error: {e}")

    def _build_telegram_text(self, event: NotificationEvent, data: Dict) -> str:
        """Build Telegram message text."""
        if event == NotificationEvent.SCAN_STARTED:
            return f"*Scan Started*\nTarget: `{data.get('target', 'unknown')}`"

        elif event == NotificationEvent.VULN_FOUND:
            sev = data.get("severity", "medium").upper()
            return (
                f"*{sev}: {data.get('title', 'Vulnerability Found')}*\n"
                f"Type: {data.get('vulnerability_type', 'unknown')}\n"
                f"Endpoint: `{data.get('endpoint', 'N/A')}`"
            )

        elif event == NotificationEvent.SCAN_COMPLETED:
            total = data.get("total_vulnerabilities", 0)
            crit = data.get("critical", 0)
            high = data.get("high", 0)
            return (
                f"*Scan Completed*\n"
                f"Vulnerabilities: *{total}*\n"
                f"Critical: {crit} | High: {high}"
            )

        elif event == NotificationEvent.SCAN_FAILED:
            return f"*Scan Failed*\nError: {data.get('error', 'Unknown')[:300]}"

        return f"*{event.value}*"

    # ── WhatsApp (Twilio) ────────────────────────────────────────────

    async def _send_whatsapp(self, event: NotificationEvent, data: Dict):
        """Send WhatsApp message via Twilio API."""
        try:
            text = self._build_telegram_text(event, data)  # Reuse text format
            # Strip markdown for WhatsApp
            text = text.replace("*", "").replace("`", "")

            url = f"https://api.twilio.com/2010-04-01/Accounts/{self.twilio_sid}/Messages.json"
            auth_str = base64.b64encode(
                f"{self.twilio_sid}:{self.twilio_token}".encode()
            ).decode()

            form_data = {
                "From": f"whatsapp:{self.twilio_from}",
                "To": f"whatsapp:{self.twilio_to}",
                "Body": text,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    data=form_data,
                    headers={"Authorization": f"Basic {auth_str}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status not in (200, 201):
                        body = await resp.text()
                        logger.warning(f"WhatsApp notification failed ({resp.status}): {body[:200]}")
        except Exception as e:
            logger.warning(f"WhatsApp notification error: {e}")

    # ── Test ─────────────────────────────────────────────────────────

    async def test_channel(self, channel: str) -> Dict:
        """Send a test notification to a specific channel."""
        test_data = {
            "target": "https://example.com",
            "title": "Test Notification",
            "severity": "info",
            "vulnerability_type": "test",
            "endpoint": "/test",
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "error": "This is a test",
        }
        event = NotificationEvent.SCAN_STARTED

        try:
            if channel == "discord":
                if not self.has_discord:
                    return {"success": False, "error": "Discord webhook URL not configured"}
                await self._send_discord(event, test_data)
            elif channel == "telegram":
                if not self.has_telegram:
                    return {"success": False, "error": "Telegram bot token or chat ID not configured"}
                await self._send_telegram(event, test_data)
            elif channel == "whatsapp":
                if not self.has_whatsapp:
                    return {"success": False, "error": "Twilio credentials not configured"}
                await self._send_whatsapp(event, test_data)
            else:
                return {"success": False, "error": f"Unknown channel: {channel}"}
            return {"success": True, "message": f"Test notification sent to {channel}"}
        except Exception as e:
            return {"success": False, "error": str(e)}


# Global singleton
notification_manager = NotificationManager()
