"""
NeuroSploit v3 - FULL AI Testing API

Serves the comprehensive pentest prompt and manages FULL AI testing sessions.
"""
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter()

# Default prompt file path - English translation preferred, fallback to original
PROMPT_PATH_EN = Path("/opt/Prompts-PenTest/pentestcompleto_en.md")
PROMPT_PATH_PT = Path("/opt/Prompts-PenTest/pentestcompleto.md")
PROMPT_PATH = PROMPT_PATH_EN if PROMPT_PATH_EN.exists() else PROMPT_PATH_PT


@router.get("/prompt")
async def get_full_ia_prompt():
    """Return the comprehensive pentest prompt content."""
    if not PROMPT_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Pentest prompt file not found at {PROMPT_PATH}"
        )
    try:
        content = PROMPT_PATH.read_text(encoding="utf-8")
        return {
            "content": content,
            "path": str(PROMPT_PATH),
            "size": len(content),
            "lines": content.count("\n") + 1,
        }
    except Exception as e:
        logger.error(f"Failed to read prompt file: {e}")
        raise HTTPException(status_code=500, detail=str(e))
