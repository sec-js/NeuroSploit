"""
NeuroSploit v3 - Scan Checkpoint Manager

Save and restore agent state to JSON for crash-resilient session persistence.
Checkpoints are stored in data/checkpoints/{scan_id}.json.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CHECKPOINT_DIR = Path(__file__).parent.parent.parent / "data" / "checkpoints"


class CheckpointManager:
    """Manages save/restore of agent scan state to disk."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._filepath = CHECKPOINT_DIR / f"{scan_id}.json"
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    def save(self, state: Dict[str, Any]) -> bool:
        """Atomically save checkpoint state to disk.

        State typically includes:
        - target, mode, scan_type
        - progress, phase
        - recon_data (endpoints, tech_stack)
        - findings (serialized)
        - test_targets (serialized)
        - junior_tested_types
        - completed_vuln_types
        - timestamp
        """
        try:
            state["_checkpoint_version"] = 1
            state["_scan_id"] = self.scan_id
            state["_timestamp"] = time.time()

            tmp_path = self._filepath.with_suffix(".tmp")
            with open(tmp_path, "w") as f:
                json.dump(state, f, indent=2, default=str)
            tmp_path.rename(self._filepath)
            logger.debug(f"Checkpoint saved for scan {self.scan_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to save checkpoint for {self.scan_id}: {e}")
            return False

    def load(self) -> Optional[Dict[str, Any]]:
        """Load checkpoint from disk, returns None if not found or corrupt."""
        if not self._filepath.exists():
            return None
        try:
            with open(self._filepath) as f:
                data = json.load(f)
            if data.get("_scan_id") != self.scan_id:
                logger.warning(f"Checkpoint scan_id mismatch: {data.get('_scan_id')} != {self.scan_id}")
                return None
            logger.info(f"Checkpoint loaded for scan {self.scan_id} (saved at {data.get('_timestamp', '?')})")
            return data
        except Exception as e:
            logger.warning(f"Failed to load checkpoint for {self.scan_id}: {e}")
            return None

    def delete(self):
        """Remove checkpoint file after successful completion."""
        try:
            if self._filepath.exists():
                self._filepath.unlink()
                logger.debug(f"Checkpoint deleted for scan {self.scan_id}")
        except Exception as e:
            logger.warning(f"Failed to delete checkpoint for {self.scan_id}: {e}")

    @property
    def exists(self) -> bool:
        """Check if a checkpoint exists for this scan."""
        return self._filepath.exists()

    @staticmethod
    def list_checkpoints() -> List[Dict[str, Any]]:
        """List all available checkpoints for the resume UI."""
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        checkpoints = []
        for f in CHECKPOINT_DIR.glob("*.json"):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                checkpoints.append({
                    "scan_id": data.get("_scan_id", f.stem),
                    "target": data.get("target", "unknown"),
                    "progress": data.get("progress", 0),
                    "phase": data.get("phase", "unknown"),
                    "timestamp": data.get("_timestamp", 0),
                    "findings_count": len(data.get("findings", [])),
                })
            except Exception:
                continue
        # Sort by most recent first
        checkpoints.sort(key=lambda c: c["timestamp"], reverse=True)
        return checkpoints

    @staticmethod
    def cleanup_old(max_age_hours: int = 72):
        """Remove checkpoints older than max_age_hours."""
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        cutoff = time.time() - (max_age_hours * 3600)
        removed = 0
        for f in CHECKPOINT_DIR.glob("*.json"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    removed += 1
            except Exception:
                continue
        if removed:
            logger.info(f"Cleaned up {removed} old checkpoints")
