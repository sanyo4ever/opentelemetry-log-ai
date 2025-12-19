import os
import json
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class CheckpointManager:
    """
    Manages checkpoint persistence to ensure logs aren't missed during restarts.
    Stores the last processed timestamp to disk.
    """
    def __init__(self, checkpoint_file: str = 'data/checkpoint.json'):
        self.checkpoint_file = checkpoint_file
        self._ensure_directory()

    def _ensure_directory(self):
        """Create checkpoint directory if it doesn't exist."""
        directory = os.path.dirname(self.checkpoint_file)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            logger.info(f"Created checkpoint directory: {directory}")

    def save(self, timestamp: int, metadata: Optional[dict] = None):
        """
        Save checkpoint to disk.

        Args:
            timestamp: Nanosecond timestamp of last processed log
            metadata: Optional metadata to store with checkpoint
        """
        try:
            checkpoint_data = {
                'timestamp': timestamp,
                'updated_at': datetime.now().isoformat(),
                'metadata': metadata or {}
            }

            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint_data, f, indent=2)

            logger.debug(f"Checkpoint saved: {timestamp}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")

    def load(self) -> Optional[int]:
        """
        Load checkpoint from disk.

        Returns:
            Timestamp (int) if checkpoint exists, None otherwise
        """
        try:
            if not os.path.exists(self.checkpoint_file):
                logger.info("No checkpoint file found, starting fresh")
                return None

            with open(self.checkpoint_file, 'r') as f:
                checkpoint_data = json.load(f)

            timestamp = checkpoint_data.get('timestamp')
            updated_at = checkpoint_data.get('updated_at')

            logger.info(f"Checkpoint loaded: {timestamp} (last updated: {updated_at})")
            return timestamp
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None

    def reset(self):
        """Remove checkpoint file to start from scratch."""
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
                logger.info("Checkpoint reset")
        except Exception as e:
            logger.error(f"Failed to reset checkpoint: {e}")
