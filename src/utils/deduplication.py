import hashlib
import logging
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AlertDeduplicator:
    """
    Deduplicates alerts based on rule + key fields within a time window.
    Uses in-memory cache with optional Redis backend.
    """
    def __init__(self, window_seconds: int = 300, use_redis: bool = False, redis_config: Optional[Dict[str, Any]] = None):
        self.window_seconds = window_seconds
        self.use_redis = use_redis
        self.redis_client = None

        # In-memory cache: {alert_hash: timestamp}
        self.cache = {}

        if use_redis and redis_config:
            try:
                import redis
                self.redis_client = redis.Redis(
                    host=redis_config.get('host', 'localhost'),
                    port=redis_config.get('port', 6379),
                    db=redis_config.get('db', 0),
                    password=redis_config.get('password'),
                    decode_responses=True
                )
                self.redis_client.ping()
                logger.info("Redis deduplication backend initialized")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis, falling back to in-memory: {e}")
                self.use_redis = False

        logger.info(f"Alert deduplicator initialized (window: {window_seconds}s, backend: {'Redis' if self.use_redis else 'memory'})")

    def _generate_alert_hash(self, alert: Dict[str, Any]) -> str:
        """
        Generate a unique hash for an alert based on rule and key fields.

        Args:
            alert: Alert dictionary with rule_title and log_data

        Returns:
            Hash string
        """
        # Extract identifying fields
        rule_title = alert.get('rule_title', 'unknown')
        log_data = alert.get('log_data', {})

        # Include key fields that make alerts unique
        key_fields = {
            'rule': rule_title,
            'event_id': log_data.get('EventID'),
            'computer': log_data.get('Computer'),
            'target_user': log_data.get('TargetUserName'),
            'source_ip': log_data.get('IpAddress'),
        }

        # Remove None values
        key_fields = {k: v for k, v in key_fields.items() if v is not None}

        # Create deterministic string representation
        key_string = '|'.join(f"{k}:{v}" for k, v in sorted(key_fields.items()))

        # Generate hash
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def is_duplicate(self, alert: Dict[str, Any]) -> bool:
        """
        Check if alert is a duplicate within the deduplication window.

        Args:
            alert: Alert dictionary

        Returns:
            True if duplicate, False otherwise
        """
        alert_hash = self._generate_alert_hash(alert)
        current_time = int(time.time())

        if self.use_redis and self.redis_client:
            return self._is_duplicate_redis(alert_hash, current_time)
        else:
            return self._is_duplicate_memory(alert_hash, current_time)

    def _is_duplicate_redis(self, alert_hash: str, current_time: int) -> bool:
        """Check for duplicate using Redis."""
        try:
            key = f"alert_dedup:{alert_hash}"

            # Check if key exists
            last_seen = self.redis_client.get(key)

            if last_seen:
                last_seen_time = int(last_seen)
                if current_time - last_seen_time < self.window_seconds:
                    logger.debug(f"Duplicate alert detected (Redis): {alert_hash}")
                    return True

            # Update timestamp
            self.redis_client.setex(key, self.window_seconds, current_time)
            return False

        except Exception as e:
            logger.error(f"Redis deduplication error: {e}, falling back to memory")
            return self._is_duplicate_memory(alert_hash, current_time)

    def _is_duplicate_memory(self, alert_hash: str, current_time: int) -> bool:
        """Check for duplicate using in-memory cache."""
        # Clean old entries
        self._cleanup_memory_cache(current_time)

        if alert_hash in self.cache:
            last_seen_time = self.cache[alert_hash]
            if current_time - last_seen_time < self.window_seconds:
                logger.debug(f"Duplicate alert detected (memory): {alert_hash}")
                return True

        # Update timestamp
        self.cache[alert_hash] = current_time
        return False

    def _cleanup_memory_cache(self, current_time: int):
        """Remove expired entries from memory cache."""
        expired_keys = [
            key for key, timestamp in self.cache.items()
            if current_time - timestamp >= self.window_seconds
        ]

        for key in expired_keys:
            del self.cache[key]

        if expired_keys:
            logger.debug(f"Cleaned {len(expired_keys)} expired entries from cache")

    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        if self.use_redis and self.redis_client:
            try:
                keys = self.redis_client.keys("alert_dedup:*")
                return {
                    'backend': 'redis',
                    'cached_alerts': len(keys),
                    'window_seconds': self.window_seconds
                }
            except:
                pass

        return {
            'backend': 'memory',
            'cached_alerts': len(self.cache),
            'window_seconds': self.window_seconds
        }
