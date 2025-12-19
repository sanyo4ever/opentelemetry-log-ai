import requests
import json
import logging
import time
from typing import Dict, Any, Optional
from collections import deque
from utils.deduplication import AlertDeduplicator

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, config: Dict[str, Any], deduplicator: Optional[AlertDeduplicator] = None):
        self.webhook_url = config['keep_webhook_url']
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 1)
        self.max_alerts_per_minute = config.get('max_alerts_per_minute', 100)

        # Alert rate limiting
        self.alert_timestamps = deque(maxlen=self.max_alerts_per_minute)

        # Deduplication
        self.deduplicator = deduplicator

        logger.info(f"Alert manager initialized (webhook: {self.webhook_url}, max_alerts/min: {self.max_alerts_per_minute})")

    def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Sends the alert payload to the configured output with deduplication and throttling.

        Args:
            alert_data: Alert dictionary

        Returns:
            True if alert was sent, False otherwise
        """
        # Check deduplication
        if self.deduplicator and self.deduplicator.is_duplicate(alert_data):
            logger.info(f"Skipping duplicate alert: {alert_data.get('rule_title')}")
            return False

        # Check rate limiting
        if not self._check_rate_limit():
            logger.warning(f"Alert rate limit exceeded ({self.max_alerts_per_minute}/min), dropping alert: {alert_data.get('rule_title')}")
            return False

        # Format payload
        payload = {
            "source": "SecurityLogAnalyzer",
            "severity": alert_data.get("rule_level", "info"),
            "text": f"Sigma Rule Match: {alert_data.get('rule_title', 'Unknown')}",
            "details": alert_data
        }

        # Send with retry logic
        return self._send_with_retry(payload, alert_data.get('rule_title', 'Unknown'))

    def _check_rate_limit(self) -> bool:
        """
        Check if we're within the rate limit.

        Returns:
            True if under limit, False otherwise
        """
        current_time = time.time()

        # Remove timestamps older than 1 minute
        while self.alert_timestamps and current_time - self.alert_timestamps[0] > 60:
            self.alert_timestamps.popleft()

        # Check if we're at the limit
        if len(self.alert_timestamps) >= self.max_alerts_per_minute:
            return False

        # Add current timestamp
        self.alert_timestamps.append(current_time)
        return True

    def _send_with_retry(self, payload: Dict[str, Any], rule_title: str) -> bool:
        """
        Send webhook with exponential backoff retry.

        Args:
            payload: Webhook payload
            rule_title: Rule title for logging

        Returns:
            True if sent successfully, False otherwise
        """
        retry_delay = self.retry_delay

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Sending alert (attempt {attempt + 1}/{self.max_retries}): {rule_title}")

                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )

                if response.status_code >= 200 and response.status_code < 300:
                    logger.info(f"Alert sent successfully: {rule_title}")
                    return True
                else:
                    logger.warning(f"Alert failed with status {response.status_code}: {response.text}")

                    # Don't retry on 4xx errors (client errors)
                    if 400 <= response.status_code < 500:
                        logger.error(f"Client error, not retrying: {rule_title}")
                        return False

            except requests.exceptions.Timeout:
                logger.warning(f"Alert timeout (attempt {attempt + 1}/{self.max_retries}): {rule_title}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error (attempt {attempt + 1}/{self.max_retries}): {rule_title}")
            except Exception as e:
                logger.error(f"Unexpected error sending alert: {e}")

            # Retry with exponential backoff
            if attempt < self.max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2

        logger.error(f"Failed to send alert after {self.max_retries} attempts: {rule_title}")
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get alert manager statistics."""
        stats = {
            'alerts_in_last_minute': len(self.alert_timestamps),
            'max_alerts_per_minute': self.max_alerts_per_minute
        }

        if self.deduplicator:
            stats['deduplication'] = self.deduplicator.get_stats()

        return stats
