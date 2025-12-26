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
        self.keep_api_key = config.get('keep_api_key', '')
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 1)
        self.max_alerts_per_minute = config.get('max_alerts_per_minute', 100)

        # Alert rate limiting
        self.alert_timestamps = deque(maxlen=self.max_alerts_per_minute)

        # Deduplication
        self.deduplicator = deduplicator

        # Log initialization (mask API key if present)
        api_key_status = "configured" if self.keep_api_key else "not configured"
        logger.info(f"Alert manager initialized (webhook: {self.webhook_url}, API key: {api_key_status}, max_alerts/min: {self.max_alerts_per_minute})")

    def _extract_hostname(self, alert_data: Dict[str, Any]) -> Optional[str]:
        log_data = alert_data.get("log_data") or {}
        if not isinstance(log_data, dict):
            return None

        candidates = [
            log_data.get("Computer"),   # Windows mapping
            log_data.get("hostname"),   # Linux mapping
            log_data.get("host.name"),
            log_data.get("host"),
            log_data.get("host_name"),
        ]

        for candidate in candidates:
            if candidate is None:
                continue
            if isinstance(candidate, str):
                value = candidate.strip()
                if value:
                    return value
                continue
            return str(candidate)

        return None

    def _format_event_name(self, alert_data: Dict[str, Any]) -> str:
        rule_title = str(alert_data.get("rule_title") or "Unknown").strip() or "Unknown"
        hostname = self._extract_hostname(alert_data)
        if hostname:
            return f"[{hostname}] Sigma Match: {rule_title}"
        return f"Sigma Match: {rule_title}"

    def _normalize_keep_source(self, source: str) -> list[str]:
        value = str(source or "").strip()
        return [value] if value else []

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

        event_name = self._format_event_name(alert_data)

        # Format payload
        payload = {
            # Keep's AlertDto expects `source` as a list[str].
            "source": self._normalize_keep_source("SecurityLogAnalyzer"),
            "severity": alert_data.get("rule_level", "info"),
            "name": event_name,
            "message": event_name,
            "status": "firing",
            "details": alert_data
        }

        # Send with retry logic
        return self._send_with_retry(payload, event_name)

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

                # Prepare headers
                headers = {'Content-Type': 'application/json'}

                # Add X-API-KEY header if API key is configured
                if self.keep_api_key:
                    headers['X-API-KEY'] = self.keep_api_key

                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers=headers,
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
