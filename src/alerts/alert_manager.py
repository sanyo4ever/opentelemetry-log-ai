import requests
import json
from typing import Dict, Any

class AlertManager:
    def __init__(self, config: Dict[str, Any]):
        self.webhook_url = config['keep_webhook_url']
        self.deduplication_window = config.get('deduplication_window', 300)

    def send_alert(self, alert_data: Dict[str, Any]):
        """
        Sends the alert payload to the configured output.
        """
        try:
            # Basic payload formatting usually required by tools like Keep or Slack
            # We'll wrap the alert_data.
            payload = {
                "source": "SecurityLogAnalyzer",
                "severity": alert_data.get("rule_level", "info"),
                "text": f"Sigma Rule Match: {alert_data.get('rule_title', 'Unknown')}",
                "details": alert_data
            }
            
            response = requests.post(
                self.webhook_url, 
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                print(f"Alert sent successfully: {alert_data.get('rule_title')}")
            else:
                print(f"Failed to send alert. Status: {response.status_code}, Body: {response.text}")

        except Exception as e:
            print(f"Error sending alert: {e}")
