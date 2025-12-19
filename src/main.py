import sys
import time
import yaml
import os
from typing import Dict, Any

from consumers.clickhouse_consumer import ClickHouseConsumer
from mappers.otel_mapper import OtelMapper
from detection.sigma_engine import SigmaEngine
from alerts.alert_manager import AlertManager

def load_config(path: str) -> Dict[str, Any]:
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def main():
    print("Starting Security Log Analysis Service...")
    
    # Load configs
    config_path = os.environ.get('CONFIG_PATH', 'config/config.yaml')
    mapping_path = os.environ.get('MAPPING_PATH', 'config/field_mappings.yaml')
    
    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)
        
    config = load_config(config_path)
    mappings = load_config(mapping_path) if os.path.exists(mapping_path) else {}
    
    # Initialize components
    try:
        consumer = ClickHouseConsumer(config['clickhouse'])
        mapper = OtelMapper(mappings)
        engine = SigmaEngine(config['sigma'])
        alerter = AlertManager(config['alerting'])
        
        print("Components initialized successfully.")
    except Exception as e:
        print(f"Error initializing components: {e}")
        sys.exit(1)

    poll_interval = config['clickhouse'].get('poll_interval', 5)

    # Main Loop
    while True:
        try:
            # 1. Fetch Logs
            raw_logs = consumer.fetch_logs()
            
            if raw_logs:
                print(f"Processing {len(raw_logs)} logs...")
                
                mapped_logs = []
                # 2. Map Logs
                for log in raw_logs:
                    mapped = mapper.map_to_sigma(log)
                    mapped_logs.append(mapped)

                # 3. Detect Threats
                alerts = engine.evaluate(mapped_logs)
                
                # 4. Send Alerts
                for alert in alerts:
                    alerter.send_alert(alert)
                    
            else:
                pass # No new logs
                
        except Exception as e:
            print(f"Error in main loop: {e}")
            
        time.sleep(poll_interval)

if __name__ == '__main__':
    main()
