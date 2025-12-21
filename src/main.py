import sys
import time
import yaml
import os
import logging
from typing import Dict, Any

from consumers.clickhouse_consumer import ClickHouseConsumer
from mappers.otel_mapper import OtelMapper
from detection.sigma_engine import SigmaEngine
from alerts.alert_manager import AlertManager
from utils.checkpoint import CheckpointManager
from utils.deduplication import AlertDeduplicator

def setup_logging(config: Dict[str, Any]):
    """Configure logging based on config."""
    log_config = config.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO'))
    log_file = log_config.get('file')

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        # Create log directory if needed
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

    # Set specific loggers to avoid spam
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('clickhouse_driver').setLevel(logging.INFO)

def load_config(path: str) -> Dict[str, Any]:
    """Load YAML configuration file with environment variable expansion."""
    with open(path, 'r') as f:
        # Read config content
        content = f.read()

        # Expand environment variables (${VAR_NAME} format)
        import re
        def expand_env_var(match):
            var_name = match.group(1)
            return os.environ.get(var_name, '')

        content = re.sub(r'\$\{([^}]+)\}', expand_env_var, content)

        # Parse YAML
        return yaml.safe_load(content)

def main():
    # Load configs first (before logging setup)
    config_path = os.environ.get('CONFIG_PATH', 'config/config.yaml')
    mapping_path = os.environ.get('MAPPING_PATH', 'config/field_mappings.yaml')

    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)

    config = load_config(config_path)
    mappings = load_config(mapping_path) if os.path.exists(mapping_path) else {}

    # Setup logging
    setup_logging(config)
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("Starting Security Log Analysis Service")
    logger.info("=" * 60)

    # Initialize components
    try:
        # Checkpoint manager
        checkpoint_path = config.get('checkpoint', {}).get('file', 'data/checkpoint.json')
        checkpoint_manager = CheckpointManager(checkpoint_path)
        logger.info(f"Checkpoint manager initialized: {checkpoint_path}")

        # Alert deduplicator
        dedup_config = config.get('alerting', {})
        use_redis = dedup_config.get('use_redis', False)
        redis_config = config.get('redis', {}) if use_redis else None

        deduplicator = AlertDeduplicator(
            window_seconds=dedup_config.get('deduplication_window', 300),
            use_redis=use_redis,
            redis_config=redis_config
        )

        # Core components
        consumer = ClickHouseConsumer(config['clickhouse'], checkpoint_manager)
        mapper = OtelMapper(mappings)
        engine = SigmaEngine(config['sigma'])
        alerter = AlertManager(config['alerting'], deduplicator)

        logger.info("All components initialized successfully")
        logger.info(f"Poll interval: {config['clickhouse'].get('poll_interval', 5)}s")

    except Exception as e:
        logger.error(f"Error initializing components: {e}", exc_info=True)
        sys.exit(1)

    poll_interval = config['clickhouse'].get('poll_interval', 5)
    stats_interval = config.get('stats_interval', 60)
    last_stats_time = time.time()

    # Main loop
    logger.info("Entering main processing loop")

    while True:
        try:
            # Process as many batches as are immediately available.
            while True:
                # 1. Fetch logs from ClickHouse
                raw_logs = consumer.fetch_logs()

                if raw_logs:
                    logger.info(f"Processing {len(raw_logs)} logs...")

                    # 2. Map logs to Sigma format
                    mapped_logs = []
                    for log in raw_logs:
                        try:
                            mapped = mapper.map_to_sigma(log)
                            mapped_logs.append(mapped)
                        except Exception as e:
                            logger.error(f"Error mapping log: {e}", exc_info=True)

                    # 3. Detect threats using Sigma rules
                    alerts = engine.evaluate(mapped_logs)

                    if alerts:
                        logger.info(f"Generated {len(alerts)} alerts")

                    # 4. Send alerts
                    sent_count = 0
                    for alert in alerts:
                        try:
                            if alerter.send_alert(alert):
                                sent_count += 1
                        except Exception as e:
                            logger.error(f"Error sending alert: {e}", exc_info=True)

                    if alerts:
                        logger.info(f"Sent {sent_count}/{len(alerts)} alerts")

                # Print stats periodically (even when idle)
                current_time = time.time()
                if current_time - last_stats_time >= stats_interval:
                    logger.info("=" * 60)
                    logger.info("System Statistics:")
                    logger.info(f"Alert Manager: {alerter.get_stats()}")
                    logger.info("=" * 60)
                    last_stats_time = current_time

                # If we got fewer than a full batch, we're likely caught up.
                if not raw_logs or len(raw_logs) < consumer.batch_size:
                    break

        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)

        time.sleep(poll_interval)

    logger.info("Security Log Analysis Service stopped")

if __name__ == '__main__':
    main()
