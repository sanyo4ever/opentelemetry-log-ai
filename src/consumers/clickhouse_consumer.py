import time
import logging
from datetime import datetime
from clickhouse_driver import Client
from typing import List, Dict, Any, Optional
from utils.checkpoint import CheckpointManager

logger = logging.getLogger(__name__)

class ClickHouseConsumer:
    def __init__(self, config: Dict[str, Any], checkpoint_manager: Optional[CheckpointManager] = None):
        # Initialize ClickHouse client with authentication
        client_config = {
            'host': config['host'],
            'port': config.get('port', 9000),
            'database': config.get('database', 'default'),
        }

        # Add authentication if provided
        if 'user' in config:
            client_config['user'] = config['user']
        if 'password' in config:
            client_config['password'] = config['password']

        self.client = Client(**client_config)
        self.table = config['table']
        self.batch_size = config.get('batch_size', 1000)
        self.checkpoint_manager = checkpoint_manager

        # Load checkpoint or start from now
        if self.checkpoint_manager:
            saved_checkpoint = self.checkpoint_manager.load()
            self.last_query_time = saved_checkpoint if saved_checkpoint else int(datetime.now().timestamp() * 1e9)
        else:
            self.last_query_time = int(datetime.now().timestamp() * 1e9)

        logger.info(f"ClickHouse consumer initialized. Starting from timestamp: {self.last_query_time}")

    def fetch_logs(self) -> List[Dict[str, Any]]:
        """
        Polls ClickHouse for new logs since the last query time.
        Updates last_query_time to the timestamp of the latest log fetched.
        """
        # Ensure timestamp is integer nanoseconds
        last_time_ns = int(self.last_query_time)

        query = f"""
            SELECT
                id,
                timestamp,
                severity_text,
                severity_number,
                body,
                attributes_string,
                attributes_number,
                attributes_bool,
                resources_string
            FROM {self.table}
            WHERE timestamp > {last_time_ns}
            ORDER BY timestamp ASC
            LIMIT {self.batch_size}
        """

        retry_count = 3
        retry_delay = 1  # seconds

        for attempt in range(retry_count):
            try:
                logger.debug(f"Fetching logs from ClickHouse (attempt {attempt + 1}/{retry_count})")

                rows = self.client.execute(
                    query,
                    with_column_types=True
                )

                data, columns = rows
                column_names = [col[0] for col in columns]

                logs = []
                for row in data:
                    log_dict = dict(zip(column_names, row))
                    logs.append(log_dict)

                if logs:
                    # Update checkpoint to the last timestamp found (int nanoseconds)
                    self.last_query_time = logs[-1]['timestamp']

                    # Persist checkpoint to disk
                    if self.checkpoint_manager:
                        self.checkpoint_manager.save(
                            self.last_query_time,
                            metadata={'logs_count': len(logs)}
                        )

                    logger.info(f"Fetched {len(logs)} logs. New checkpoint: {self.last_query_time}")

                return logs

            except Exception as e:
                logger.error(f"Error fetching logs from ClickHouse (attempt {attempt + 1}/{retry_count}): {e}")

                if attempt < retry_count - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error(f"Failed to fetch logs after {retry_count} attempts")
                    logger.error(f"Failed Query: {query}")
                    return []

        return []
