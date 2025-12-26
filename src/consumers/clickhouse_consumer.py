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
        self.service_name_allowlist = config.get('service_name_allowlist', []) or []
        self.body_contains = config.get('body_contains', []) or []
        self.additional_where = config.get('additional_where')

        # Load checkpoint or determine initial start point
        if self.checkpoint_manager:
            saved_checkpoint = self.checkpoint_manager.load()
            if saved_checkpoint is not None:
                # Resume from saved checkpoint
                self.last_query_time = saved_checkpoint
                logger.info(f"Resuming from saved checkpoint: {self.last_query_time}")
            else:
                # No checkpoint exists - determine initial start mode
                initial_start_mode = config.get('initial_start_mode', 'now')
                if initial_start_mode == 'beginning':
                    # Start from the beginning (timestamp 0)
                    self.last_query_time = 0
                    logger.info("No checkpoint found. Starting from the beginning (processing all historical logs)")
                else:
                    # Default: start from now
                    self.last_query_time = int(datetime.now().timestamp() * 1e9)
                    logger.info("No checkpoint found. Starting from current time (only new logs will be processed)")
        else:
            # No checkpoint manager - always start from now
            self.last_query_time = int(datetime.now().timestamp() * 1e9)
            logger.info("No checkpoint manager. Starting from current time")

        logger.info(f"ClickHouse consumer initialized. Starting timestamp: {self.last_query_time}")

    def _quote_sql_string(self, value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _build_filter_where(self) -> str:
        clauses: List[str] = []

        if self.service_name_allowlist:
            service_names = ", ".join(self._quote_sql_string(name) for name in self.service_name_allowlist if name)
            if service_names:
                clauses.append(f"resources_string['service.name'] IN ({service_names})")

        if self.body_contains:
            parts = [substring for substring in self.body_contains if substring]
            if parts:
                contains = " OR ".join(f"position(body, {self._quote_sql_string(part)}) > 0" for part in parts)
                clauses.append(f"({contains})")

        if self.additional_where:
            clauses.append(f"({self.additional_where})")

        return " AND ".join(clauses)

    def fetch_logs(self) -> List[Dict[str, Any]]:
        """
        Polls ClickHouse for new logs since the last query time.
        Updates last_query_time to the timestamp of the latest log fetched.
        """
        # Ensure timestamp is integer nanoseconds
        last_time_ns = int(self.last_query_time)

        # Convert nanoseconds to ts_bucket_start (unix seconds, 30-min buckets)
        last_time_seconds = last_time_ns // 1_000_000_000
        last_bucket_start = (last_time_seconds // 1800) * 1800  # Round down to 30-min bucket

        # Build WHERE clauses
        where = [
            f"ts_bucket_start >= {last_bucket_start}",
            f"timestamp > {last_time_ns}"
        ]
        filter_where = self._build_filter_where()
        if filter_where:
            where.append(filter_where)

        query = f"""
            SELECT
                id,
                timestamp,
                ts_bucket_start,
                severity_text,
                severity_number,
                body,
                attributes_string,
                attributes_number,
                attributes_bool,
                resources_string
            FROM {self.table}
            WHERE {' AND '.join(where)}
            ORDER BY ts_bucket_start, timestamp
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
