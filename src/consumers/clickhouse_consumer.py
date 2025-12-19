import time
from datetime import datetime
from clickhouse_driver import Client
from typing import List, Dict, Any

class ClickHouseConsumer:
    def __init__(self, config: Dict[str, Any]):
        self.client = Client(
            host=config['host'],
            port=config.get('port', 9000),
            database=config.get('database', 'default'),
            # prompt for password/user handling if needed, but keeping simple for now
            # user=config.get('user', 'default'),
            # password=config.get('password', '')
        )
        self.table = config['table']
        self.batch_size = config.get('batch_size', 1000)
        self.last_query_time = datetime.now() # Start from now or load from persistence

    def fetch_logs(self) -> List[Dict[str, Any]]:
        """
        Polls ClickHouse for new logs since the last query time.
        Updates last_query_time to the timestamp of the latest log fetched.
        """
        # User example shows timestamps are nanoseconds (integers like 169...)
        # We need to handle that if self.last_query_time is a datetime or int.
        
        # Determine start_ns
        if isinstance(self.last_query_time, datetime):
            last_time_ns = int(self.last_query_time.timestamp() * 1e9)
        else:
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
            WHERE timestamp > %(last_time)s
            ORDER BY timestamp ASC
            LIMIT %(limit)d
        """
        
        try:
            # Execute query with parameters
            # ClickHouse driver params usually work for basic types, but ensure last_time matches column type (UInt64)
            rows = self.client.execute(
                query, 
                {'last_time': last_time_ns, 'limit': self.batch_size},
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
                print(f"Fetched {len(logs)} logs. New checkpoint_ns: {self.last_query_time}")
            
            return logs

        except Exception as e:
            print(f"Error fetching logs from ClickHouse: {e}")
            return []
