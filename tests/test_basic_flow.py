import sys
import os
import unittest
# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from mappers.otel_mapper import OtelMapper
from detection.sigma_engine import SigmaEngine

class TestBasicFlow(unittest.TestCase):
    def setUp(self):
        # Mock Mappings
        self.mappings = {
            'windows': {
                'EventID': 'body.EventID',
                'Computer': 'attributes.host.name'
            }
        }
        self.mapper = OtelMapper(self.mappings)
        
        # Mock Engine Config
        self.engine_config = {'rules_path': 'dummy'}
        self.engine = SigmaEngine(self.engine_config)

    def test_failed_login_detection(self):
        # Simulator a raw log from ClickHouse (SigNoz logs_v2 schema)
        raw_log = {
            'timestamp': 1698422400000000000, # Nanoseconds
            'body': '{"EventID": 4625, "Message": "Failed login"}',
            'attributes_string': {'host.name': 'production-server-1'},
            'attributes_number': {},
            'attributes_bool': {}
        }
        
        # 1. Map
        mapped = self.mapper.map_to_sigma(raw_log)
        
        print(f"Mapped Log: {mapped}")
        
        self.assertEqual(mapped.get('EventID'), 4625)
        self.assertEqual(mapped.get('Computer'), 'production-server-1')

        # 2. Evaluate
        alerts = self.engine.evaluate([mapped])
        
        print(f"Alerts: {alerts}")
        
        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0]['rule_title'], 'Failed Login Attempt')

if __name__ == '__main__':
    unittest.main()
