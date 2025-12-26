import json
import logging
from typing import Dict, Any, Optional, Iterable

logger = logging.getLogger(__name__)

class OtelMapper:
    def __init__(self, mappings: Dict[str, Any]):
        self.mappings = mappings

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Optional[Any]:
        """
        Retrieves a value from a nested dictionary using dot notation.
        Supports keys containing dots (e.g., attributes['host.name']) by attempting
        to match composite keys if direct traversal fails.
        """
        keys = path.split('.')
        
        # Try direct traversal first
        current = data
        try:
            for i, key in enumerate(keys):
                if isinstance(current, dict):
                    # Special case: check if we can match the rest of the path as a single key
                    # This is common for OTEL attributes like 'host.name' inside 'attributes'
                    # e.g. path="attributes.host.name", we are at "attributes". 
                    # Remaining keys are ["host", "name"]. Join them -> "host.name".
                    if i < len(keys) - 1:
                        remaining = ".".join(keys[i:])
                        if remaining in current:
                            return current[remaining]
                            
                    # Also check for partial merges? e.g. "host.name" might be "host" -> "name"
                    # For now just proceed with standard split
                    current = current.get(key)
                else:
                    return None
            return current
        except:
            return None

    def parse_log_entry(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses a raw ClickHouse log entry.
        Merges attributes_string, attributes_number, etc. into a single 'attributes' dict.
        Normalizes 'body' if it is JSON string.
        """
        # Create a mutable copy to work with
        structured_log = raw_log.copy()
        
        # 1. Expand JSON fields if they are strings (body)
        if isinstance(structured_log.get('body'), str):
            try:
                # Basic check if it looks like JSON
                if structured_log['body'].strip().startswith('{'):
                    structured_log['body'] = json.loads(structured_log['body'])
            except (json.JSONDecodeError, AttributeError):
                pass

        # 1b. Common Windows event shape: merge EventData fields for easier Sigma field access.
        # Many Sigma rules refer to fields like "Image" / "CommandLine" which are typically found in EventData.
        body = structured_log.get('body')
        if isinstance(body, dict):
            event_data = body.get('EventData')
            if isinstance(event_data, dict):
                for key, value in event_data.items():
                    body.setdefault(key, value)
        
        # 2. Merge Separate Attribute Columns into one 'attributes' dictionary
        # This matches SigNoz's logs_v2 schema where attributes are split by type
        attributes = {}
        
        # Merge attributes_string
        attrs_str = structured_log.get('attributes_string', {})
        if isinstance(attrs_str, dict):
            attributes.update(attrs_str)
            
        # Merge attributes_number
        attrs_num = structured_log.get('attributes_number', {})
        if isinstance(attrs_num, dict):
            attributes.update(attrs_num)
            
        # Merge attributes_bool
        attrs_bool = structured_log.get('attributes_bool', {})
        if isinstance(attrs_bool, dict):
            attributes.update(attrs_bool)
            
        structured_log['attributes'] = attributes

        # Also merge resources
        resources = structured_log.get('resources_string', {})
        if isinstance(resources, dict):
            # OTEL usually expects resources separate, but let's ensure it's a dict
            structured_log['resource'] = resources
            # For mapping convenience, merge resource attributes into attributes
            # (without overwriting log record attributes).
            for key, value in resources.items():
                attributes.setdefault(key, value)

        return structured_log

    def _detect_log_source(self, structured_log: Dict[str, Any]) -> str:
        """
        Detect the log source type (windows, linux, etc.) based on log content.

        Args:
            structured_log: Parsed log entry

        Returns:
            Source type string ('windows', 'linux', or 'unknown')
        """
        # Check for Windows-specific indicators
        body = structured_log.get('body', {})
        attributes = structured_log.get('attributes', {})

        # Windows: has EventID and Channel fields
        if isinstance(body, dict) and 'EventID' in body:
            logger.debug("Detected Windows log (EventID present)")
            return 'windows'

        if isinstance(body, dict) and 'Channel' in body:
            logger.debug("Detected Windows log (Channel present)")
            return 'windows'

        # Windows: OS type indicator
        os_type = attributes.get('os.type') or attributes.get('os_type')
        if os_type and 'windows' in str(os_type).lower():
            logger.debug("Detected Windows log (os.type)")
            return 'windows'

        # Linux: syslog message format
        if isinstance(body, dict) and 'message' in body:
            logger.debug("Detected Linux log (syslog message)")
            return 'linux'

        # Linux: log file path indicators
        log_file = attributes.get('log.file.path') or attributes.get('log_file_path')
        if log_file and any(path in str(log_file) for path in ['/var/log', '/etc/', '/proc/']):
            logger.debug("Detected Linux log (file path)")
            return 'linux'

        if os_type and 'linux' in str(os_type).lower():
            logger.debug("Detected Linux log (os.type)")
            return 'linux'

        logger.debug("Unable to detect log source, treating as unknown")
        return 'unknown'

    def map_to_sigma(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Maps a raw log entry to a flat Sigma-compatible dictionary based on configuration.
        Automatically detects log source type and applies appropriate mappings.
        """
        structured_log = self.parse_log_entry(raw_log)
        return self.map_structured_to_sigma(structured_log)

    def map_structured_to_sigma(self, structured_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Maps an already-parsed log entry to a flat Sigma-compatible dictionary.
        """
        mapped_log = {}

        # Detect log source type
        source_type = self._detect_log_source(structured_log)

        # Select appropriate mappings
        if source_type in self.mappings:
            active_mappings = self.mappings[source_type]
            logger.debug(f"Applying {source_type} mappings ({len(active_mappings)} fields)")
        else:
            # Fall back to merging all mappings for unknown sources
            active_mappings = {}
            for category in self.mappings.values():
                active_mappings.update(category)
            logger.debug(f"Source type unknown, applying all mappings ({len(active_mappings)} fields)")

        # Apply mappings
        for sigma_field, otel_path in active_mappings.items():
            if otel_path is None:
                continue

            paths: Iterable[str]
            if isinstance(otel_path, (list, tuple)):
                paths = [str(p) for p in otel_path if p]
            else:
                paths = [str(otel_path)]

            for path in paths:
                val = self._get_nested_value(structured_log, path)
                if isinstance(val, str) and not val.strip():
                    continue
                if val is not None:
                    mapped_log[sigma_field] = val
                    break

        # Add metadata
        mapped_log['_source_type'] = source_type
        mapped_log['_timestamp'] = structured_log.get('timestamp')

        # Preserve original log for debugging (optional)
        # mapped_log['original_log'] = structured_log

        return mapped_log

    def build_sigma_event(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds a Sigma evaluation event that merges:
        - Parsed body fields (top-level)
        - Attributes and resources (top-level)
        - Mapped Sigma fields (top-level, takes precedence)

        This increases compatibility with upstream Sigma rules that reference fields
        directly (e.g. "Image", "CommandLine") while still keeping our explicit mappings.
        """
        structured_log = self.parse_log_entry(raw_log)
        mapped = self.map_structured_to_sigma(structured_log)

        event: Dict[str, Any] = {}

        body = structured_log.get('body')
        if isinstance(body, dict):
            event.update(body)
        elif body is not None:
            # Keep the raw body available; also help "keywords" search by setting message when possible.
            event['body'] = body
            if isinstance(body, str):
                event.setdefault('message', body)

        attributes = structured_log.get('attributes', {})
        if isinstance(attributes, dict):
            for key, value in attributes.items():
                event.setdefault(key, value)

        resource = structured_log.get('resource', {})
        if isinstance(resource, dict):
            for key, value in resource.items():
                event.setdefault(key, value)

        # Include basic ClickHouse columns for context (do not overwrite existing keys).
        for key in ('timestamp', 'severity_text', 'severity_number', 'id'):
            if key in structured_log:
                event.setdefault(key, structured_log.get(key))

        # Apply mapped Sigma fields last (explicit mappings win).
        event.update(mapped)

        # Convenience: some Sigma rules use "Message" (capitalized).
        if 'message' in event:
            event.setdefault('Message', event.get('message'))

        return event
