import json
from typing import Dict, Any, Optional

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

        return structured_log

    def map_to_sigma(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Maps a raw log entry to a flat Sigma-compatible dictionary based on configuration.
        """
        structured_log = self.parse_log_entry(raw_log)
        mapped_log = {}

        # Determine if it's Windows or Linux (simple heuristic or config based)
        # For now, we'll try to apply all mappings or decide based on a field.
        # Let's flatten everything we can find.
        
        # We start with the raw log as the base, so fields that are ALREADY flat exist
        # But usually Sigma expects specific renamed fields.
        
        # Iterate through all configured mapping categories (windows, linux)
        # In a real app, you'd select the category based on log source.
        # Here we just iterate 'windows' mappings as default for demonstration
        # or merge all.
        
        # Taking a simple approach: Flatten EVERYTHING defined in mappings.
        all_mappings = {}
        for category in self.mappings.values():
            all_mappings.update(category)
            
        for sigma_field, otel_path in all_mappings.items():
            val = self._get_nested_value(structured_log, otel_path)
            if val is not None:
                mapped_log[sigma_field] = val
                
        # Also preserve original fields if needed for context
        mapped_log['original_log'] = structured_log
        
        return mapped_log
