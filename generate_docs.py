#!/usr/bin/env python3

import json
import re
import sys
from typing import Dict, Any, List, Tuple, Optional

# Constants
class DocConstants:
    CONFIG_SECTION_HEADER = "Configuration Values"
    CONFIG_SECTION_TITLE = "Configuration Values\n===================="
    NEXT_SECTION_HEADER = "XLIO Monitoring & Performance Counters"
    
    # File paths
    SCHEMA_FILE = "src/core/config/descriptor_providers/xlio_config_schema.json"
    README_FILE = "README"
    
    # Units for formatting
    MB = 1024 * 1024
    GB = 1024 * 1024 * 1024


class ConfigPropertyParser:
    """Handles parsing and processing of configuration properties from schema."""
    
    @staticmethod
    def extract_env_var(description: Optional[str]) -> Optional[str]:
        """Extract environment variable name from property description.
        
        Args:
            description: The property description text
            
        Returns:
            Environment variable name or None if not found
        """
        if not description or "Maps to " not in description:
            return None
        
        match = re.search(r'Maps to ([A-Z_]+) environment variable', description)
        return match.group(1) if match else None

    @staticmethod
    def format_default_value(value: Any) -> str:
        """Format default value for better readability.
        
        Args:
            value: The default value to format
            
        Returns:
            Formatted string representation of the value
        """
        if isinstance(value, bool):
            return "true" if value else "false"
        elif isinstance(value, int):
            # Format large integers with more readable units
            if value >= DocConstants.GB and value % DocConstants.GB == 0:
                return f"{value // DocConstants.GB}GB"
            if value >= DocConstants.MB and value % DocConstants.MB == 0:
                return f"{value // DocConstants.MB}MB"
            return str(value)
        elif isinstance(value, str):
            if value.lower() in ["true", "false", "enabled", "disabled"]:
                return value.lower()
            return value if value != "" else "\"\""
        else:
            return str(value)


class SchemaProcessor:
    """Processes JSON schema and builds hierarchical structure of configuration options."""
    
    def __init__(self):
        self.hierarchy = {}
        self.processed_props = set()
    
    def process_schema_file(self, schema_file: str) -> Dict[str, Any]:
        """Process the JSON schema file and return hierarchical structure.
        
        Args:
            schema_file: Path to the JSON schema file
            
        Returns:
            Dictionary with hierarchical structure of configuration options
        """
        with open(schema_file, 'r') as f:
            schema = json.load(f)
        
        # Process each top-level section in the schema
        for section_name, section_data in schema.get("properties", {}).items():
            self.hierarchy[section_name] = {
                "is_section": True,
                "description": section_data.get("description", ""),
                "properties": {}
            }
            self._process_properties(section_data, section_name)
        
        return self.hierarchy
    
    def _process_properties(
        self, 
        schema: Dict[str, Any], 
        parent_path: str = ""
    ) -> None:
        """Process schema properties and build a hierarchical structure.
        
        Args:
            schema: The schema dictionary to process
            parent_path: Current path in the property hierarchy
        """
        # Handle properties at current level
        properties = schema.get("properties", {})
        for prop_name, prop_data in properties.items():
            current_path = f"{parent_path}.{prop_name}" if parent_path else prop_name
            
            # Skip if we've already processed this property
            if current_path in self.processed_props:
                continue

            if prop_name == "additionalProperties":
                continue
            
            self.processed_props.add(current_path)
            
            # Extract property information
            description = prop_data.get("description", "")
            default = prop_data.get("default", None)
            env_var = ConfigPropertyParser.extract_env_var(description)
            
            # If this is an object with properties, process its children
            if prop_data.get("type") == "object":
                # Create an entry for this section
                if current_path not in self.hierarchy:
                    self.hierarchy[current_path] = {
                        "is_section": True,
                        "description": description,
                        "properties": {}
                    }
                
                # Process nested properties
                self._process_properties(prop_data, current_path)
            else:  # This is a leaf property
                # Ensure parent section exists
                self._ensure_parent_exists(parent_path)
                
                # Store the property info under its parent
                self.hierarchy[parent_path]["properties"][current_path] = {
                    "description": description,
                    "env_var": env_var,
                    "default": default
                }
            
            # Handle oneOf with nested properties
            if "oneOf" in prop_data:
                env_var = ConfigPropertyParser.extract_env_var(prop_data.get("description", ""))
                
                # Ensure parent section exists
                self._ensure_parent_exists(parent_path)
                
                # Get default from first oneOf option with a default
                default = None
                for option in prop_data.get("oneOf", []):
                    if "default" in option:
                        default = option["default"]
                        break
                
                # Store the property info under its parent
                self.hierarchy[parent_path]["properties"][current_path] = {
                    "description": prop_data.get("description", ""),
                    "env_var": env_var,
                    "default": default
                }
    
    def _ensure_parent_exists(self, parent_path: str) -> None:
        """Ensure the parent section exists in the hierarchy.
        
        Args:
            parent_path: The parent section path
        """
        if parent_path not in self.hierarchy:
            self.hierarchy[parent_path] = {
                "is_section": True,
                "description": "",
                "properties": {}
            }


class DocumentationGenerator:
    """Generates documentation from processed schema hierarchy."""
    
    @staticmethod
    def format_property_entry(path: str, info: Dict[str, Any]) -> str:
        """Format a single property entry for the README.
        
        Args:
            path: The property path
            info: Property information dictionary
            
        Returns:
            Formatted property documentation
        """
        # Check if this is a section or a property
        if info.get("is_section", False):
            return ""
        
        env_var = info.get("env_var")
        description = info.get("description", "")
        default = info.get("default")
        
        # Format the path and description
        output = f"{path}\n"
        
        # Replace the environment variable with a bold version in the description
        if env_var:
            desc_cleaned = description.replace(
                f"Maps to {env_var} environment variable.", 
                f"Maps to **{env_var}** environment variable."
            )
            output += f"{desc_cleaned}\n"
        else:
            output += f"{description}\n"
        
        # Add default value if available
        if default is not None and "Default value is" not in description:
            default_str = ConfigPropertyParser.format_default_value(default)
            output += f"Default value is {default_str}\n"
        
        output += "\n"
        return output
    
    @staticmethod
    def collect_sorted_properties(hierarchy: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        """Collect and sort all properties from the hierarchy.
        
        Args:
            hierarchy: The property hierarchy
            
        Returns:
            List of tuples containing (property_path, property_info)
        """
        all_properties = []
        
        # Collect all properties from all sections and subsections
        for section_name, section_data in hierarchy.items():
            for path, prop_info in section_data.get("properties", {}).items():
                if not prop_info.get("is_section", False):
                    all_properties.append((path, prop_info))
        
        # Sort properties by path
        return sorted(all_properties, key=lambda x: x[0])
    
    @classmethod
    def generate_from_hierarchy(cls, hierarchy: Dict[str, Any]) -> str:
        """Generate documentation in README format from processed hierarchy.
        
        Args:
            hierarchy: The processed property hierarchy
            
        Returns:
            Generated documentation text
        """
        # Get sorted properties
        sorted_properties = cls.collect_sorted_properties(hierarchy)
        
        # Generate the documentation output
        doc_text = ""
        current_section = None
        
        for path, prop_info in sorted_properties:
            # Get the top-level section from the path
            top_section = path.split('.')[0]
            
            # If we're entering a new section, add a separator
            if top_section != current_section:
                # Add section header
                if current_section is not None:  # Don't add separator before the first section
                    doc_text += "\n" + "=" * 80 + "\n\n"
                
                doc_text += f"{top_section.upper()}\n" + "-" * len(top_section) + "\n\n"
                current_section = top_section
            
            doc_text += cls.format_property_entry(path, prop_info)
        
        return doc_text


class ReadmeUpdater:
    """Handles updating the README file with generated documentation."""
    
    @staticmethod
    def update_readme(readme_file: str, documentation: str) -> bool:
        """Update the README file by replacing the environment variable documentation section.
        
        Args:
            readme_file: Path to the README file
            documentation: Generated documentation to insert
            
        Returns:
            True if update was successful, False otherwise
        """
        try:
            with open(readme_file, 'r') as f:
                content = f.read()
            
            # Find the section where configuration values are documented
            config_section_start = content.find(f"\n{DocConstants.CONFIG_SECTION_HEADER}\n")
            if config_section_start == -1:
                print(f"Error: Could not find {DocConstants.CONFIG_SECTION_HEADER} section in README")
                return False
            
            # Find the next section
            next_section = f"\n{DocConstants.NEXT_SECTION_HEADER}"
            next_section_pos = content.find(next_section, config_section_start)
            if next_section_pos == -1:
                print(f"Error: Could not find '{DocConstants.NEXT_SECTION_HEADER}' section")
                return False
            
            # Replace everything between "Configuration Values" section and next section
            new_content = (
                content[:config_section_start] + 
                f"\n{DocConstants.CONFIG_SECTION_TITLE}\n" + 
                documentation + 
                content[next_section_pos:]
            )
            
            # Write the updated content back to the README
            with open(readme_file, 'w') as f:
                f.write(new_content)
            
            return True
        
        except Exception as e:
            print(f"Error updating README: {e}")
            return False


def main():
    """Main entry point for the script."""
    try:
        # Initialize schema processor and generate hierarchy
        processor = SchemaProcessor()
        hierarchy = processor.process_schema_file(DocConstants.SCHEMA_FILE)
        
        # Generate documentation
        documentation = DocumentationGenerator.generate_from_hierarchy(hierarchy)
        
        # Update README file
        if ReadmeUpdater.update_readme(DocConstants.README_FILE, documentation):
            print(f"Successfully updated {DocConstants.README_FILE} with generated documentation")
        else:
            # If updating the README fails, just print the documentation
            print("Generated documentation:")
            print(documentation)
    
    except FileNotFoundError:
        print(f"Error: Schema file not found at {DocConstants.SCHEMA_FILE}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
