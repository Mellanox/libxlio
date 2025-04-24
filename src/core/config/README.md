# XLIO Configuration Subsystem

This directory contains the implementation of XLIO's configuration management system. The configuration subsystem provides a flexible, hierarchical approach to configuring XLIO through JSON files and environment variables.

## Overview

The configuration system is designed with the following goals:
- Structured, hierarchical configuration with logical grouping
- Type-safe access to configuration values
- Multiple configuration sources (files, environment variables)
- Validation of configuration against a schema
- Backward compatibility with existing environment variables

## Components

### Core Components

- **Registry**: `config_registry` - Central configuration store that aggregates values from all loaders
- **Descriptor**: `config_descriptor` - Describes the structure and validation rules for configuration
- **Loaders**: Components that load configuration from different sources

### Loaders

- **JSON Loader (`json_loader`)**: Loads configuration from JSON files
- **Inline Loader (`inline_loader`)**: Loads configuration from inline strings using the `XLIO_INLINE_CONFIG` environment variable

### Descriptor Providers

- **JSON Descriptor Provider (`json_descriptor_provider`)**: Provides configuration schema from a JSON schema file

## Configuration Schema

XLIO uses a JSON Schema (Draft-07) to define the structure, types, defaults, and constraints for all configuration parameters. The schema is located in `descriptor_providers/xlio_config_schema.json`.

The schema organizes configuration into the following main sections:

1. **core**: Essential configuration affecting XLIO's basic operation
2. **network**: Network-related settings and protocol configurations
3. **hardware**: Hardware-specific configurations and offloads
4. **performance**: Settings that affect XLIO performance characteristics
5. **applications**: Configurations and optimizations for specific applications
6. **observability**: Settings for logging, statistics, and monitoring

## Configuration Methods

XLIO supports two configuration approaches: the new structured configuration system and the legacy environment variable system.

### New Configuration System

The new configuration system uses a hierarchical, structured approach with the following methods:

#### 1. Using XLIO_INLINE_CONFIG

Multiple configuration values can be set in a single environment variable using the `XLIO_INLINE_CONFIG` format:

```bash
# Set multiple configuration values in one line
export XLIO_INLINE_CONFIG="core.resources.memory_limit=4294967296, observability.log.file_path=/tmp/xlio.log, network.protocols.tcp.nodelay.enable=true"
```

The syntax supports comma-separated key-value pairs where each key uses the dot notation of the configuration hierarchy.

#### 2. Using JSON Configuration Files

Configuration can be provided through JSON files that follow the schema structure:

```json
{
  "core": {
    "resources": {
      "memory_limit": 4294967296,
      "hugepages": {
        "enable": true
      }
    }
  },
  "network": {
    "protocols": {
      "tcp": {
        "performance": {
          "nodelay": {
            "enable": true
          }
        }
      }
    }
  }
}
```

By default, XLIO looks for a JSON configuration file at `/etc/libxlio_config.json`. 

You can specify a custom configuration file location by setting the `XLIO_CONFIG_FILE` environment variable:

```bash
# Set custom JSON configuration file path
export XLIO_CONFIG_FILE=/path/to/my/xlio_config.json
```

### Legacy Configuration System

The legacy system uses individual environment variables for configuration. These are still supported for backward compatibility:

```bash
# Legacy environment variables
export XLIO_TRACELEVEL=debug
export XLIO_MEMORY_LIMIT=4294967296
export XLIO_TCP_NODELAY=true
```

To force XLIO to use the new configuration subsystem, set:

```bash
export XLIO_USE_NEW_CONFIG=1
```

## Environment Variable Mapping

The new configuration system maintains compatibility with legacy environment variables through a mapping system. Each configuration parameter in the new system can be associated with a legacy environment variable. This mapping is defined in `src/core/config/mappings.py`.

For example:
- `observability.log.level` maps to `XLIO_TRACELEVEL`
- `network.protocols.ip.mtu` maps to `XLIO_MTU`
- `performance.threading.cpu_affinity` maps to `XLIO_INTERNAL_THREAD_AFFINITY`

## Configuration Keys

Configuration keys in the new system follow a hierarchical dot notation that reflects their organization in the schema. For example:

```
core.resources.memory_limit
network.protocols.tcp.nodelay.enable
performance.rings.tx.alloc_logic
performance.buffers.tx.global_array_size
applications.nginx.distribute_cq
observability.stats.shmem_dir
```

## Dependencies

The configuration subsystem depends on:
- **json-c (0.13)**: A JSON implementation in C for parsing and manipulating JSON objects
  - **Location**: Included in the repository under `third_party/json-c`
  - Website: https://github.com/json-c/json-c
  - License: MIT
  - Features used: JSON parsing, object traversal, type handling

## Code Usage Examples

### Accessing Configuration Values

```cpp
// Get a boolean value with fallback
bool enable_hugepages = config->get_value<bool>("core.resources.hugepages.enable");

// Get an integer value
int64_t memory_limit = config->get_value<int64_t>("core.resources.memory_limit");

// Get a string value
std::string log_file = config->get_value<std::string>("observability.log.file_path");
```

## Migration Guide

For users migrating from the legacy environment variable configuration model to the new structured configuration system:

1. Use the mappings defined in `src/core/config/mappings.py` to understand the new configuration keys
2. Replace direct environment variable usage with either XLIO_INLINE_CONFIG or JSON configuration
3. `export XLIO_USE_NEW_CONFIG=1` to use the new subsystem.

## Further Information

- For a complete list of configuration parameters and their descriptions, refer to the JSON schema file
- For environment variable mappings, see `src/core/config/mappings.py`
- For implementation details, consult the header files in this directory
- Unit tests for the configuration subsystem are available at `tests/unit_tests/config` 