# YAML Configuration Guide for DPDK Tuple Filter

## Overview

The DPDK Tuple Filter now supports comprehensive YAML configuration files in addition to the existing command-line arguments and simple configuration format. This guide explains how to use the new YAML configuration system.

## Prerequisites

### Dependencies

You need to install `libyaml-dev` (on Ubuntu/Debian) or `libyaml-devel` (on RHEL/CentOS):

```bash
# Ubuntu/Debian
sudo apt-get install libyaml-dev

# RHEL/CentOS
sudo yum install libyaml-devel

# Fedora
sudo dnf install libyaml-devel
```

### Building with YAML Support

The Makefile has been updated to include YAML support. Simply build as usual:

```bash
# Install dependencies
make install

# Build the application
make all
```

## Configuration Structure

The YAML configuration file (`dpdk_config.yaml`) contains four main sections:

1. **`ports`** - Physical NIC port definitions
2. **`cpu_cores`** - CPU core assignments for RX/TX processing
3. **`rules`** - Packet filtering rules
4. **`global_settings`** - System-wide configuration parameters

## Usage Examples

### Basic Usage

```bash
# Run with YAML configuration
sudo ./build/tuple_filter -l 0-7 -n 4 -- --yaml-config=dpdk_config.yaml

# Combine with other options
sudo ./build/tuple_filter -l 0-7 -n 4 -- --yaml-config=dpdk_config.yaml --verbose
```

### Advanced Usage

```bash
# Use YAML config with custom port mask
sudo ./build/tuple_filter -l 0-7 -n 4 -- --yaml-config=dpdk_config.yaml --portmask=0x3

# Use YAML config with custom stats interval
sudo ./build/tuple_filter -l 0-7 -n 4 -- --yaml-config=dpdk_config.yaml --stats-interval=10
```

## Configuration Sections

### 1. Ports Section

Defines physical NIC ports with their PCI addresses and properties:

```yaml
ports:
  - id: port-a
    pci_address: "0000:03:00.0"
    mac_address: "aa:bb:cc:dd:ee:01"
    description: "Primary ingress port"
    
  - id: port-b
    pci_address: "0000:03:00.1"
    mac_address: "aa:bb:cc:dd:ee:02"
    description: "Secondary ingress port"
```

**Fields:**
- `id`: Logical port identifier (used in rules and core assignments)
- `pci_address`: PCI address in format "0000:xx:yy.z"
- `mac_address`: MAC address (optional)
- `description`: Human-readable description

### 2. CPU Cores Section

Assigns specific CPU cores to handle RX and TX processing:

```yaml
cpu_cores:
  rx_cores:
    - port: port-a
      queue: 0
      core: 2
      description: "RX processing for port-a"
      
  tx_cores:
    - port: port-c
      queue: 0
      core: 6
      description: "TX processing for port-c"
```

**Fields:**
- `port`: Port ID (references the ports section)
- `queue`: Queue number (0-based)
- `core`: CPU core number
- `description`: Human-readable description

### 3. Rules Section

Defines packet filtering rules with 5-tuple matching:

```yaml
rules:
  - id: rule-001
    priority: 100
    match:
      src_ip: "192.168.1.0/24"
      dst_ip: "*"
      src_port: "*"
      dst_port: 22
      protocol: "tcp"
    action: drop
    description: "Drop SSH traffic from 192.168.1.0/24"
    
  - id: rule-002
    priority: 200
    match:
      src_ip: "*"
      dst_ip: "10.0.0.0/8"
      src_port: "*"
      dst_port: 80
      protocol: "tcp"
    action: forward
    out_port: port-c
    description: "Forward HTTP traffic to port-c"
```

**Match Fields:**
- `src_ip`: Source IP address (supports CIDR notation or "*" for any)
- `dst_ip`: Destination IP address
- `src_port`: Source port number (or "*" for any)
- `dst_port`: Destination port number (or "*" for any)
- `protocol`: Protocol ("tcp", "udp", "icmp", "*", or number)

**Action Fields:**
- `action`: Action to take ("drop", "forward", "accept")
- `out_port`: Output port for "forward" action
- `priority`: Rule priority (lower numbers = higher priority)

### 4. Global Settings Section

System-wide configuration parameters:

```yaml
global_settings:
  # Performance settings
  rx_burst_size: 32
  tx_burst_size: 32
  num_mbufs: 8192
  
  # NUMA configuration
  enable_numa: true
  numa_socket: 0
  
  # Queue configuration
  rx_queues_per_port: 2
  tx_queues_per_port: 2
  rx_descriptors: 1024
  tx_descriptors: 1024
  
  # Monitoring
  enable_stats: true
  stats_interval: 5
  log_level: "info"
```

## Integration with Existing System

### Precedence Order

Configuration parameters are applied in this order (later takes precedence):
1. Default values
2. Simple config file (if specified with `-c`)
3. YAML config file (if specified with `-y`)
4. Command-line arguments

### Backward Compatibility

The existing configuration system remains fully functional:
- Command-line arguments work as before
- Simple config files (`tuple_filter.conf`) work as before
- YAML is an additional optional feature

### Migration Path

To migrate from simple config to YAML:

1. **Keep existing setup** - No changes needed initially
2. **Add YAML gradually** - Use YAML for rules, keep simple config for basic settings
3. **Full migration** - Move all configuration to YAML when ready

## Configuration Validation

The system validates configuration at startup:
- Port PCI addresses must be valid
- Core assignments must reference existing ports
- Rule syntax must be correct
- IP addresses and ports must be valid

Validation errors will be logged and cause startup to fail.

## Performance Considerations

### Rule Ordering

Rules are processed in priority order (lowest number first):
- Use low priorities (e.g., 10-100) for high-priority drop rules
- Use medium priorities (e.g., 200-500) for forwarding rules
- Use high priorities (e.g., 900-999) for default/catch-all rules

### Core Assignment

For optimal performance:
- Assign RX cores to the same NUMA socket as input ports
- Assign TX cores to the same NUMA socket as output ports
- Leave core 0 for the main application thread
- Use cores 1-N for packet processing

### Memory Configuration

Tune memory settings based on your traffic load:
- `num_mbufs`: Increase for high traffic (8192-16384)
- `rx_descriptors`/`tx_descriptors`: Increase for burst traffic
- `rx_burst_size`/`tx_burst_size`: Tune for latency vs throughput

## Troubleshooting

### Common Issues

1. **YAML parsing errors**
   - Check YAML syntax with `yamllint dpdk_config.yaml`
   - Ensure proper indentation (spaces, not tabs)
   - Verify quotes around strings

2. **Port not found**
   - Verify PCI addresses with `lspci | grep Ethernet`
   - Ensure DPDK has bound the devices
   - Check hugepage allocation

3. **Core assignment errors**
   - Verify core numbers with `lscpu`
   - Ensure cores are not isolated
   - Check NUMA topology

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
sudo ./build/tuple_filter -l 0-7 -n 4 -- --yaml-config=dpdk_config.yaml --verbose
```

## Examples

### Example 1: Simple Web Server Protection

```yaml
rules:
  # Block known attack sources
  - id: block-attackers
    priority: 10
    match:
      src_ip: "203.0.113.0/24"
      dst_ip: "*"
      src_port: "*"
      dst_port: "*"
      protocol: "*"
    action: drop
    
  # Allow HTTP traffic
  - id: allow-http
    priority: 100
    match:
      src_ip: "*"
      dst_ip: "10.0.0.0/8"
      src_port: "*"
      dst_port: 80
      protocol: "tcp"
    action: forward
    out_port: port-web
    
  # Allow HTTPS traffic
  - id: allow-https
    priority: 100
    match:
      src_ip: "*"
      dst_ip: "10.0.0.0/8"
      src_port: "*"
      dst_port: 443
      protocol: "tcp"
    action: forward
    out_port: port-web
```

### Example 2: Load Balancer Configuration

```yaml
rules:
  # Distribute HTTP traffic
  - id: http-server1
    priority: 200
    match:
      src_ip: "*"
      dst_ip: "10.0.1.100"
      src_port: "*"
      dst_port: 80
      protocol: "tcp"
    action: forward
    out_port: port-server1
    
  - id: http-server2
    priority: 200
    match:
      src_ip: "*"
      dst_ip: "10.0.1.101"
      src_port: "*"
      dst_port: 80
      protocol: "tcp"
    action: forward
    out_port: port-server2
```

## Best Practices

1. **Use descriptive IDs** - Make rule and port IDs meaningful
2. **Group related rules** - Use priority ranges for different rule types
3. **Document your config** - Add descriptions to all rules
4. **Test incrementally** - Add rules gradually and test each change
5. **Monitor performance** - Use statistics to verify rule effectiveness
6. **Version control** - Keep configuration files in version control

## Support

For issues with YAML configuration:
1. Check the application logs for detailed error messages
2. Validate YAML syntax with online tools or `yamllint`
3. Test with minimal configurations first
4. Enable verbose logging for debugging