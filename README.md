# DPDK High-Performance Tuple Filter

A high-performance packet filtering system built with DPDK (Data Plane Development Kit) capable of processing 100+ Gbps traffic with low latency tuple-based filtering.

## Features

- **High-Performance Hash Tables**: Optimized cuckoo and hopscotch hashing implementations
- **Lock-Free Updates**: Runtime rule modification without blocking packet processing
- **Multi-Core Scaling**: NUMA-aware architecture for optimal multi-core performance
- **Flexible Tuple Matching**: Support for 5-tuple, custom tuple formats
- **Zero-Copy Processing**: Minimal memory operations for maximum throughput
- **Real-time Statistics**: Performance monitoring and rule hit statistics
- **YAML Configuration**: Comprehensive YAML-based configuration system for advanced setups

## Architecture

The system uses a producer-consumer model with:
- Dedicated RX cores for packet ingress
- Worker cores for tuple filtering and processing
- Lock-free ring buffers for inter-core communication
- Per-core hash tables to avoid contention

## Performance Targets

- **Throughput**: 100+ Gbps on multi-core systems
- **Latency**: Sub-microsecond processing per packet
- **Rule Updates**: Lock-free runtime rule insertion/deletion
- **Memory Efficiency**: Optimized for cache locality and NUMA topology

## Build Requirements

### System Requirements

- **Linux Kernel**: 4.4+ with hugepage support
- **Architecture**: x86_64 with SSE4.2+ instruction set
- **CPU**: Intel or AMD processor with NUMA support (recommended)
- **Memory**: Minimum 4GB RAM, 8GB+ recommended for optimal performance
- **Root Access**: Required for hugepage configuration and kernel module loading

### Software Dependencies

#### Core Build Tools
- **GCC**: 9.0+ or **Clang**: 10.0+
- **Make**: Build system
- **pkg-config**: For dependency management
- **Python**: 3.6+ with pyelftools

#### DPDK Dependencies
- **DPDK**: 23.11 or later
- **Meson**: Build system (0.47.1+)
- **Ninja**: Build backend
- **libnuma-dev**: NUMA support library
- **libssl-dev**: SSL/TLS support
- **zlib1g-dev**: Compression library
- **libyaml-dev**: YAML configuration parser

### Installation Guide

#### Option 1: Automated Setup (Recommended)

The project includes an automated setup script that handles all dependencies and configuration:

```bash
# Clone the repository
git clone <repository-url>
cd dpdk-tuple-filter

# Run automated setup (requires sudo privileges)
chmod +x scripts/setup.sh
./scripts/setup.sh

# The script will:
# - Check system requirements
# - Install all dependencies
# - Download and build DPDK
# - Configure hugepages
# - Load kernel modules
# - Build the application
```

#### Option 2: Manual Installation

##### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc libnuma-dev pkg-config \
    meson ninja-build python3 python3-pyelftools libssl-dev zlib1g-dev
```

**RHEL/CentOS:**
```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y gcc numactl-devel pkg-config meson ninja-build \
    python3 python3-pyelftools openssl-devel zlib-devel
```

**Fedora:**
```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y gcc numactl-devel pkg-config meson ninja-build \
    python3 python3-pyelftools openssl-devel zlib-devel
```

##### 2. Install DPDK

```bash
# Download DPDK 23.11
cd /tmp
wget https://fast.dpdk.org/rel/dpdk-23.11.tar.xz
tar -xf dpdk-23.11.tar.xz
cd dpdk-23.11

# Configure and build DPDK
meson setup build --prefix=/usr/local --libdir=lib
cd build
ninja
sudo ninja install
sudo ldconfig
```

##### 3. Configure Hugepages

```bash
# Allocate hugepages (requires root)
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages

# Make persistent across reboots
echo "vm.nr_hugepages = 1024" | sudo tee -a /etc/sysctl.conf

# Mount hugepage filesystem
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs hugetlbfs /mnt/huge

# Add to fstab for persistence
echo "hugetlbfs /mnt/huge hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab
```

##### 4. Load Kernel Modules

```bash
# Load required kernel modules
sudo modprobe uio
sudo modprobe uio_pci_generic

# Make persistent across reboots
echo "uio" | sudo tee -a /etc/modules
echo "uio_pci_generic" | sudo tee -a /etc/modules
```

##### 5. Build Application

```bash
# Return to project directory
cd /path/to/dpdk-tuple-filter

# Verify DPDK installation
pkg-config --exists libdpdk && echo "DPDK found" || echo "DPDK not found"

# Build the application
make all

# Or build with debug symbols
make debug
```

### Verification

After installation, verify the setup:

```bash
# Check hugepages
cat /proc/sys/vm/nr_hugepages

# Check kernel modules
lsmod | grep uio

# Check DPDK installation
pkg-config --modversion libdpdk

# Verify application build
ls -la build/tuple_filter
```

### Troubleshooting

#### Common Issues

**DPDK not found:**
```bash
# Ensure pkg-config can find DPDK
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
sudo ldconfig
```

**Insufficient hugepages:**
```bash
# Check available memory
cat /proc/meminfo | grep HugePages
# Increase allocation if needed
echo 2048 | sudo tee /proc/sys/vm/nr_hugepages
```

**Permission denied errors:**
```bash
# Ensure proper permissions for hugepages
sudo chmod 666 /dev/hugepages/*
```

## Quick Start

```bash
# Using automated setup
./scripts/setup.sh

# Manual build process
make setup     # Configure hugepages and kernel modules
make all       # Compile the application
make run       # Run with default configuration

# Using YAML configuration
sudo apt-get install libyaml-dev  # Install YAML parser
make all       # Build with YAML support
sudo ./build/tuple_filter -l 0-7 -n 4 -- --yaml-config=dpdk_config.yaml
```

## Configuration

The application supports multiple configuration methods:

1. **Command-line arguments** - For basic configuration
2. **Simple config files** - Key-value format (backward compatible)
3. **YAML configuration** - Comprehensive configuration system (recommended)

See `YAML_CONFIG_GUIDE.md` for detailed YAML configuration documentation.
