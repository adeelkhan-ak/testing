#!/bin/bash

# DPDK Tuple Filter Setup Script
# This script configures the system and builds the application

set -e

# Configuration
HUGEPAGES_SIZE=2048
HUGEPAGES_COUNT=1024
DPDK_VERSION="23.11"
BUILD_TYPE="release"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may need different permissions."
    fi
}

# Check system requirements
check_requirements() {
    print_info "Checking system requirements..."
    
    # Check Linux kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 4 ]] || [[ $KERNEL_MAJOR -eq 4 && $KERNEL_MINOR -lt 4 ]]; then
        print_error "Linux kernel 4.4+ required. Current: $(uname -r)"
        exit 1
    fi
    
    # Check CPU architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]]; then
        print_error "x86_64 architecture required. Current: $ARCH"
        exit 1
    fi
    
    # Check for SSE4.2 support
    if ! grep -q sse4_2 /proc/cpuinfo; then
        print_error "SSE4.2 CPU support required"
        exit 1
    fi
    
    print_success "System requirements met"
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            gcc \
            libnuma-dev \
            pkg-config \
            meson \
            ninja-build \
            python3 \
            python3-pyelftools \
            libssl-dev \
            zlib1g-dev
            
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y \
            gcc \
            numactl-devel \
            pkg-config \
            meson \
            ninja-build \
            python3 \
            python3-pyelftools \
            openssl-devel \
            zlib-devel
            
    elif command -v dnf &> /dev/null; then
        # Fedora
        sudo dnf groupinstall -y "Development Tools"
        sudo dnf install -y \
            gcc \
            numactl-devel \
            pkg-config \
            meson \
            ninja-build \
            python3 \
            python3-pyelftools \
            openssl-devel \
            zlib-devel
            
    else
        print_error "Unsupported package manager. Please install dependencies manually."
        exit 1
    fi
    
    print_success "Dependencies installed"
}

# Install DPDK
install_dpdk() {
    print_info "Installing DPDK ${DPDK_VERSION}..."
    
    # Check if DPDK is already installed
    if pkg-config --exists libdpdk; then
        INSTALLED_VERSION=$(pkg-config --modversion libdpdk)
        print_info "DPDK already installed: version $INSTALLED_VERSION"
        return 0
    fi
    
    # Download and build DPDK
    DPDK_DIR="/tmp/dpdk-${DPDK_VERSION}"
    
    if [[ ! -d "$DPDK_DIR" ]]; then
        print_info "Downloading DPDK ${DPDK_VERSION}..."
        cd /tmp
        wget -q "https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz"
        tar -xf "dpdk-${DPDK_VERSION}.tar.xz"
    fi
    
    cd "$DPDK_DIR"
    
    # Configure DPDK build
    meson setup build \
        --prefix=/usr/local \
        --libdir=lib \
        -Dexamples='' \
        -Dtests=false \
        -Ddeveloper_mode=disabled
    
    # Build and install
    cd build
    ninja
    sudo ninja install
    sudo ldconfig
    
    print_success "DPDK installed"
}

# Configure hugepages
configure_hugepages() {
    print_info "Configuring hugepages..."
    
    # Check current hugepage configuration
    CURRENT_HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo "0")
    
    if [[ $CURRENT_HUGEPAGES -ge $HUGEPAGES_COUNT ]]; then
        print_info "Hugepages already configured: $CURRENT_HUGEPAGES pages"
        return 0
    fi
    
    # Configure hugepages
    echo $HUGEPAGES_COUNT | sudo tee /proc/sys/vm/nr_hugepages > /dev/null
    
    # Make hugepage configuration persistent
    if ! grep -q "vm.nr_hugepages" /etc/sysctl.conf; then
        echo "vm.nr_hugepages = $HUGEPAGES_COUNT" | sudo tee -a /etc/sysctl.conf
    fi
    
    # Mount hugepage filesystem
    sudo mkdir -p /mnt/huge
    if ! grep -q "/mnt/huge" /proc/mounts; then
        sudo mount -t hugetlbfs hugetlbfs /mnt/huge
    fi
    
    # Add to fstab for persistence
    if ! grep -q "/mnt/huge" /etc/fstab; then
        echo "hugetlbfs /mnt/huge hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab
    fi
    
    # Verify hugepage configuration
    ACTUAL_HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages)
    if [[ $ACTUAL_HUGEPAGES -ge $HUGEPAGES_COUNT ]]; then
        print_success "Hugepages configured: $ACTUAL_HUGEPAGES pages"
    else
        print_error "Failed to configure hugepages: only $ACTUAL_HUGEPAGES allocated"
        exit 1
    fi
}

# Load kernel modules
load_kernel_modules() {
    print_info "Loading kernel modules..."
    
    # Load UIO module
    if ! lsmod | grep -q uio; then
        sudo modprobe uio
    fi
    
    # Load UIO PCI generic module
    if ! lsmod | grep -q uio_pci_generic; then
        sudo modprobe uio_pci_generic
    fi
    
    # Make module loading persistent
    if ! grep -q "uio" /etc/modules; then
        echo "uio" | sudo tee -a /etc/modules
    fi
    
    if ! grep -q "uio_pci_generic" /etc/modules; then
        echo "uio_pci_generic" | sudo tee -a /etc/modules
    fi
    
    print_success "Kernel modules loaded"
}

# Build application
build_application() {
    print_info "Building tuple filter application..."
    
    # Clean previous build
    make clean 2>/dev/null || true
    
    # Build application
    if [[ "$BUILD_TYPE" == "debug" ]]; then
        make debug
    else
        make all
    fi
    
    if [[ -f "build/tuple_filter" ]]; then
        print_success "Application built successfully"
    else
        print_error "Application build failed"
        exit 1
    fi
}

# Create directories
create_directories() {
    print_info "Creating directories..."
    
    mkdir -p build
    mkdir -p logs
    mkdir -p config
    mkdir -p scripts
    
    print_success "Directories created"
}

# Set permissions
set_permissions() {
    print_info "Setting permissions..."
    
    # Make scripts executable
    chmod +x scripts/*.sh 2>/dev/null || true
    
    # Set application permissions
    if [[ -f "build/tuple_filter" ]]; then
        chmod +x build/tuple_filter
    fi
    
    print_success "Permissions set"
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    # Check DPDK installation
    if ! pkg-config --exists libdpdk; then
        print_error "DPDK not found"
        exit 1
    fi
    
    # Check hugepages
    HUGEPAGES=$(cat /proc/sys/vm/nr_hugepages)
    if [[ $HUGEPAGES -lt 512 ]]; then
        print_warning "Low hugepage count: $HUGEPAGES (recommended: 1024+)"
    fi
    
    # Check application binary
    if [[ ! -f "build/tuple_filter" ]]; then
        print_error "Application binary not found"
        exit 1
    fi
    
    print_success "Installation verified"
}

# Print usage information
print_usage() {
    print_info "Setup completed successfully!"
    echo
    echo "Usage:"
    echo "  make run           # Run with default configuration"
    echo "  make debug         # Build with debug symbols"
    echo "  make clean         # Clean build files"
    echo
    echo "Advanced usage:"
    echo "  sudo ./build/tuple_filter -l 0-3 -n 4 -- -p 0x1 -q 2"
    echo "  sudo ./build/tuple_filter -l 0-7 -n 4 -- --portmask=0x3 --numa"
    echo
    echo "Configuration:"
    echo "  Edit config/tuple_filter.conf for custom settings"
    echo
    echo "Logs:"
    echo "  Application logs will be stored in logs/ directory"
}

# Main setup function
main() {
    echo "DPDK Tuple Filter Setup Script"
    echo "==============================="
    echo
    
    check_root
    check_requirements
    install_dependencies
    install_dpdk
    configure_hugepages
    load_kernel_modules
    create_directories
    build_application
    set_permissions
    verify_installation
    
    echo
    print_usage
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --hugepages)
            HUGEPAGES_COUNT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --debug              Build in debug mode"
            echo "  --hugepages COUNT    Number of hugepages to allocate (default: 1024)"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main setup
main