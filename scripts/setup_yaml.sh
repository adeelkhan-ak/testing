#!/bin/bash
# YAML Configuration Setup Script for DPDK Tuple Filter
# This script installs YAML dependencies and validates configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== DPDK Tuple Filter YAML Configuration Setup ==="
echo

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# Function to install dependencies
install_dependencies() {
    local os=$(detect_os)
    
    echo "Detected OS: $os"
    echo "Installing YAML dependencies..."
    
    case $os in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y libyaml-dev yamllint
            ;;
        rhel|centos|fedora)
            if command_exists dnf; then
                sudo dnf install -y libyaml-devel yamllint
            else
                sudo yum install -y libyaml-devel
                # yamllint might not be available in older repos
                echo "Note: yamllint might not be available. Install with pip: pip install yamllint"
            fi
            ;;
        *)
            echo "Unknown OS. Please install libyaml-dev manually."
            exit 1
            ;;
    esac
    
    echo "Dependencies installed successfully!"
}

# Function to validate YAML configuration
validate_yaml() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file not found: $config_file"
        return 1
    fi
    
    echo "Validating YAML configuration: $config_file"
    
    # Check if yamllint is available
    if command_exists yamllint; then
        echo "Running yamllint validation..."
        if yamllint "$config_file"; then
            echo "✓ YAML syntax is valid"
        else
            echo "✗ YAML syntax errors found"
            return 1
        fi
    else
        echo "Warning: yamllint not available, skipping syntax validation"
    fi
    
    # Basic structure validation
    echo "Checking configuration structure..."
    
    if grep -q "^ports:" "$config_file"; then
        echo "✓ Found ports section"
    else
        echo "✗ Missing ports section"
        return 1
    fi
    
    if grep -q "^rules:" "$config_file"; then
        echo "✓ Found rules section"
    else
        echo "✗ Missing rules section"
        return 1
    fi
    
    if grep -q "^global_settings:" "$config_file"; then
        echo "✓ Found global_settings section"
    else
        echo "✗ Missing global_settings section"
        return 1
    fi
    
    echo "Configuration validation passed!"
    return 0
}

# Function to build application with YAML support
build_application() {
    echo "Building application with YAML support..."
    
    cd "$PROJECT_DIR"
    
    # Check if pkg-config can find yaml
    if ! pkg-config --exists yaml-0.1; then
        echo "Error: libyaml not found by pkg-config"
        echo "Please ensure libyaml-dev is installed"
        return 1
    fi
    
    # Build the application
    if make all; then
        echo "✓ Application built successfully"
    else
        echo "✗ Build failed"
        return 1
    fi
    
    echo "Build completed!"
}

# Function to create example configuration
create_example_config() {
    local config_file="$PROJECT_DIR/example_config.yaml"
    
    echo "Creating example configuration: $config_file"
    
    cat > "$config_file" << 'EOF'
# Example YAML Configuration for DPDK Tuple Filter
# This is a minimal configuration for testing

ports:
  - id: port0
    pci_address: "0000:03:00.0"
    mac_address: "00:11:22:33:44:55"
    description: "Primary test port"

cpu_cores:
  rx_cores:
    - port: port0
      queue: 0
      core: 1
      description: "RX core for port0"
  
  tx_cores:
    - port: port0
      queue: 0
      core: 2
      description: "TX core for port0"

rules:
  - id: allow-http
    priority: 100
    match:
      src_ip: "*"
      dst_ip: "*"
      src_port: "*"
      dst_port: 80
      protocol: "tcp"
    action: forward
    out_port: port0
    description: "Allow HTTP traffic"
  
  - id: default-drop
    priority: 999
    match:
      src_ip: "*"
      dst_ip: "*"
      src_port: "*"
      dst_port: "*"
      protocol: "*"
    action: drop
    description: "Default drop rule"

global_settings:
  rx_burst_size: 32
  tx_burst_size: 32
  num_mbufs: 8192
  enable_numa: true
  enable_stats: true
  stats_interval: 5
  log_level: "info"
EOF
    
    echo "Example configuration created!"
    echo "Edit $config_file to match your system before use."
}

# Function to run quick test
run_quick_test() {
    local config_file="$1"
    
    echo "Running quick configuration test..."
    
    # Check if application was built
    if [[ ! -f "$PROJECT_DIR/build/tuple_filter" ]]; then
        echo "Error: Application not built. Run build first."
        return 1
    fi
    
    # Test configuration parsing (this will fail if DPDK init fails, but that's expected)
    echo "Testing configuration parsing..."
    cd "$PROJECT_DIR"
    
    # Run with --help to test that YAML option is available
    if ./build/tuple_filter --help 2>&1 | grep -q "yaml-config"; then
        echo "✓ YAML configuration option is available"
    else
        echo "✗ YAML configuration option not found"
        return 1
    fi
    
    echo "Quick test completed!"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -i, --install           Install YAML dependencies"
    echo "  -v, --validate FILE     Validate YAML configuration file"
    echo "  -b, --build             Build application with YAML support"
    echo "  -e, --example           Create example configuration file"
    echo "  -t, --test FILE         Run quick test with configuration file"
    echo "  -a, --all               Do everything (install, build, create example)"
    echo
    echo "Examples:"
    echo "  $0 --install                           # Install dependencies"
    echo "  $0 --validate dpdk_config.yaml        # Validate configuration"
    echo "  $0 --build                             # Build application"
    echo "  $0 --all                               # Full setup"
}

# Main function
main() {
    local action=""
    local config_file=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -i|--install)
                action="install"
                shift
                ;;
            -v|--validate)
                action="validate"
                config_file="$2"
                shift 2
                ;;
            -b|--build)
                action="build"
                shift
                ;;
            -e|--example)
                action="example"
                shift
                ;;
            -t|--test)
                action="test"
                config_file="$2"
                shift 2
                ;;
            -a|--all)
                action="all"
                shift
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Default action if none specified
    if [[ -z "$action" ]]; then
        show_usage
        exit 1
    fi
    
    # Execute action
    case $action in
        install)
            install_dependencies
            ;;
        validate)
            if [[ -z "$config_file" ]]; then
                echo "Error: Configuration file required for validation"
                exit 1
            fi
            validate_yaml "$config_file"
            ;;
        build)
            build_application
            ;;
        example)
            create_example_config
            ;;
        test)
            if [[ -z "$config_file" ]]; then
                echo "Error: Configuration file required for test"
                exit 1
            fi
            run_quick_test "$config_file"
            ;;
        all)
            install_dependencies
            echo
            build_application
            echo
            create_example_config
            echo
            echo "Setup complete! Next steps:"
            echo "1. Edit example_config.yaml to match your system"
            echo "2. Validate: $0 --validate example_config.yaml"
            echo "3. Run: sudo ./build/tuple_filter -l 0-3 -n 4 -- --yaml-config=example_config.yaml"
            ;;
    esac
}

# Run main function
main "$@"