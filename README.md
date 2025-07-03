# DPDK High-Performance Tuple Filter

A high-performance packet filtering system built with DPDK (Data Plane Development Kit) capable of processing 100+ Gbps traffic with low latency tuple-based filtering.

## Features

- **High-Performance Hash Tables**: Optimized cuckoo and hopscotch hashing implementations
- **Lock-Free Updates**: Runtime rule modification without blocking packet processing
- **Multi-Core Scaling**: NUMA-aware architecture for optimal multi-core performance
- **Flexible Tuple Matching**: Support for 5-tuple, custom tuple formats
- **Zero-Copy Processing**: Minimal memory operations for maximum throughput
- **Real-time Statistics**: Performance monitoring and rule hit statistics

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

- DPDK 23.x or later
- GCC 9.0+ or Clang 10.0+
- Linux kernel 4.4+ with hugepage support
- Intel or AMD x86_64 processor with SSE4.2+

## Quick Start

```bash
make setup     # Install dependencies and configure hugepages
make build     # Compile the application
make run       # Run with default configuration
```
