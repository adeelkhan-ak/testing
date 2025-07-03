# DPDK Tuple Filter Makefile

APP = tuple_filter

# DPDK configuration
RTE_SDK ?= /usr/local/share/dpdk
RTE_TARGET ?= x86_64-native-linuxapp-gcc

# Source files
SRCS = src/main.c \
       src/tuple_hash.c \
       src/packet_processor.c \
       src/rule_manager.c \
       src/stats_collector.c \
       src/config.c

# Compiler flags
CFLAGS += -O3 -g -Wall -Wextra
CFLAGS += -march=native -mtune=native
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -I./include

# DPDK flags
CFLAGS += $(shell pkg-config --cflags libdpdk)
LDFLAGS += $(shell pkg-config --libs libdpdk)

# Additional optimizations
CFLAGS += -ffast-math -funroll-loops
CFLAGS += -D_GNU_SOURCE

# Build directory
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
SRC_DIR = src

# Object files
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean setup install run debug

all: $(BUILD_DIR)/$(APP)

$(BUILD_DIR)/$(APP): $(OBJS) | $(BUILD_DIR)
	@echo "Linking $@"
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

setup:
	@echo "Setting up DPDK environment..."
	@if [ ! -d "/sys/kernel/mm/hugepages" ]; then \
		echo "Error: Hugepages not supported by kernel"; \
		exit 1; \
	fi
	@echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages || true
	@echo "Hugepages configured"
	@modprobe uio_pci_generic || echo "uio_pci_generic already loaded"

run: $(BUILD_DIR)/$(APP)
	@echo "Running tuple filter with default configuration..."
	sudo $(BUILD_DIR)/$(APP) -l 0-3 -n 4 -- -p 0x1 -q 2

debug: CFLAGS += -DDEBUG -O0
debug: $(BUILD_DIR)/$(APP)

install: setup
	@echo "Installing dependencies..."
	@which pkg-config > /dev/null || (echo "pkg-config required" && exit 1)
	@pkg-config --exists libdpdk || (echo "DPDK not found. Install DPDK first." && exit 1)

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Available targets:"
	@echo "  all     - Build the application"
	@echo "  setup   - Configure hugepages and kernel modules"
	@echo "  install - Check and install dependencies"
	@echo "  run     - Run with default configuration"
	@echo "  debug   - Build with debug symbols"
	@echo "  clean   - Clean build files"