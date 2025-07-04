#ifndef _YAML_CONFIG_H_
#define _YAML_CONFIG_H_

#include <stdint.h>
#include <stdbool.h>

/* Maximum limits for YAML configuration */
#define MAX_YAML_PORTS 16
#define MAX_YAML_CORES 64
#define MAX_YAML_RULES 10000

/* Port configuration structure */
struct yaml_port_config {
    char id[32];
    char pci_address[32];
    char mac_address[32];
    char description[128];
} __rte_aligned(64);

/* CPU core configuration structure */
struct yaml_core_config {
    char port[32];
    uint32_t queue;
    uint32_t core;
    char description[128];
} __rte_aligned(64);

/* Rule configuration structure */
struct yaml_rule_config {
    char id[32];
    uint32_t priority;
    
    /* Match criteria */
    uint32_t src_ip;
    uint32_t src_ip_mask;
    uint32_t dst_ip;
    uint32_t dst_ip_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    /* Action */
    uint8_t action;
    char out_port[32];
    char description[128];
} __rte_aligned(64);

/* Global settings structure */
struct yaml_global_settings {
    /* Basic settings */
    uint32_t rx_burst_size;
    uint32_t tx_burst_size;
    uint32_t num_mbufs;
    bool enable_numa;
    
    /* Extended settings */
    uint32_t mbuf_size;
    uint32_t mbuf_cache_size;
    uint32_t numa_socket;
    
    /* Performance settings */
    bool enable_hw_checksum;
    bool enable_rss;
    char rss_hash_key[64];
    
    /* Queue configuration */
    uint32_t rx_queues_per_port;
    uint32_t tx_queues_per_port;
    uint32_t rx_descriptors;
    uint32_t tx_descriptors;
    
    /* Logging and monitoring */
    char log_level[16];
    bool enable_stats;
    uint32_t stats_interval;
    
    /* Application settings */
    char app_name[64];
    char version[32];
    
    /* Memory configuration */
    uint32_t memory_channels;
    char huge_page_size[16];
    
    /* Interrupt handling */
    bool enable_interrupt;
    uint32_t interrupt_timeout;
    
    /* Flow control */
    bool enable_flow_control;
    uint32_t flow_control_pause_time;
} __rte_aligned(64);

/* Main YAML configuration structure */
struct yaml_config {
    /* Ports configuration */
    struct yaml_port_config ports[MAX_YAML_PORTS];
    uint32_t num_ports;
    
    /* CPU cores configuration */
    struct yaml_core_config rx_cores[MAX_YAML_CORES];
    struct yaml_core_config tx_cores[MAX_YAML_CORES];
    uint32_t num_rx_cores;
    uint32_t num_tx_cores;
    
    /* Rules configuration */
    struct yaml_rule_config rules[MAX_YAML_RULES];
    uint32_t num_rules;
    
    /* Global settings */
    struct yaml_global_settings global_settings;
} __rte_aligned(64);

/* Forward declaration */
struct app_context;

/* Function prototypes */

/**
 * Load YAML configuration from file
 * @param filename Path to YAML configuration file
 * @param config Pointer to configuration structure to populate
 * @return 0 on success, negative error code on failure
 */
int yaml_config_load(const char *filename, struct yaml_config *config);

/**
 * Free YAML configuration resources
 * @param config Pointer to configuration structure
 */
void yaml_config_free(struct yaml_config *config);

/**
 * Apply YAML configuration to application context
 * @param yaml_config Pointer to YAML configuration
 * @param ctx Pointer to application context
 * @return 0 on success, negative error code on failure
 */
int yaml_config_apply(struct yaml_config *yaml_config, struct app_context *ctx);

/**
 * Validate YAML configuration
 * @param config Pointer to configuration structure
 * @return 0 if valid, negative error code if invalid
 */
int yaml_config_validate(const struct yaml_config *config);

/**
 * Print YAML configuration summary
 * @param config Pointer to configuration structure
 */
void yaml_config_print_summary(const struct yaml_config *config);

/**
 * Convert port ID to port number
 * @param config Pointer to configuration structure
 * @param port_id Port ID string
 * @return Port number, or -1 if not found
 */
int yaml_config_get_port_number(const struct yaml_config *config, const char *port_id);

/**
 * Get core assignment for port and queue
 * @param config Pointer to configuration structure
 * @param port_id Port ID string
 * @param queue Queue number
 * @param is_rx True for RX core, false for TX core
 * @return Core number, or -1 if not found
 */
int yaml_config_get_core_assignment(const struct yaml_config *config, 
                                   const char *port_id, uint32_t queue, bool is_rx);

#endif /* _YAML_CONFIG_H_ */