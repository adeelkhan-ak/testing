#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>

#include "tuple_filter.h"

#define RTE_LOGTYPE_CONFIG RTE_LOGTYPE_USER6

/* Default configuration values */
#define DEFAULT_PORT_MASK 0x1
#define DEFAULT_NB_QUEUES 1
#define DEFAULT_HASH_ENTRIES (1024 * 1024)

/* Configuration structure */
struct config_params {
    uint32_t port_mask;
    uint32_t nb_queues;
    uint32_t hash_entries;
    bool numa_enabled;
    bool verbose;
    char *rules_file;
    char *config_file;
    uint32_t stats_interval;
} __rte_cache_aligned;

static struct config_params g_config;

/* Command line option definitions */
static struct option long_options[] = {
    {"portmask", required_argument, 0, 'p'},
    {"queues", required_argument, 0, 'q'},
    {"hash-entries", required_argument, 0, 'h'},
    {"numa", no_argument, 0, 'n'},
    {"verbose", no_argument, 0, 'v'},
    {"rules-file", required_argument, 0, 'r'},
    {"config-file", required_argument, 0, 'c'},
    {"stats-interval", required_argument, 0, 's'},
    {"help", no_argument, 0, 'H'},
    {0, 0, 0, 0}
};

/* Print usage information */
static void
print_usage(const char *prog_name)
{
    printf("\nUsage: %s [DPDK options] -- [application options]\n\n", prog_name);
    printf("Application options:\n");
    printf("  -p, --portmask=MASK      Hexadecimal bitmask of ports to use (default: 0x1)\n");
    printf("  -q, --queues=N           Number of RX queues per port (default: 1)\n");
    printf("  -h, --hash-entries=N     Number of hash table entries (default: 1M)\n");
    printf("  -n, --numa               Enable NUMA awareness\n");
    printf("  -v, --verbose            Enable verbose logging\n");
    printf("  -r, --rules-file=FILE    Load rules from file\n");
    printf("  -c, --config-file=FILE   Load configuration from file\n");
    printf("  -s, --stats-interval=N   Statistics collection interval in seconds (default: 5)\n");
    printf("  -H, --help               Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -l 0-3 -n 4 -- -p 0x3 -q 2 -n\n", prog_name);
    printf("  %s -l 0-7 -n 4 -- --portmask=0xf --queues=4 --numa\n", prog_name);
    printf("\n");
}

/* Parse port mask */
static int
parse_portmask(const char *portmask_str, uint32_t *portmask)
{
    char *end = NULL;
    unsigned long pm;
    
    if (!portmask_str || !portmask) {
        return -EINVAL;
    }
    
    pm = strtoul(portmask_str, &end, 16);
    
    if (end == portmask_str || *end != '\0' || pm == 0) {
        RTE_LOG(ERR, CONFIG, "Invalid portmask: %s\n", portmask_str);
        return -EINVAL;
    }
    
    *portmask = (uint32_t)pm;
    return 0;
}

/* Parse number argument */
static int
parse_number(const char *str, uint32_t *value, uint32_t min_val, uint32_t max_val)
{
    char *end = NULL;
    unsigned long val;
    
    if (!str || !value) {
        return -EINVAL;
    }
    
    val = strtoul(str, &end, 10);
    
    if (end == str || *end != '\0') {
        return -EINVAL;
    }
    
    if (val < min_val || val > max_val) {
        RTE_LOG(ERR, CONFIG, "Value %lu out of range [%u, %u]\n", 
                val, min_val, max_val);
        return -ERANGE;
    }
    
    *value = (uint32_t)val;
    return 0;
}

/* Validate port mask against available ports */
static int
validate_portmask(uint32_t portmask)
{
    uint16_t portid;
    uint32_t valid_ports = 0;
    
    /* Get available ports */
    RTE_ETH_FOREACH_DEV(portid) {
        valid_ports |= (1 << portid);
    }
    
    /* Check if requested ports are available */
    if ((portmask & valid_ports) != portmask) {
        RTE_LOG(ERR, CONFIG, "Invalid portmask 0x%x, available ports: 0x%x\n",
                portmask, valid_ports);
        return -EINVAL;
    }
    
    return 0;
}

/* Count number of enabled ports */
static uint32_t
count_enabled_ports(uint32_t portmask)
{
    uint32_t count = 0;
    uint16_t portid;
    
    RTE_ETH_FOREACH_DEV(portid) {
        if ((portmask & (1 << portid)) != 0) {
            count++;
        }
    }
    
    return count;
}

/* Check NUMA configuration */
static bool
check_numa_support(void)
{
    unsigned socket_id;
    bool numa_available = false;
    
    RTE_LCORE_FOREACH(socket_id) {
        if (rte_lcore_to_socket_id(socket_id) > 0) {
            numa_available = true;
            break;
        }
    }
    
    return numa_available;
}

/* Load configuration from file */
static int
load_config_file(const char *filename, struct config_params *config)
{
    FILE *fp;
    char line[256];
    char key[64], value[192];
    int line_num = 0;
    
    if (!filename || !config) {
        return -EINVAL;
    }
    
    fp = fopen(filename, "r");
    if (fp == NULL) {
        RTE_LOG(ERR, CONFIG, "Failed to open config file: %s\n", filename);
        return -errno;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        
        /* Parse key=value pairs */
        if (sscanf(line, "%63[^=]=%191s", key, value) != 2) {
            RTE_LOG(WARNING, CONFIG, "Invalid line %d in config file: %s",
                    line_num, line);
            continue;
        }
        
        /* Process configuration options */
        if (strcmp(key, "portmask") == 0) {
            if (parse_portmask(value, &config->port_mask) != 0) {
                RTE_LOG(ERR, CONFIG, "Invalid portmask in config file: %s\n", value);
            }
        } else if (strcmp(key, "queues") == 0) {
            if (parse_number(value, &config->nb_queues, 1, 16) != 0) {
                RTE_LOG(ERR, CONFIG, "Invalid queues in config file: %s\n", value);
            }
        } else if (strcmp(key, "hash_entries") == 0) {
            if (parse_number(value, &config->hash_entries, 1024, 16777216) != 0) {
                RTE_LOG(ERR, CONFIG, "Invalid hash_entries in config file: %s\n", value);
            }
        } else if (strcmp(key, "numa") == 0) {
            config->numa_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "verbose") == 0) {
            config->verbose = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "stats_interval") == 0) {
            if (parse_number(value, &config->stats_interval, 1, 3600) != 0) {
                RTE_LOG(ERR, CONFIG, "Invalid stats_interval in config file: %s\n", value);
            }
        } else {
            RTE_LOG(WARNING, CONFIG, "Unknown configuration option: %s\n", key);
        }
    }
    
    fclose(fp);
    
    RTE_LOG(INFO, CONFIG, "Configuration loaded from %s\n", filename);
    return 0;
}

/* Parse command line arguments */
static int
parse_args(int argc, char **argv, struct config_params *config)
{
    int opt, option_index;
    const char *short_options = "p:q:h:nvr:c:s:H";
    
    if (!config) {
        return -EINVAL;
    }
    
    /* Set defaults */
    config->port_mask = DEFAULT_PORT_MASK;
    config->nb_queues = DEFAULT_NB_QUEUES;
    config->hash_entries = DEFAULT_HASH_ENTRIES;
    config->numa_enabled = false;
    config->verbose = false;
    config->rules_file = NULL;
    config->config_file = NULL;
    config->stats_interval = 5;
    
    /* Parse arguments */
    while ((opt = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
        switch (opt) {
        case 'p':
            if (parse_portmask(optarg, &config->port_mask) != 0) {
                return -EINVAL;
            }
            break;
            
        case 'q':
            if (parse_number(optarg, &config->nb_queues, 1, 16) != 0) {
                RTE_LOG(ERR, CONFIG, "Invalid number of queues: %s\n", optarg);
                return -EINVAL;
            }
            break;
            
        case 'h':
            if (parse_number(optarg, &config->hash_entries, 1024, 16777216) != 0) {
                RTE_LOG(ERR, CONFIG, "Invalid hash entries: %s\n", optarg);
                return -EINVAL;
            }
            break;
            
        case 'n':
            config->numa_enabled = true;
            break;
            
        case 'v':
            config->verbose = true;
            break;
            
        case 'r':
            config->rules_file = strdup(optarg);
            break;
            
        case 'c':
            config->config_file = strdup(optarg);
            break;
            
        case 's':
            if (parse_number(optarg, &config->stats_interval, 1, 3600) != 0) {
                RTE_LOG(ERR, CONFIG, "Invalid stats interval: %s\n", optarg);
                return -EINVAL;
            }
            break;
            
        case 'H':
            print_usage(argv[0]);
            exit(0);
            break;
            
        default:
            RTE_LOG(ERR, CONFIG, "Unknown option: %c\n", opt);
            print_usage(argv[0]);
            return -EINVAL;
        }
    }
    
    return 0;
}

/* Initialize configuration */
int
config_init(struct app_context *ctx, int argc, char **argv)
{
    int ret;
    
    if (!ctx) {
        RTE_LOG(ERR, CONFIG, "Invalid context\n");
        return -EINVAL;
    }
    
    /* Parse command line arguments */
    ret = parse_args(argc, argv, &g_config);
    if (ret != 0) {
        return ret;
    }
    
    /* Load configuration file if specified */
    if (g_config.config_file) {
        ret = load_config_file(g_config.config_file, &g_config);
        if (ret != 0) {
            return ret;
        }
    }
    
    /* Validate configuration */
    ret = validate_portmask(g_config.port_mask);
    if (ret != 0) {
        return ret;
    }
    
    /* Check NUMA support */
    if (g_config.numa_enabled && !check_numa_support()) {
        RTE_LOG(WARNING, CONFIG, "NUMA requested but not available, disabling\n");
        g_config.numa_enabled = false;
    }
    
    /* Apply configuration to context */
    ctx->enabled_port_mask = g_config.port_mask;
    ctx->nb_ports = count_enabled_ports(g_config.port_mask);
    ctx->nb_lcores = rte_lcore_count();
    ctx->numa_on = g_config.numa_enabled;
    
    /* Configure logging if verbose */
    if (g_config.verbose) {
        rte_log_set_global_level(RTE_LOG_DEBUG);
    }
    
    /* Configure statistics collection */
    stats_collector_configure(true, g_config.stats_interval);
    
    /* Print configuration summary */
    RTE_LOG(INFO, CONFIG, "Configuration summary:\n");
    RTE_LOG(INFO, CONFIG, "  Port mask:      0x%x (%u ports)\n", 
            ctx->enabled_port_mask, ctx->nb_ports);
    RTE_LOG(INFO, CONFIG, "  Queues per port: %u\n", g_config.nb_queues);
    RTE_LOG(INFO, CONFIG, "  Hash entries:   %u\n", g_config.hash_entries);
    RTE_LOG(INFO, CONFIG, "  NUMA enabled:   %s\n", ctx->numa_on ? "yes" : "no");
    RTE_LOG(INFO, CONFIG, "  Verbose mode:   %s\n", g_config.verbose ? "yes" : "no");
    RTE_LOG(INFO, CONFIG, "  Stats interval: %u seconds\n", g_config.stats_interval);
    RTE_LOG(INFO, CONFIG, "  Number of lcores: %u\n", ctx->nb_lcores);
    
    if (g_config.rules_file) {
        RTE_LOG(INFO, CONFIG, "  Rules file:     %s\n", g_config.rules_file);
    }
    
    return 0;
}

/* Destroy configuration */
void
config_destroy(struct app_context *ctx)
{
    RTE_SET_USED(ctx);
    
    /* Free allocated strings */
    if (g_config.rules_file) {
        free(g_config.rules_file);
        g_config.rules_file = NULL;
    }
    
    if (g_config.config_file) {
        free(g_config.config_file);
        g_config.config_file = NULL;
    }
    
    /* Clear configuration */
    memset(&g_config, 0, sizeof(g_config));
    
    RTE_LOG(INFO, CONFIG, "Configuration destroyed\n");
}

/* Get configuration parameters */
const struct config_params *
config_get_params(void)
{
    return &g_config;
}

/* Update configuration at runtime */
int
config_update_stats_interval(uint32_t interval_seconds)
{
    if (interval_seconds == 0 || interval_seconds > 3600) {
        return -EINVAL;
    }
    
    g_config.stats_interval = interval_seconds;
    stats_collector_configure(true, interval_seconds);
    
    RTE_LOG(INFO, CONFIG, "Statistics interval updated to %u seconds\n", 
            interval_seconds);
    
    return 0;
}

/* Enable/disable verbose mode */
int
config_set_verbose(bool verbose)
{
    g_config.verbose = verbose;
    
    if (verbose) {
        rte_log_set_global_level(RTE_LOG_DEBUG);
    } else {
        rte_log_set_global_level(RTE_LOG_INFO);
    }
    
    RTE_LOG(INFO, CONFIG, "Verbose mode %s\n", verbose ? "enabled" : "disabled");
    
    return 0;
}

/* Save current configuration to file */
int
config_save_to_file(const char *filename)
{
    FILE *fp;
    
    if (!filename) {
        return -EINVAL;
    }
    
    fp = fopen(filename, "w");
    if (fp == NULL) {
        RTE_LOG(ERR, CONFIG, "Failed to open file for writing: %s\n", filename);
        return -errno;
    }
    
    fprintf(fp, "# DPDK Tuple Filter Configuration\n");
    fprintf(fp, "# Generated automatically\n\n");
    fprintf(fp, "portmask=0x%x\n", g_config.port_mask);
    fprintf(fp, "queues=%u\n", g_config.nb_queues);
    fprintf(fp, "hash_entries=%u\n", g_config.hash_entries);
    fprintf(fp, "numa=%s\n", g_config.numa_enabled ? "true" : "false");
    fprintf(fp, "verbose=%s\n", g_config.verbose ? "true" : "false");
    fprintf(fp, "stats_interval=%u\n", g_config.stats_interval);
    
    fclose(fp);
    
    RTE_LOG(INFO, CONFIG, "Configuration saved to %s\n", filename);
    
    return 0;
}