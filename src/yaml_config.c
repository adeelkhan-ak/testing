#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <yaml.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

#include "tuple_filter.h"
#include "yaml_config.h"

#define RTE_LOGTYPE_YAML_CONFIG RTE_LOGTYPE_USER7

/* YAML configuration context */
struct yaml_config_ctx {
    yaml_parser_t parser;
    yaml_document_t document;
    struct yaml_config *config;
    bool document_loaded;
};

/* Helper function to get node value as string */
static const char *
yaml_get_node_value(yaml_document_t *document, yaml_node_t *node)
{
    if (node->type == YAML_SCALAR_NODE) {
        return (const char *)node->data.scalar.value;
    }
    return NULL;
}

/* Helper function to find child node by key */
static yaml_node_t *
yaml_find_child_node(yaml_document_t *document, yaml_node_t *parent, const char *key)
{
    yaml_node_pair_t *pair;
    yaml_node_t *key_node, *value_node;
    
    if (parent->type != YAML_MAPPING_NODE) {
        return NULL;
    }
    
    for (pair = parent->data.mapping.pairs.start;
         pair < parent->data.mapping.pairs.top; pair++) {
        key_node = yaml_document_get_node(document, pair->key);
        if (key_node && key_node->type == YAML_SCALAR_NODE) {
            if (strcmp((char *)key_node->data.scalar.value, key) == 0) {
                value_node = yaml_document_get_node(document, pair->value);
                return value_node;
            }
        }
    }
    
    return NULL;
}

/* Parse IP address and netmask */
static int
parse_ip_address(const char *ip_str, uint32_t *ip, uint32_t *mask)
{
    char *slash_pos;
    char ip_copy[64];
    int prefix_len = 32;
    
    if (!ip_str || !ip || !mask) {
        return -EINVAL;
    }
    
    /* Handle wildcard */
    if (strcmp(ip_str, "*") == 0) {
        *ip = 0;
        *mask = 0;
        return 0;
    }
    
    strncpy(ip_copy, ip_str, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';
    
    /* Check for CIDR notation */
    slash_pos = strchr(ip_copy, '/');
    if (slash_pos) {
        *slash_pos = '\0';
        prefix_len = atoi(slash_pos + 1);
        if (prefix_len < 0 || prefix_len > 32) {
            return -EINVAL;
        }
    }
    
    /* Parse IP address */
    if (inet_pton(AF_INET, ip_copy, ip) != 1) {
        return -EINVAL;
    }
    
    /* Calculate mask */
    if (prefix_len == 32) {
        *mask = 0xFFFFFFFF;
    } else if (prefix_len == 0) {
        *mask = 0;
    } else {
        *mask = htonl(~((1 << (32 - prefix_len)) - 1));
    }
    
    return 0;
}

/* Parse port specification */
static int
parse_port(const char *port_str, uint16_t *port)
{
    int port_val;
    
    if (!port_str || !port) {
        return -EINVAL;
    }
    
    /* Handle wildcard */
    if (strcmp(port_str, "*") == 0) {
        *port = 0;
        return 0;
    }
    
    port_val = atoi(port_str);
    if (port_val < 0 || port_val > 65535) {
        return -EINVAL;
    }
    
    *port = htons((uint16_t)port_val);
    return 0;
}

/* Parse protocol */
static int
parse_protocol(const char *proto_str, uint8_t *proto)
{
    if (!proto_str || !proto) {
        return -EINVAL;
    }
    
    if (strcmp(proto_str, "*") == 0) {
        *proto = 0;
    } else if (strcmp(proto_str, "tcp") == 0) {
        *proto = IPPROTO_TCP;
    } else if (strcmp(proto_str, "udp") == 0) {
        *proto = IPPROTO_UDP;
    } else if (strcmp(proto_str, "icmp") == 0) {
        *proto = IPPROTO_ICMP;
    } else {
        int proto_val = atoi(proto_str);
        if (proto_val < 0 || proto_val > 255) {
            return -EINVAL;
        }
        *proto = (uint8_t)proto_val;
    }
    
    return 0;
}

/* Parse ports section */
static int
parse_ports_section(yaml_document_t *document, yaml_node_t *ports_node, struct yaml_config *config)
{
    yaml_node_item_t *item;
    yaml_node_t *port_node, *child_node;
    struct yaml_port_config *port_config;
    const char *value;
    int port_idx = 0;
    
    if (ports_node->type != YAML_SEQUENCE_NODE) {
        RTE_LOG(ERR, YAML_CONFIG, "Ports section must be a sequence\n");
        return -EINVAL;
    }
    
    for (item = ports_node->data.sequence.items.start;
         item < ports_node->data.sequence.items.top && port_idx < MAX_YAML_PORTS;
         item++, port_idx++) {
        
        port_node = yaml_document_get_node(document, *item);
        if (!port_node || port_node->type != YAML_MAPPING_NODE) {
            continue;
        }
        
        port_config = &config->ports[port_idx];
        
        /* Parse port ID */
        child_node = yaml_find_child_node(document, port_node, "id");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                strncpy(port_config->id, value, sizeof(port_config->id) - 1);
            }
        }
        
        /* Parse PCI address */
        child_node = yaml_find_child_node(document, port_node, "pci_address");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                strncpy(port_config->pci_address, value, sizeof(port_config->pci_address) - 1);
            }
        }
        
        /* Parse MAC address */
        child_node = yaml_find_child_node(document, port_node, "mac_address");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                strncpy(port_config->mac_address, value, sizeof(port_config->mac_address) - 1);
            }
        }
        
        /* Parse description */
        child_node = yaml_find_child_node(document, port_node, "description");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                strncpy(port_config->description, value, sizeof(port_config->description) - 1);
            }
        }
        
        config->num_ports++;
    }
    
    return 0;
}

/* Parse CPU cores section */
static int
parse_cpu_cores_section(yaml_document_t *document, yaml_node_t *cpu_cores_node, struct yaml_config *config)
{
    yaml_node_t *rx_cores_node, *tx_cores_node;
    yaml_node_item_t *item;
    yaml_node_t *core_node, *child_node;
    struct yaml_core_config *core_config;
    const char *value;
    int core_idx;
    
    /* Parse RX cores */
    rx_cores_node = yaml_find_child_node(document, cpu_cores_node, "rx_cores");
    if (rx_cores_node && rx_cores_node->type == YAML_SEQUENCE_NODE) {
        core_idx = 0;
        for (item = rx_cores_node->data.sequence.items.start;
             item < rx_cores_node->data.sequence.items.top && core_idx < MAX_YAML_CORES;
             item++, core_idx++) {
            
            core_node = yaml_document_get_node(document, *item);
            if (!core_node || core_node->type != YAML_MAPPING_NODE) {
                continue;
            }
            
            core_config = &config->rx_cores[core_idx];
            
            /* Parse port */
            child_node = yaml_find_child_node(document, core_node, "port");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    strncpy(core_config->port, value, sizeof(core_config->port) - 1);
                }
            }
            
            /* Parse queue */
            child_node = yaml_find_child_node(document, core_node, "queue");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    core_config->queue = atoi(value);
                }
            }
            
            /* Parse core */
            child_node = yaml_find_child_node(document, core_node, "core");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    core_config->core = atoi(value);
                }
            }
            
            config->num_rx_cores++;
        }
    }
    
    /* Parse TX cores */
    tx_cores_node = yaml_find_child_node(document, cpu_cores_node, "tx_cores");
    if (tx_cores_node && tx_cores_node->type == YAML_SEQUENCE_NODE) {
        core_idx = 0;
        for (item = tx_cores_node->data.sequence.items.start;
             item < tx_cores_node->data.sequence.items.top && core_idx < MAX_YAML_CORES;
             item++, core_idx++) {
            
            core_node = yaml_document_get_node(document, *item);
            if (!core_node || core_node->type != YAML_MAPPING_NODE) {
                continue;
            }
            
            core_config = &config->tx_cores[core_idx];
            
            /* Parse port */
            child_node = yaml_find_child_node(document, core_node, "port");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    strncpy(core_config->port, value, sizeof(core_config->port) - 1);
                }
            }
            
            /* Parse queue */
            child_node = yaml_find_child_node(document, core_node, "queue");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    core_config->queue = atoi(value);
                }
            }
            
            /* Parse core */
            child_node = yaml_find_child_node(document, core_node, "core");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    core_config->core = atoi(value);
                }
            }
            
            config->num_tx_cores++;
        }
    }
    
    return 0;
}

/* Parse rules section */
static int
parse_rules_section(yaml_document_t *document, yaml_node_t *rules_node, struct yaml_config *config)
{
    yaml_node_item_t *item;
    yaml_node_t *rule_node, *match_node, *child_node;
    struct yaml_rule_config *rule_config;
    const char *value;
    int rule_idx = 0;
    
    if (rules_node->type != YAML_SEQUENCE_NODE) {
        RTE_LOG(ERR, YAML_CONFIG, "Rules section must be a sequence\n");
        return -EINVAL;
    }
    
    for (item = rules_node->data.sequence.items.start;
         item < rules_node->data.sequence.items.top && rule_idx < MAX_YAML_RULES;
         item++, rule_idx++) {
        
        rule_node = yaml_document_get_node(document, *item);
        if (!rule_node || rule_node->type != YAML_MAPPING_NODE) {
            continue;
        }
        
        rule_config = &config->rules[rule_idx];
        
        /* Parse rule ID */
        child_node = yaml_find_child_node(document, rule_node, "id");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                strncpy(rule_config->id, value, sizeof(rule_config->id) - 1);
            }
        }
        
        /* Parse priority */
        child_node = yaml_find_child_node(document, rule_node, "priority");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                rule_config->priority = atoi(value);
            }
        }
        
        /* Parse match section */
        match_node = yaml_find_child_node(document, rule_node, "match");
        if (match_node && match_node->type == YAML_MAPPING_NODE) {
            /* Parse source IP */
            child_node = yaml_find_child_node(document, match_node, "src_ip");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    parse_ip_address(value, &rule_config->src_ip, &rule_config->src_ip_mask);
                }
            }
            
            /* Parse destination IP */
            child_node = yaml_find_child_node(document, match_node, "dst_ip");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    parse_ip_address(value, &rule_config->dst_ip, &rule_config->dst_ip_mask);
                }
            }
            
            /* Parse source port */
            child_node = yaml_find_child_node(document, match_node, "src_port");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    parse_port(value, &rule_config->src_port);
                }
            }
            
            /* Parse destination port */
            child_node = yaml_find_child_node(document, match_node, "dst_port");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    parse_port(value, &rule_config->dst_port);
                }
            }
            
            /* Parse protocol */
            child_node = yaml_find_child_node(document, match_node, "protocol");
            if (child_node) {
                value = yaml_get_node_value(document, child_node);
                if (value) {
                    parse_protocol(value, &rule_config->protocol);
                }
            }
        }
        
        /* Parse action */
        child_node = yaml_find_child_node(document, rule_node, "action");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                if (strcmp(value, "drop") == 0) {
                    rule_config->action = ACTION_DROP;
                } else if (strcmp(value, "forward") == 0) {
                    rule_config->action = ACTION_FORWARD;
                } else {
                    rule_config->action = ACTION_ACCEPT;
                }
            }
        }
        
        /* Parse output port */
        child_node = yaml_find_child_node(document, rule_node, "out_port");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                strncpy(rule_config->out_port, value, sizeof(rule_config->out_port) - 1);
            }
        }
        
        /* Parse description */
        child_node = yaml_find_child_node(document, rule_node, "description");
        if (child_node) {
            value = yaml_get_node_value(document, child_node);
            if (value) {
                strncpy(rule_config->description, value, sizeof(rule_config->description) - 1);
            }
        }
        
        config->num_rules++;
    }
    
    return 0;
}

/* Parse global settings section */
static int
parse_global_settings_section(yaml_document_t *document, yaml_node_t *global_node, struct yaml_config *config)
{
    yaml_node_t *child_node;
    const char *value;
    
    /* Parse RX burst size */
    child_node = yaml_find_child_node(document, global_node, "rx_burst_size");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.rx_burst_size = atoi(value);
        }
    }
    
    /* Parse TX burst size */
    child_node = yaml_find_child_node(document, global_node, "tx_burst_size");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.tx_burst_size = atoi(value);
        }
    }
    
    /* Parse number of mbufs */
    child_node = yaml_find_child_node(document, global_node, "num_mbufs");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.num_mbufs = atoi(value);
        }
    }
    
    /* Parse NUMA enable */
    child_node = yaml_find_child_node(document, global_node, "enable_numa");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.enable_numa = (strcmp(value, "true") == 0);
        }
    }
    
    /* Parse other settings... */
    child_node = yaml_find_child_node(document, global_node, "mbuf_size");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.mbuf_size = atoi(value);
        }
    }
    
    child_node = yaml_find_child_node(document, global_node, "mbuf_cache_size");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.mbuf_cache_size = atoi(value);
        }
    }
    
    child_node = yaml_find_child_node(document, global_node, "rx_queues_per_port");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.rx_queues_per_port = atoi(value);
        }
    }
    
    child_node = yaml_find_child_node(document, global_node, "tx_queues_per_port");
    if (child_node) {
        value = yaml_get_node_value(document, child_node);
        if (value) {
            config->global_settings.tx_queues_per_port = atoi(value);
        }
    }
    
    return 0;
}

/* Load YAML configuration from file */
int
yaml_config_load(const char *filename, struct yaml_config *config)
{
    struct yaml_config_ctx ctx;
    FILE *file;
    yaml_node_t *root, *child_node;
    int ret = 0;
    
    if (!filename || !config) {
        return -EINVAL;
    }
    
    memset(&ctx, 0, sizeof(ctx));
    memset(config, 0, sizeof(*config));
    
    /* Open file */
    file = fopen(filename, "r");
    if (!file) {
        RTE_LOG(ERR, YAML_CONFIG, "Failed to open YAML file: %s\n", filename);
        return -errno;
    }
    
    /* Initialize YAML parser */
    if (!yaml_parser_initialize(&ctx.parser)) {
        RTE_LOG(ERR, YAML_CONFIG, "Failed to initialize YAML parser\n");
        fclose(file);
        return -ENOMEM;
    }
    
    /* Set input file */
    yaml_parser_set_input_file(&ctx.parser, file);
    
    /* Load document */
    if (!yaml_parser_load(&ctx.parser, &ctx.document)) {
        RTE_LOG(ERR, YAML_CONFIG, "Failed to load YAML document\n");
        ret = -EINVAL;
        goto cleanup;
    }
    
    ctx.document_loaded = true;
    
    /* Get root node */
    root = yaml_document_get_root_node(&ctx.document);
    if (!root) {
        RTE_LOG(ERR, YAML_CONFIG, "Failed to get root node\n");
        ret = -EINVAL;
        goto cleanup;
    }
    
    /* Parse ports section */
    child_node = yaml_find_child_node(&ctx.document, root, "ports");
    if (child_node) {
        ret = parse_ports_section(&ctx.document, child_node, config);
        if (ret < 0) {
            RTE_LOG(ERR, YAML_CONFIG, "Failed to parse ports section\n");
            goto cleanup;
        }
    }
    
    /* Parse CPU cores section */
    child_node = yaml_find_child_node(&ctx.document, root, "cpu_cores");
    if (child_node) {
        ret = parse_cpu_cores_section(&ctx.document, child_node, config);
        if (ret < 0) {
            RTE_LOG(ERR, YAML_CONFIG, "Failed to parse CPU cores section\n");
            goto cleanup;
        }
    }
    
    /* Parse rules section */
    child_node = yaml_find_child_node(&ctx.document, root, "rules");
    if (child_node) {
        ret = parse_rules_section(&ctx.document, child_node, config);
        if (ret < 0) {
            RTE_LOG(ERR, YAML_CONFIG, "Failed to parse rules section\n");
            goto cleanup;
        }
    }
    
    /* Parse global settings section */
    child_node = yaml_find_child_node(&ctx.document, root, "global_settings");
    if (child_node) {
        ret = parse_global_settings_section(&ctx.document, child_node, config);
        if (ret < 0) {
            RTE_LOG(ERR, YAML_CONFIG, "Failed to parse global settings section\n");
            goto cleanup;
        }
    }
    
    RTE_LOG(INFO, YAML_CONFIG, "Successfully loaded YAML configuration:\n");
    RTE_LOG(INFO, YAML_CONFIG, "  Ports: %d\n", config->num_ports);
    RTE_LOG(INFO, YAML_CONFIG, "  RX Cores: %d\n", config->num_rx_cores);
    RTE_LOG(INFO, YAML_CONFIG, "  TX Cores: %d\n", config->num_tx_cores);
    RTE_LOG(INFO, YAML_CONFIG, "  Rules: %d\n", config->num_rules);
    
cleanup:
    if (ctx.document_loaded) {
        yaml_document_delete(&ctx.document);
    }
    yaml_parser_delete(&ctx.parser);
    fclose(file);
    
    return ret;
}

/* Free YAML configuration */
void
yaml_config_free(struct yaml_config *config)
{
    if (config) {
        memset(config, 0, sizeof(*config));
    }
}

/* Apply YAML configuration to app context */
int
yaml_config_apply(struct yaml_config *yaml_config, struct app_context *ctx)
{
    struct filter_rule rule;
    int i, ret;
    
    if (!yaml_config || !ctx) {
        return -EINVAL;
    }
    
    /* Apply global settings */
    if (yaml_config->global_settings.enable_numa) {
        ctx->numa_on = true;
    }
    
    /* Convert and add rules */
    for (i = 0; i < yaml_config->num_rules; i++) {
        struct yaml_rule_config *yaml_rule = &yaml_config->rules[i];
        
        memset(&rule, 0, sizeof(rule));
        
        /* Convert tuple */
        rule.tuple.src_ip = yaml_rule->src_ip;
        rule.tuple.dst_ip = yaml_rule->dst_ip;
        rule.tuple.src_port = yaml_rule->src_port;
        rule.tuple.dst_port = yaml_rule->dst_port;
        rule.tuple.proto = yaml_rule->protocol;
        
        /* Set action */
        rule.action = yaml_rule->action;
        rule.priority = yaml_rule->priority;
        rule.rule_id = i + 1;
        
        /* Add rule to manager */
        ret = rule_manager_add(ctx, &rule);
        if (ret < 0) {
            RTE_LOG(ERR, YAML_CONFIG, "Failed to add rule %s\n", yaml_rule->id);
            return ret;
        }
    }
    
    RTE_LOG(INFO, YAML_CONFIG, "Applied %d rules from YAML configuration\n", 
            yaml_config->num_rules);
    
    return 0;
}