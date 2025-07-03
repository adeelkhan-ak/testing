#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "tuple_filter.h"

#define RTE_LOGTYPE_TUPLE_FILTER RTE_LOGTYPE_USER1

/* Global application context */
static struct app_context g_app_ctx;
static volatile bool force_quit = false;

/* Port configuration */
static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
    },
};

/* Signal handler */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* Initialize memory pools */
static int
init_mem_pools(struct app_context *ctx)
{
    unsigned lcore_id, socket_id;
    char name[64];
    
    /* Create packet mbuf pool */
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (!rte_lcore_is_enabled(lcore_id))
            continue;
            
        socket_id = rte_lcore_to_socket_id(lcore_id);
        snprintf(name, sizeof(name), "mbuf_pool_%u", socket_id);
        
        ctx->pktmbuf_pool = rte_pktmbuf_pool_create(name,
            8192, MEMPOOL_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
            
        if (ctx->pktmbuf_pool == NULL) {
            RTE_LOG(ERR, TUPLE_FILTER,
                "Cannot create mbuf pool on socket %u\n", socket_id);
            return -1;
        }
        break; /* Use first enabled lcore's socket */
    }
    
    return 0;
}

/* Initialize network ports */
static int
init_ports(struct app_context *ctx)
{
    uint16_t portid;
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    
    RTE_ETH_FOREACH_DEV(portid) {
        if ((ctx->enabled_port_mask & (1 << portid)) == 0)
            continue;
            
        printf("Initializing port %u... ", portid);
        fflush(stdout);
        
        /* Get device info */
        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0) {
            printf("Error getting device info for port %u: %s\n",
                   portid, strerror(-ret));
            return ret;
        }
        
        /* Configure the Ethernet device */
        ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
        if (ret < 0) {
            printf("Cannot configure device: err=%d, port=%u\n",
                   ret, portid);
            return ret;
        }
        
        /* Setup RX queue */
        ret = rte_eth_rx_queue_setup(portid, 0, RTE_TEST_RX_DESC_DEFAULT,
                                   rte_eth_dev_socket_id(portid),
                                   NULL, ctx->pktmbuf_pool);
        if (ret < 0) {
            printf("rte_eth_rx_queue_setup: err=%d, port=%u\n",
                   ret, portid);
            return ret;
        }
        
        /* Setup TX queue */
        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, 0, RTE_TEST_TX_DESC_DEFAULT,
                                   rte_eth_dev_socket_id(portid), &txconf);
        if (ret < 0) {
            printf("rte_eth_tx_queue_setup: err=%d, port=%u\n",
                   ret, portid);
            return ret;
        }
        
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0) {
            printf("rte_eth_dev_start: err=%d, port=%u\n",
                   ret, portid);
            return ret;
        }
        
        /* Enable promiscuous mode */
        ret = rte_eth_promiscuous_enable(portid);
        if (ret != 0) {
            printf("rte_eth_promiscuous_enable: err=%s, port=%u\n",
                   rte_strerror(-ret), portid);
            return ret;
        }
        
        printf("done\n");
    }
    
    return 0;
}

/* Main packet processing loop for worker lcores */
static int
lcore_main_loop(void *arg)
{
    struct app_context *ctx = (struct app_context *)arg;
    unsigned lcore_id = rte_lcore_id();
    uint16_t portid;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint16_t nb_rx;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + 1000000 - 1) / 1000000 *
                               BURST_TX_DRAIN_US;
    
    prev_tsc = 0;
    timer_tsc = 0;
    
    RTE_LOG(INFO, TUPLE_FILTER, "Entering main loop on lcore %u\n", lcore_id);
    
    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        
        /* Read packets from all ports assigned to this lcore */
        RTE_ETH_FOREACH_DEV(portid) {
            if ((ctx->enabled_port_mask & (1 << portid)) == 0)
                continue;
                
            nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
            
            if (nb_rx == 0)
                continue;
                
            /* Process packets through tuple filter */
            uint16_t nb_processed = process_packets(pkts_burst, nb_rx, ctx, lcore_id);
            
            /* Update statistics */
            STATS_UPDATE(ctx, lcore_id, rx_packets, nb_rx);
            STATS_UPDATE(ctx, lcore_id, tx_packets, nb_processed);
            STATS_UPDATE(ctx, lcore_id, dropped_packets, nb_rx - nb_processed);
        }
        
        /* Print statistics periodically */
        if (unlikely(diff_tsc > drain_tsc)) {
            if (timer_tsc >= rte_get_tsc_hz()) {
                if (lcore_id == rte_get_main_lcore()) {
                    stats_collector_print(ctx);
                }
                timer_tsc = 0;
            } else {
                timer_tsc += diff_tsc;
            }
            prev_tsc = cur_tsc;
        }
    }
    
    return 0;
}

/* Initialize default filter rules for testing */
static int
init_default_rules(struct app_context *ctx)
{
    struct filter_rule rule;
    int ret;
    
    /* Add some sample rules */
    memset(&rule, 0, sizeof(rule));
    
    /* Rule 1: Block traffic from 192.168.1.0/24 */
    rule.tuple.src_ip = rte_cpu_to_be_32(0xC0A80100); /* 192.168.1.0 */
    rule.tuple.dst_ip = 0; /* Any destination */
    rule.tuple.src_port = 0; /* Any source port */
    rule.tuple.dst_port = 0; /* Any destination port */
    rule.tuple.proto = 0; /* Any protocol */
    rule.action = ACTION_DROP;
    rule.priority = 10;
    rule.rule_id = 1;
    
    ret = rule_manager_add(ctx, &rule);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to add rule 1\n");
        return ret;
    }
    
    /* Rule 2: Allow HTTP traffic */
    memset(&rule, 0, sizeof(rule));
    rule.tuple.src_ip = 0; /* Any source */
    rule.tuple.dst_ip = 0; /* Any destination */
    rule.tuple.src_port = 0; /* Any source port */
    rule.tuple.dst_port = rte_cpu_to_be_16(80); /* HTTP port */
    rule.tuple.proto = IPPROTO_TCP;
    rule.action = ACTION_ACCEPT;
    rule.priority = 5;
    rule.rule_id = 2;
    
    ret = rule_manager_add(ctx, &rule);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to add rule 2\n");
        return ret;
    }
    
    /* Rule 3: Allow HTTPS traffic */
    rule.tuple.dst_port = rte_cpu_to_be_16(443); /* HTTPS port */
    rule.rule_id = 3;
    
    ret = rule_manager_add(ctx, &rule);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to add rule 3\n");
        return ret;
    }
    
    printf("Added %d default filter rules\n", 3);
    return 0;
}

/* Application initialization */
static int
app_init(struct app_context *ctx, int argc, char **argv)
{
    struct hash_config hash_config;
    int ret;
    
    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));
    
    /* Initialize configuration */
    ret = config_init(ctx, argc, argv);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize configuration\n");
        return ret;
    }
    
    /* Initialize memory pools */
    ret = init_mem_pools(ctx);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize memory pools\n");
        return ret;
    }
    
    /* Initialize hash table */
    hash_config.entries = HASH_ENTRIES;
    hash_config.key_len = sizeof(struct five_tuple);
    hash_config.hash_type = HASH_TYPE;
    hash_config.socket_id = SOCKET_ID_ANY;
    
    ret = tuple_hash_init(ctx, &hash_config);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize hash table\n");
        return ret;
    }
    
    /* Initialize packet processor */
    ret = packet_processor_init(ctx);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize packet processor\n");
        return ret;
    }
    
    /* Initialize rule manager */
    ret = rule_manager_init(ctx);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize rule manager\n");
        return ret;
    }
    
    /* Initialize statistics collector */
    ret = stats_collector_init(ctx);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize stats collector\n");
        return ret;
    }
    
    /* Initialize network ports */
    ret = init_ports(ctx);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize ports\n");
        return ret;
    }
    
    /* Add default rules */
    ret = init_default_rules(ctx);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Failed to initialize default rules\n");
        return ret;
    }
    
    return 0;
}

/* Application cleanup */
static void
app_cleanup(struct app_context *ctx)
{
    uint16_t portid;
    int ret;
    
    /* Stop and close all ports */
    RTE_ETH_FOREACH_DEV(portid) {
        if ((ctx->enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    
    /* Cleanup components */
    stats_collector_destroy(ctx);
    rule_manager_destroy(ctx);
    packet_processor_destroy(ctx);
    tuple_hash_destroy(ctx);
    config_destroy(ctx);
    
    printf("\nApplication cleanup completed.\n");
}

/* Main function */
int
main(int argc, char **argv)
{
    int ret;
    unsigned lcore_id;
    
    /* Initialize DPDK EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    
    argc -= ret;
    argv += ret;
    
    /* Install signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Initialize application */
    ret = app_init(&g_app_ctx, argc, argv);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_FILTER, "Application initialization failed\n");
        return -1;
    }
    
    printf("\nTuple Filter Application Started\n");
    printf("================================\n");
    printf("Number of ports: %u\n", g_app_ctx.nb_ports);
    printf("Number of lcores: %u\n", g_app_ctx.nb_lcores);
    printf("Port mask: 0x%x\n", g_app_ctx.enabled_port_mask);
    printf("NUMA support: %s\n", g_app_ctx.numa_on ? "enabled" : "disabled");
    printf("\nPress Ctrl+C to exit...\n\n");
    
    /* Launch workers on slave lcores */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_main_loop, &g_app_ctx, lcore_id);
    }
    
    /* Run main loop on main lcore */
    lcore_main_loop(&g_app_ctx);
    
    /* Wait for workers to finish */
    rte_eal_mp_wait_lcore();
    
    /* Cleanup and exit */
    app_cleanup(&g_app_ctx);
    
    /* Clean up EAL */
    rte_eal_cleanup();
    
    return 0;
}