#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_ethdev.h>

#include "tuple_filter.h"

#define RTE_LOGTYPE_STATS_COLLECTOR RTE_LOGTYPE_USER5

/* Global statistics collection interval (seconds) */
#define STATS_COLLECTION_INTERVAL 5

/* Extended statistics structure */
struct extended_stats {
    /* Packet processing statistics */
    uint64_t total_cycles;
    uint64_t avg_cycles_per_packet;
    uint64_t min_cycles_per_packet;
    uint64_t max_cycles_per_packet;
    
    /* Hash table statistics */
    uint64_t hash_lookups;
    uint64_t hash_hits;
    uint64_t hash_misses;
    uint64_t hash_collisions;
    
    /* Memory statistics */
    uint64_t memory_used;
    uint64_t memory_peak;
    
    /* Throughput statistics */
    double packets_per_sec;
    double bits_per_sec;
    double gbps;
    
    /* Latency statistics (in nanoseconds) */
    uint64_t avg_latency_ns;
    uint64_t min_latency_ns;
    uint64_t max_latency_ns;
} __rte_cache_aligned;

/* Per-lcore extended statistics */
static struct extended_stats g_ext_stats[RTE_MAX_LCORE];

/* Global statistics collection context */
struct stats_collector_ctx {
    uint64_t start_time;
    uint64_t last_collection_time;
    uint64_t collection_count;
    bool enabled;
    uint32_t collection_interval;
} __rte_cache_aligned;

static struct stats_collector_ctx g_stats_ctx;

/* Initialize statistics collector */
int
stats_collector_init(struct app_context *ctx)
{
    if (!ctx) {
        RTE_LOG(ERR, STATS_COLLECTOR, "Invalid context\n");
        return -EINVAL;
    }
    
    /* Initialize context */
    memset(&g_stats_ctx, 0, sizeof(g_stats_ctx));
    memset(g_ext_stats, 0, sizeof(g_ext_stats));
    
    g_stats_ctx.start_time = rte_rdtsc();
    g_stats_ctx.last_collection_time = g_stats_ctx.start_time;
    g_stats_ctx.enabled = true;
    g_stats_ctx.collection_interval = STATS_COLLECTION_INTERVAL;
    
    /* Initialize min values */
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        g_ext_stats[lcore_id].min_cycles_per_packet = UINT64_MAX;
        g_ext_stats[lcore_id].min_latency_ns = UINT64_MAX;
    }
    
    RTE_LOG(INFO, STATS_COLLECTOR, "Statistics collector initialized\n");
    return 0;
}

/* Destroy statistics collector */
void
stats_collector_destroy(struct app_context *ctx)
{
    RTE_UNUSED(ctx);
    
    g_stats_ctx.enabled = false;
    memset(&g_stats_ctx, 0, sizeof(g_stats_ctx));
    memset(g_ext_stats, 0, sizeof(g_ext_stats));
    
    RTE_LOG(INFO, STATS_COLLECTOR, "Statistics collector destroyed\n");
}

/* Update statistics for a specific lcore */
void
stats_collector_update(struct app_context *ctx, unsigned lcore_id,
                      uint64_t rx_pkts, uint64_t tx_pkts, uint64_t dropped)
{
    RTE_UNUSED(ctx);
    
    if (!g_stats_ctx.enabled || lcore_id >= RTE_MAX_LCORE) {
        return;
    }
    
    /* Update basic packet counters */
    struct lcore_stats *stats = &ctx->stats[lcore_id];
    stats->rx_packets += rx_pkts;
    stats->tx_packets += tx_pkts;
    stats->dropped_packets += dropped;
}

/* Update processing time statistics */
void
stats_collector_update_cycles(unsigned lcore_id, uint64_t cycles, uint64_t packets)
{
    if (!g_stats_ctx.enabled || lcore_id >= RTE_MAX_LCORE || packets == 0) {
        return;
    }
    
    struct extended_stats *ext_stats = &g_ext_stats[lcore_id];
    uint64_t cycles_per_packet = cycles / packets;
    
    /* Update cycle statistics */
    ext_stats->total_cycles += cycles;
    ext_stats->avg_cycles_per_packet = 
        (ext_stats->avg_cycles_per_packet + cycles_per_packet) / 2;
    
    if (cycles_per_packet < ext_stats->min_cycles_per_packet) {
        ext_stats->min_cycles_per_packet = cycles_per_packet;
    }
    
    if (cycles_per_packet > ext_stats->max_cycles_per_packet) {
        ext_stats->max_cycles_per_packet = cycles_per_packet;
    }
}

/* Update hash table statistics */
void
stats_collector_update_hash_stats(unsigned lcore_id, uint64_t lookups,
                                 uint64_t hits, uint64_t misses)
{
    if (!g_stats_ctx.enabled || lcore_id >= RTE_MAX_LCORE) {
        return;
    }
    
    struct extended_stats *ext_stats = &g_ext_stats[lcore_id];
    
    ext_stats->hash_lookups += lookups;
    ext_stats->hash_hits += hits;
    ext_stats->hash_misses += misses;
}

/* Calculate throughput statistics */
static void
calculate_throughput_stats(struct app_context *ctx)
{
    uint64_t current_time = rte_rdtsc();
    uint64_t time_diff = current_time - g_stats_ctx.last_collection_time;
    double time_seconds = (double)time_diff / rte_get_tsc_hz();
    
    if (time_seconds <= 0) {
        return;
    }
    
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        if (!rte_lcore_is_enabled(lcore_id)) {
            continue;
        }
        
        struct lcore_stats *stats = &ctx->stats[lcore_id];
        struct extended_stats *ext_stats = &g_ext_stats[lcore_id];
        
        /* Calculate packets per second */
        ext_stats->packets_per_sec = (double)stats->tx_packets / time_seconds;
        
        /* Estimate bits per second (assuming average packet size of 1500 bytes) */
        ext_stats->bits_per_sec = ext_stats->packets_per_sec * 1500 * 8;
        ext_stats->gbps = ext_stats->bits_per_sec / 1000000000.0;
    }
    
    g_stats_ctx.last_collection_time = current_time;
}

/* Get port statistics */
static void
get_port_stats(uint16_t port_id, struct rte_eth_stats *port_stats)
{
    if (rte_eth_stats_get(port_id, port_stats) != 0) {
        memset(port_stats, 0, sizeof(*port_stats));
    }
}

/* Print comprehensive statistics */
void
stats_collector_print(struct app_context *ctx)
{
    if (!g_stats_ctx.enabled || !ctx) {
        return;
    }
    
    /* Calculate throughput statistics */
    calculate_throughput_stats(ctx);
    
    uint64_t current_time = rte_rdtsc();
    double uptime = (double)(current_time - g_stats_ctx.start_time) / rte_get_tsc_hz();
    
    printf("\n================================================================================\n");
    printf("DPDK Tuple Filter - Performance Statistics\n");
    printf("Uptime: %.2f seconds | Collection #%lu\n", uptime, ++g_stats_ctx.collection_count);
    printf("================================================================================\n");
    
    /* Per-lcore statistics */
    printf("\n=== Per-LCore Statistics ===\n");
    printf("%-6s %-12s %-12s %-12s %-12s %-12s %-12s\n",
           "LCore", "RX Packets", "TX Packets", "Dropped", "Rule Hits", "PPS", "Gbps");
    
    uint64_t total_rx = 0, total_tx = 0, total_dropped = 0, total_hits = 0;
    double total_pps = 0, total_gbps = 0;
    
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        if (!rte_lcore_is_enabled(lcore_id)) {
            continue;
        }
        
        struct lcore_stats *stats = &ctx->stats[lcore_id];
        struct extended_stats *ext_stats = &g_ext_stats[lcore_id];
        
        if (stats->rx_packets > 0 || stats->tx_packets > 0) {
            printf("%-6u %-12lu %-12lu %-12lu %-12lu %-12.0f %-12.3f\n",
                   lcore_id,
                   stats->rx_packets,
                   stats->tx_packets,
                   stats->dropped_packets,
                   stats->rule_hits,
                   ext_stats->packets_per_sec,
                   ext_stats->gbps);
            
            total_rx += stats->rx_packets;
            total_tx += stats->tx_packets;
            total_dropped += stats->dropped_packets;
            total_hits += stats->rule_hits;
            total_pps += ext_stats->packets_per_sec;
            total_gbps += ext_stats->gbps;
        }
    }
    
    printf("%-6s %-12lu %-12lu %-12lu %-12lu %-12.0f %-12.3f\n",
           "Total", total_rx, total_tx, total_dropped, total_hits, total_pps, total_gbps);
    
    /* Hash table performance */
    printf("\n=== Hash Table Performance ===\n");
    printf("%-6s %-12s %-12s %-12s %-12s\n",
           "LCore", "Lookups", "Hits", "Misses", "Hit Rate %");
    
    uint64_t total_lookups = 0, total_hits_hash = 0, total_misses = 0;
    
    RTE_LCORE_FOREACH(lcore_id) {
        if (!rte_lcore_is_enabled(lcore_id)) {
            continue;
        }
        
        struct extended_stats *ext_stats = &g_ext_stats[lcore_id];
        
        if (ext_stats->hash_lookups > 0) {
            double hit_rate = (double)ext_stats->hash_hits * 100.0 / ext_stats->hash_lookups;
            
            printf("%-6u %-12lu %-12lu %-12lu %-12.2f\n",
                   lcore_id,
                   ext_stats->hash_lookups,
                   ext_stats->hash_hits,
                   ext_stats->hash_misses,
                   hit_rate);
            
            total_lookups += ext_stats->hash_lookups;
            total_hits_hash += ext_stats->hash_hits;
            total_misses += ext_stats->hash_misses;
        }
    }
    
    if (total_lookups > 0) {
        double total_hit_rate = (double)total_hits_hash * 100.0 / total_lookups;
        printf("%-6s %-12lu %-12lu %-12lu %-12.2f\n",
               "Total", total_lookups, total_hits_hash, total_misses, total_hit_rate);
    }
    
    /* Port statistics */
    printf("\n=== Port Statistics ===\n");
    printf("%-6s %-12s %-12s %-12s %-12s %-12s\n",
           "Port", "RX Packets", "TX Packets", "RX Errors", "TX Errors", "RX Missed");
    
    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        if ((ctx->enabled_port_mask & (1 << port_id)) == 0) {
            continue;
        }
        
        struct rte_eth_stats port_stats;
        get_port_stats(port_id, &port_stats);
        
        printf("%-6u %-12lu %-12lu %-12lu %-12lu %-12lu\n",
               port_id,
               port_stats.ipackets,
               port_stats.opackets,
               port_stats.ierrors,
               port_stats.oerrors,
               port_stats.imissed);
    }
    
    /* Processing efficiency */
    printf("\n=== Processing Efficiency ===\n");
    if (total_rx > 0) {
        double drop_rate = (double)total_dropped * 100.0 / total_rx;
        double filter_efficiency = (double)total_hits * 100.0 / total_rx;
        
        printf("Packet Drop Rate:     %.2f%%\n", drop_rate);
        printf("Filter Hit Rate:      %.2f%%\n", filter_efficiency);
        printf("Total Throughput:     %.3f Gbps\n", total_gbps);
        printf("Processing Rate:      %.0f packets/sec\n", total_pps);
    }
    
    /* Rule manager statistics */
    printf("\n");
    rule_manager_print_stats();
    
    /* Hash table detailed statistics */
    if (ctx->rule_hash) {
        printf("=== Hash Table Details ===\n");
        printf("Active Rules:         %u\n", tuple_hash_count(ctx));
        printf("Rule Utilization:     %.2f%%\n", 
               (double)tuple_hash_count(ctx) * 100.0 / MAX_RULES);
    }
    
    printf("================================================================================\n\n");
}

/* Print performance summary */
void
stats_collector_print_summary(struct app_context *ctx)
{
    if (!g_stats_ctx.enabled || !ctx) {
        return;
    }
    
    uint64_t current_time = rte_rdtsc();
    double uptime = (double)(current_time - g_stats_ctx.start_time) / rte_get_tsc_hz();
    
    uint64_t total_rx = 0, total_tx = 0, total_dropped = 0;
    double total_gbps = 0;
    
    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        if (!rte_lcore_is_enabled(lcore_id)) {
            continue;
        }
        
        struct lcore_stats *stats = &ctx->stats[lcore_id];
        struct extended_stats *ext_stats = &g_ext_stats[lcore_id];
        
        total_rx += stats->rx_packets;
        total_tx += stats->tx_packets;
        total_dropped += stats->dropped_packets;
        total_gbps += ext_stats->gbps;
    }
    
    printf("\n=== Performance Summary ===\n");
    printf("Uptime:           %.2f seconds\n", uptime);
    printf("Total RX:         %lu packets\n", total_rx);
    printf("Total TX:         %lu packets\n", total_tx);
    printf("Total Dropped:    %lu packets\n", total_dropped);
    printf("Drop Rate:        %.2f%%\n", 
           total_rx > 0 ? (double)total_dropped * 100.0 / total_rx : 0.0);
    printf("Throughput:       %.3f Gbps\n", total_gbps);
    printf("Active Rules:     %u\n", tuple_hash_count(ctx));
    printf("===========================\n\n");
}

/* Reset all statistics */
void
stats_collector_reset(struct app_context *ctx)
{
    if (!ctx) {
        return;
    }
    
    /* Reset per-lcore statistics */
    memset(ctx->stats, 0, sizeof(ctx->stats));
    memset(g_ext_stats, 0, sizeof(g_ext_stats));
    
    /* Reset timestamps */
    g_stats_ctx.start_time = rte_rdtsc();
    g_stats_ctx.last_collection_time = g_stats_ctx.start_time;
    g_stats_ctx.collection_count = 0;
    
    /* Reset rule manager statistics */
    rule_manager_reset_stats();
    
    /* Reset port statistics */
    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        if ((ctx->enabled_port_mask & (1 << port_id)) == 0) {
            continue;
        }
        rte_eth_stats_reset(port_id);
    }
    
    RTE_LOG(INFO, STATS_COLLECTOR, "All statistics reset\n");
}

/* Configure statistics collection */
int
stats_collector_configure(bool enabled, uint32_t interval_seconds)
{
    g_stats_ctx.enabled = enabled;
    
    if (interval_seconds > 0) {
        g_stats_ctx.collection_interval = interval_seconds;
    }
    
    RTE_LOG(INFO, STATS_COLLECTOR, 
            "Configuration updated: enabled=%s, interval=%u seconds\n",
            enabled ? "true" : "false", g_stats_ctx.collection_interval);
    
    return 0;
}

/* Check if it's time to collect statistics */
bool
stats_collector_should_collect(void)
{
    if (!g_stats_ctx.enabled) {
        return false;
    }
    
    uint64_t current_time = rte_rdtsc();
    uint64_t elapsed = current_time - g_stats_ctx.last_collection_time;
    double elapsed_seconds = (double)elapsed / rte_get_tsc_hz();
    
    return (elapsed_seconds >= g_stats_ctx.collection_interval);
}