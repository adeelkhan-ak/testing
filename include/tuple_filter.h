#ifndef _TUPLE_FILTER_H_
#define _TUPLE_FILTER_H_

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>

/* Configuration constants */
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100
#define MAX_RULES 1048576  /* 1M rules */
#define HASH_ENTRIES (MAX_RULES * 4)
#define RING_SIZE 4096

/* Tuple filter types */
#define TUPLE_TYPE_5TUPLE 1
#define TUPLE_TYPE_CUSTOM 2

/* Action types */
#define ACTION_ACCEPT 1
#define ACTION_DROP   2
#define ACTION_FORWARD 3

/* Performance optimization flags */
#define USE_CUCKOO_HASH 1
#define USE_HOPSCOTCH_HASH 2
#define HASH_TYPE USE_CUCKOO_HASH

/* 5-tuple structure for packet classification */
struct five_tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t pad[3];  /* Align to 16 bytes */
} __rte_aligned(16);

/* Filter rule structure */
struct filter_rule {
    struct five_tuple tuple;
    uint8_t action;
    uint8_t priority;
    uint16_t rule_id;
    uint64_t hit_count;
    uint64_t last_hit_time;
} __rte_aligned(64);  /* Cache line aligned */

/* Per-lcore statistics */
struct lcore_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t dropped_packets;
    uint64_t rule_hits;
    uint64_t rule_misses;
    uint64_t cycles_per_packet;
} __rte_cache_aligned;

/* Hash table configuration */
struct hash_config {
    uint32_t entries;
    uint32_t key_len;
    uint8_t hash_type;
    uint8_t socket_id;
} __rte_cache_aligned;

/* Main application context */
struct app_context {
    /* Hash table for rule lookup */
    struct rte_hash *rule_hash;
    
    /* Rule storage */
    struct filter_rule *rules;
    
    /* Inter-core communication rings */
    struct rte_ring *rx_rings[RTE_MAX_LCORE];
    struct rte_ring *tx_rings[RTE_MAX_LCORE];
    
    /* Memory pools */
    struct rte_mempool *pktmbuf_pool;
    
    /* Statistics */
    struct lcore_stats stats[RTE_MAX_LCORE];
    
    /* Configuration */
    uint32_t enabled_port_mask;
    uint32_t nb_ports;
    uint32_t nb_lcores;
    bool numa_on;
    
    /* Lock-free rule management */
    volatile uint32_t rule_generation;
    volatile bool updating_rules;
} __rte_cache_aligned;

/* Missing definitions */
#ifndef SOCKET_ID_ANY
#define SOCKET_ID_ANY -1
#endif

/* Rule manager statistics structure */
struct rule_manager_stats {
    uint64_t total_operations;
    uint64_t add_operations;
    uint64_t delete_operations;
    uint64_t update_operations;
    uint64_t failed_operations;
    uint32_t pending_operations;
} __rte_cache_aligned;

/* Function prototypes */

/* Hash table operations */
int tuple_hash_init(struct app_context *ctx, const struct hash_config *config);
void tuple_hash_destroy(struct app_context *ctx);
int tuple_hash_add_rule(struct app_context *ctx, const struct filter_rule *rule);
int tuple_hash_del_rule(struct app_context *ctx, const struct five_tuple *tuple);
struct filter_rule *tuple_hash_lookup(struct app_context *ctx, 
                                     const struct five_tuple *tuple);
int tuple_hash_lookup_bulk(struct app_context *ctx, const struct five_tuple **tuples, 
                          uint32_t num_keys, int32_t *positions);
void tuple_hash_get_stats(struct app_context *ctx, struct rte_hash_stats *stats);
void tuple_hash_reset(struct app_context *ctx);
uint32_t tuple_hash_count(struct app_context *ctx);
int tuple_hash_iterate(struct app_context *ctx,
                      int (*callback)(const struct five_tuple *tuple,
                                     const struct filter_rule *rule,
                                     void *userdata),
                      void *userdata);

/* Packet processing */
int packet_processor_init(struct app_context *ctx);
void packet_processor_destroy(struct app_context *ctx);
uint16_t process_packets(struct rte_mbuf **pkts, uint16_t nb_pkts,
                        struct app_context *ctx, unsigned lcore_id);
uint16_t process_packets_vec(struct rte_mbuf **pkts, uint16_t nb_pkts,
                           struct app_context *ctx, unsigned lcore_id);
void packet_processor_print_stats(void);

/* Rule management */
int rule_manager_init(struct app_context *ctx);
void rule_manager_destroy(struct app_context *ctx);
int rule_manager_add(struct app_context *ctx, const struct filter_rule *rule);
int rule_manager_delete(struct app_context *ctx, const struct five_tuple *tuple);
int rule_manager_update(struct app_context *ctx, const struct filter_rule *rule);
int rule_manager_process_operations(struct app_context *ctx);
int rule_manager_batch_add(struct app_context *ctx, const struct filter_rule *rules, uint32_t num_rules);
void rule_manager_get_stats(struct rule_manager_stats *stats);
void rule_manager_reset_stats(void);
void rule_manager_print_stats(void);
int rule_manager_configure(bool batch_processing, uint32_t batch_size);
int rule_manager_flush(struct app_context *ctx);
bool rule_manager_is_idle(void);
double rule_manager_get_queue_utilization(void);

/* Statistics */
int stats_collector_init(struct app_context *ctx);
void stats_collector_destroy(struct app_context *ctx);
void stats_collector_update(struct app_context *ctx, unsigned lcore_id,
                           uint64_t rx_pkts, uint64_t tx_pkts, uint64_t dropped);
void stats_collector_print(struct app_context *ctx);
void stats_collector_update_cycles(unsigned lcore_id, uint64_t cycles, uint64_t packets);
void stats_collector_update_hash_stats(unsigned lcore_id, uint64_t lookups,
                                       uint64_t hits, uint64_t misses);
void stats_collector_print_summary(struct app_context *ctx);
void stats_collector_reset(struct app_context *ctx);
int stats_collector_configure(bool enabled, uint32_t interval_seconds);
bool stats_collector_should_collect(void);

/* Configuration */
int config_init(struct app_context *ctx, int argc, char **argv);
void config_destroy(struct app_context *ctx);

/* Utility macros */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define STATS_UPDATE(ctx, lcore, field, value) \
    do { \
        (ctx)->stats[(lcore)].field += (value); \
    } while(0)

/* Inline functions for performance-critical operations */
static inline uint32_t
tuple_hash_func(const void *key, uint32_t key_len, uint32_t init_val)
{
    const struct five_tuple *tuple = key;
    uint32_t hash = init_val;
    
    /* Optimized hash for 5-tuple */
    hash = rte_jhash_32b((const uint32_t *)tuple, 
                        sizeof(struct five_tuple) / sizeof(uint32_t), hash);
    
    return hash;
}

static inline void
extract_5tuple(const struct rte_mbuf *m, struct five_tuple *tuple)
{
    const struct rte_ether_hdr *eth_hdr;
    const struct rte_ipv4_hdr *ipv4_hdr;
    const struct rte_tcp_hdr *tcp_hdr;
    const struct rte_udp_hdr *udp_hdr;
    
    eth_hdr = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
    
    if (likely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
        ipv4_hdr = (const struct rte_ipv4_hdr *)(eth_hdr + 1);
        
        tuple->src_ip = ipv4_hdr->src_addr;
        tuple->dst_ip = ipv4_hdr->dst_addr;
        tuple->proto = ipv4_hdr->next_proto_id;
        
        if (likely(tuple->proto == IPPROTO_TCP)) {
            tcp_hdr = (const struct rte_tcp_hdr *)((const char *)ipv4_hdr + 
                     ((ipv4_hdr->version_ihl & 0x0f) << 2));
            tuple->src_port = tcp_hdr->src_port;
            tuple->dst_port = tcp_hdr->dst_port;
        } else if (tuple->proto == IPPROTO_UDP) {
            udp_hdr = (const struct rte_udp_hdr *)((const char *)ipv4_hdr + 
                     ((ipv4_hdr->version_ihl & 0x0f) << 2));
            tuple->src_port = udp_hdr->src_port;
            tuple->dst_port = udp_hdr->dst_port;
        } else {
            tuple->src_port = 0;
            tuple->dst_port = 0;
        }
    }
}

#endif /* _TUPLE_FILTER_H_ */