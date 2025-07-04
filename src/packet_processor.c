#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>

#include "tuple_filter.h"

#define RTE_LOGTYPE_PACKET_PROCESSOR RTE_LOGTYPE_USER3

/* Packet processing statistics */
struct packet_stats {
    uint64_t total_packets;
    uint64_t ipv4_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t other_packets;
    uint64_t filtered_packets;
    uint64_t dropped_packets;
    uint64_t forwarded_packets;
    uint64_t parse_errors;
} __rte_cache_aligned;

static struct packet_stats g_pkt_stats[RTE_MAX_LCORE];

/* Initialize packet processor */
int
packet_processor_init(struct app_context *ctx)
{
    if (!ctx) {
        RTE_LOG(ERR, PACKET_PROCESSOR, "Invalid context\n");
        return -EINVAL;
    }
    
    /* Clear statistics */
    memset(g_pkt_stats, 0, sizeof(g_pkt_stats));
    
    RTE_LOG(INFO, PACKET_PROCESSOR, "Packet processor initialized\n");
    return 0;
}

/* Destroy packet processor */
void
packet_processor_destroy(struct app_context *ctx)
{
    RTE_SET_USED(ctx);
    
    /* Clear statistics */
    memset(g_pkt_stats, 0, sizeof(g_pkt_stats));
    
    RTE_LOG(INFO, PACKET_PROCESSOR, "Packet processor destroyed\n");
}

/* Fast path packet parsing for IPv4 */
static inline int
parse_ipv4_packet(struct rte_mbuf *m, struct five_tuple *tuple)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint16_t ether_type;
    uint8_t ip_hdr_len;
    
    /* Check minimum packet size */
    if (unlikely(rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr) + 
                sizeof(struct rte_ipv4_hdr))) {
        return -1;
    }
    
    /* Parse Ethernet header */
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    
    /* Check if IPv4 packet */
    if (unlikely(ether_type != RTE_ETHER_TYPE_IPV4)) {
        return -1;
    }
    
    /* Parse IPv4 header */
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    
    /* Validate IP header */
    if (unlikely((ipv4_hdr->version_ihl >> 4) != 4)) {
        return -1;
    }
    
    ip_hdr_len = (ipv4_hdr->version_ihl & 0x0f) << 2;
    if (unlikely(ip_hdr_len < sizeof(struct rte_ipv4_hdr))) {
        return -1;
    }
    
    /* Extract IP addresses and protocol */
    tuple->src_ip = ipv4_hdr->src_addr;
    tuple->dst_ip = ipv4_hdr->dst_addr;
    tuple->proto = ipv4_hdr->next_proto_id;
    
    /* Parse transport layer header */
    switch (tuple->proto) {
    case IPPROTO_TCP:
        if (unlikely(rte_pktmbuf_data_len(m) < 
                    sizeof(struct rte_ether_hdr) + ip_hdr_len + 
                    sizeof(struct rte_tcp_hdr))) {
            return -1;
        }
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hdr_len);
        tuple->src_port = tcp_hdr->src_port;
        tuple->dst_port = tcp_hdr->dst_port;
        break;
        
    case IPPROTO_UDP:
        if (unlikely(rte_pktmbuf_data_len(m) < 
                    sizeof(struct rte_ether_hdr) + ip_hdr_len + 
                    sizeof(struct rte_udp_hdr))) {
            return -1;
        }
        udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + ip_hdr_len);
        tuple->src_port = udp_hdr->src_port;
        tuple->dst_port = udp_hdr->dst_port;
        break;
        
    default:
        /* For other protocols, set ports to 0 */
        tuple->src_port = 0;
        tuple->dst_port = 0;
        break;
    }
    
    return 0;
}

/* Apply filter rule to packet */
static inline int
apply_filter_rule(struct rte_mbuf *m, const struct filter_rule *rule,
                 const struct five_tuple *pkt_tuple)
{
    RTE_SET_USED(m);
    
    /* Check each field for match (0 means wildcard) */
    if (rule->tuple.src_ip != 0 && rule->tuple.src_ip != pkt_tuple->src_ip) {
        return 0; /* No match */
    }
    
    if (rule->tuple.dst_ip != 0 && rule->tuple.dst_ip != pkt_tuple->dst_ip) {
        return 0; /* No match */
    }
    
    if (rule->tuple.src_port != 0 && rule->tuple.src_port != pkt_tuple->src_port) {
        return 0; /* No match */
    }
    
    if (rule->tuple.dst_port != 0 && rule->tuple.dst_port != pkt_tuple->dst_port) {
        return 0; /* No match */
    }
    
    if (rule->tuple.proto != 0 && rule->tuple.proto != pkt_tuple->proto) {
        return 0; /* No match */
    }
    
    /* Rule matches */
    return 1;
}

/* Process single packet through filter */
static inline int
process_single_packet(struct rte_mbuf *m, struct app_context *ctx,
                     unsigned lcore_id)
{
    struct five_tuple tuple;
    struct filter_rule *rule;
    int ret;
    
    /* Parse packet to extract 5-tuple */
    ret = parse_ipv4_packet(m, &tuple);
    if (unlikely(ret < 0)) {
        g_pkt_stats[lcore_id].parse_errors++;
        rte_pktmbuf_free(m);
        return ACTION_DROP;
    }
    
    /* Update packet type statistics */
    g_pkt_stats[lcore_id].ipv4_packets++;
    
    switch (tuple.proto) {
    case IPPROTO_TCP:
        g_pkt_stats[lcore_id].tcp_packets++;
        break;
    case IPPROTO_UDP:
        g_pkt_stats[lcore_id].udp_packets++;
        break;
    default:
        g_pkt_stats[lcore_id].other_packets++;
        break;
    }
    
    /* Lookup rule in hash table */
    rule = tuple_hash_lookup(ctx, &tuple);
    if (rule != NULL) {
        /* Rule found - apply action */
        g_pkt_stats[lcore_id].filtered_packets++;
        
        switch (rule->action) {
        case ACTION_ACCEPT:
            /* Forward packet */
            g_pkt_stats[lcore_id].forwarded_packets++;
            return ACTION_ACCEPT;
            
        case ACTION_DROP:
            /* Drop packet */
            g_pkt_stats[lcore_id].dropped_packets++;
            rte_pktmbuf_free(m);
            return ACTION_DROP;
            
        case ACTION_FORWARD:
            /* Forward to specific port/queue */
            g_pkt_stats[lcore_id].forwarded_packets++;
            return ACTION_FORWARD;
            
        default:
            /* Unknown action - drop by default */
            g_pkt_stats[lcore_id].dropped_packets++;
            rte_pktmbuf_free(m);
            return ACTION_DROP;
        }
    } else {
        /* No rule found - default action (accept) */
        g_pkt_stats[lcore_id].forwarded_packets++;
        return ACTION_ACCEPT;
    }
}

/* Bulk packet processing function */
uint16_t
process_packets(struct rte_mbuf **pkts, uint16_t nb_pkts,
               struct app_context *ctx, unsigned lcore_id)
{
    uint16_t i, nb_processed = 0;
    uint64_t start_tsc, end_tsc;
    
    if (unlikely(nb_pkts == 0)) {
        return 0;
    }
    
    start_tsc = rte_rdtsc();
    
    /* Update total packet count */
    g_pkt_stats[lcore_id].total_packets += nb_pkts;
    
    /* Process packets in bulk */
    for (i = 0; i < nb_pkts; i++) {
        /* Prefetch next packet for better cache performance */
        if (likely(i + 1 < nb_pkts)) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 1], char *));
        }
        
        /* Process current packet */
        int action = process_single_packet(pkts[i], ctx, lcore_id);
        
        if (action == ACTION_ACCEPT || action == ACTION_FORWARD) {
            /* Keep processed packets for transmission */
            if (nb_processed != i) {
                pkts[nb_processed] = pkts[i];
            }
            nb_processed++;
        }
        /* Dropped packets are already freed in process_single_packet */
    }
    
    /* Update processing time statistics */
    end_tsc = rte_rdtsc();
    if (nb_processed > 0) {
        uint64_t cycles_per_packet = (end_tsc - start_tsc) / nb_processed;
        g_pkt_stats[lcore_id].total_packets += cycles_per_packet;
    }
    
    return nb_processed;
}

/* Vectorized packet processing (experimental) */
uint16_t
process_packets_vec(struct rte_mbuf **pkts, uint16_t nb_pkts,
                   struct app_context *ctx, unsigned lcore_id)
{
    uint16_t i, nb_processed = 0;
    struct five_tuple tuples[MAX_PKT_BURST];
    struct filter_rule *rules[MAX_PKT_BURST];
    int parse_results[MAX_PKT_BURST];
    uint64_t start_tsc, end_tsc;
    
    if (unlikely(nb_pkts == 0)) {
        return 0;
    }
    
    start_tsc = rte_rdtsc();
    
    /* Update total packet count */
    g_pkt_stats[lcore_id].total_packets += nb_pkts;
    
    /* Step 1: Parse all packets */
    for (i = 0; i < nb_pkts; i++) {
        parse_results[i] = parse_ipv4_packet(pkts[i], &tuples[i]);
        
        if (likely(parse_results[i] >= 0)) {
            g_pkt_stats[lcore_id].ipv4_packets++;
        } else {
            g_pkt_stats[lcore_id].parse_errors++;
        }
    }
    
    /* Step 2: Bulk hash lookup */
    /* Note: This would require implementing bulk lookup in tuple_hash.c */
    for (i = 0; i < nb_pkts; i++) {
        if (parse_results[i] >= 0) {
            rules[i] = tuple_hash_lookup(ctx, &tuples[i]);
        } else {
            rules[i] = NULL;
        }
    }
    
    /* Step 3: Apply actions */
    for (i = 0; i < nb_pkts; i++) {
        int action = ACTION_ACCEPT; /* Default action */
        
        if (parse_results[i] < 0) {
            /* Parse error - drop packet */
            rte_pktmbuf_free(pkts[i]);
            continue;
        }
        
        if (rules[i] != NULL) {
            /* Rule found */
            g_pkt_stats[lcore_id].filtered_packets++;
            action = rules[i]->action;
        }
        
        switch (action) {
        case ACTION_ACCEPT:
        case ACTION_FORWARD:
            /* Keep packet */
            if (nb_processed != i) {
                pkts[nb_processed] = pkts[i];
            }
            nb_processed++;
            g_pkt_stats[lcore_id].forwarded_packets++;
            break;
            
        case ACTION_DROP:
        default:
            /* Drop packet */
            rte_pktmbuf_free(pkts[i]);
            g_pkt_stats[lcore_id].dropped_packets++;
            break;
        }
    }
    
    /* Update processing time statistics */
    end_tsc = rte_rdtsc();
    if (nb_processed > 0) {
        uint64_t cycles_per_packet = (end_tsc - start_tsc) / nb_processed;
        g_pkt_stats[lcore_id].total_packets += cycles_per_packet;
    }
    
    return nb_processed;
}

/* Get packet processing statistics */
void
packet_processor_get_stats(unsigned lcore_id, struct packet_stats *stats)
{
    if (lcore_id < RTE_MAX_LCORE && stats) {
        memcpy(stats, &g_pkt_stats[lcore_id], sizeof(struct packet_stats));
    }
}

/* Reset packet processing statistics */
void
packet_processor_reset_stats(unsigned lcore_id)
{
    if (lcore_id < RTE_MAX_LCORE) {
        memset(&g_pkt_stats[lcore_id], 0, sizeof(struct packet_stats));
    }
}

/* Print packet processing statistics */
void
packet_processor_print_stats(void)
{
    unsigned lcore_id;
    struct packet_stats total_stats = {0};
    
    printf("\n=== Packet Processing Statistics ===\n");
    printf("%-8s %-12s %-12s %-12s %-12s %-12s %-12s %-12s\n",
           "LCore", "Total", "IPv4", "TCP", "UDP", "Filtered", "Dropped", "Forwarded");
    
    RTE_LCORE_FOREACH(lcore_id) {
        if (!rte_lcore_is_enabled(lcore_id))
            continue;
            
        struct packet_stats *stats = &g_pkt_stats[lcore_id];
        
        if (stats->total_packets > 0) {
            printf("%-8u %-12lu %-12lu %-12lu %-12lu %-12lu %-12lu %-12lu\n",
                   lcore_id,
                   stats->total_packets,
                   stats->ipv4_packets,
                   stats->tcp_packets,
                   stats->udp_packets,
                   stats->filtered_packets,
                   stats->dropped_packets,
                   stats->forwarded_packets);
            
            /* Accumulate totals */
            total_stats.total_packets += stats->total_packets;
            total_stats.ipv4_packets += stats->ipv4_packets;
            total_stats.tcp_packets += stats->tcp_packets;
            total_stats.udp_packets += stats->udp_packets;
            total_stats.filtered_packets += stats->filtered_packets;
            total_stats.dropped_packets += stats->dropped_packets;
            total_stats.forwarded_packets += stats->forwarded_packets;
        }
    }
    
    /* Print totals */
    printf("%-8s %-12lu %-12lu %-12lu %-12lu %-12lu %-12lu %-12lu\n",
           "Total",
           total_stats.total_packets,
           total_stats.ipv4_packets,
           total_stats.tcp_packets,
           total_stats.udp_packets,
           total_stats.filtered_packets,
           total_stats.dropped_packets,
           total_stats.forwarded_packets);
    
    /* Calculate percentages */
    if (total_stats.total_packets > 0) {
        printf("\nProcessing efficiency:\n");
        printf("  IPv4 packets: %.2f%%\n",
               (double)total_stats.ipv4_packets * 100.0 / total_stats.total_packets);
        printf("  Filtered packets: %.2f%%\n",
               (double)total_stats.filtered_packets * 100.0 / total_stats.total_packets);
        printf("  Drop rate: %.2f%%\n",
               (double)total_stats.dropped_packets * 100.0 / total_stats.total_packets);
    }
    
    printf("=====================================\n\n");
}