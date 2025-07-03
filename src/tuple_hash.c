#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>

#include "tuple_filter.h"

#define RTE_LOGTYPE_TUPLE_HASH RTE_LOGTYPE_USER2

/* Hash table parameters */
struct tuple_hash_params {
    struct rte_hash_parameters hash_params;
    struct rte_hash *hash_table;
    struct filter_rule *rule_table;
    uint32_t num_rules;
    rte_rwlock_t rwlock;
} __rte_cache_aligned;

static struct tuple_hash_params g_hash_params;

/* Custom hash function optimized for 5-tuple */
static uint32_t
tuple_hash_crc32(const void *key, uint32_t key_len, uint32_t init_val)
{
    const struct five_tuple *tuple = (const struct five_tuple *)key;
    uint32_t hash = init_val;
    
    /* Use CRC32 for better distribution if available */
    if (rte_hash_crc32_alg == CRC32_SSE42) {
        hash = rte_hash_crc_4byte(tuple->src_ip, hash);
        hash = rte_hash_crc_4byte(tuple->dst_ip, hash);
        hash = rte_hash_crc_2byte(tuple->src_port, hash);
        hash = rte_hash_crc_2byte(tuple->dst_port, hash);
        hash = rte_hash_crc_1byte(tuple->proto, hash);
    } else {
        /* Fallback to Jenkins hash */
        hash = tuple_hash_func(key, key_len, init_val);
    }
    
    return hash;
}

/* Initialize hash table */
int
tuple_hash_init(struct app_context *ctx, const struct hash_config *config)
{
    struct rte_hash_parameters hash_params = {0};
    char name[RTE_HASH_NAMESIZE];
    
    if (!ctx || !config) {
        RTE_LOG(ERR, TUPLE_HASH, "Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Configure hash table parameters */
    snprintf(name, sizeof(name), "tuple_hash_%u", rte_lcore_id());
    hash_params.name = name;
    hash_params.entries = config->entries;
    hash_params.key_len = config->key_len;
    hash_params.hash_func = tuple_hash_crc32;
    hash_params.hash_func_init_val = 0;
    hash_params.socket_id = config->socket_id;
    
    /* Set additional flags for performance */
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |
                            RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD |
                            RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
    
    /* Create hash table */
    ctx->rule_hash = rte_hash_create(&hash_params);
    if (ctx->rule_hash == NULL) {
        RTE_LOG(ERR, TUPLE_HASH, "Failed to create hash table: %s\n",
                rte_strerror(rte_errno));
        return -rte_errno;
    }
    
    /* Allocate rule storage array */
    ctx->rules = rte_zmalloc_socket("filter_rules",
                                   config->entries * sizeof(struct filter_rule),
                                   RTE_CACHE_LINE_SIZE,
                                   config->socket_id);
    if (ctx->rules == NULL) {
        RTE_LOG(ERR, TUPLE_HASH, "Failed to allocate rule storage\n");
        rte_hash_free(ctx->rule_hash);
        return -ENOMEM;
    }
    
    /* Initialize global hash parameters */
    g_hash_params.hash_table = ctx->rule_hash;
    g_hash_params.rule_table = ctx->rules;
    g_hash_params.num_rules = 0;
    rte_rwlock_init(&g_hash_params.rwlock);
    
    RTE_LOG(INFO, TUPLE_HASH, "Hash table initialized with %u entries\n",
            config->entries);
    
    return 0;
}

/* Destroy hash table */
void
tuple_hash_destroy(struct app_context *ctx)
{
    if (ctx->rule_hash) {
        rte_hash_free(ctx->rule_hash);
        ctx->rule_hash = NULL;
    }
    
    if (ctx->rules) {
        rte_free(ctx->rules);
        ctx->rules = NULL;
    }
    
    g_hash_params.num_rules = 0;
    
    RTE_LOG(INFO, TUPLE_HASH, "Hash table destroyed\n");
}

/* Add rule to hash table */
int
tuple_hash_add_rule(struct app_context *ctx, const struct filter_rule *rule)
{
    int32_t pos;
    int ret;
    
    if (!ctx || !rule) {
        RTE_LOG(ERR, TUPLE_HASH, "Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Write lock for rule updates */
    rte_rwlock_write_lock(&g_hash_params.rwlock);
    
    /* Check for duplicate rule */
    pos = rte_hash_lookup(ctx->rule_hash, &rule->tuple);
    if (pos >= 0) {
        /* Update existing rule */
        memcpy(&ctx->rules[pos], rule, sizeof(struct filter_rule));
        ctx->rules[pos].hit_count = 0;
        ctx->rules[pos].last_hit_time = rte_rdtsc();
        ret = 0;
        goto unlock;
    }
    
    /* Add new rule */
    pos = rte_hash_add_key(ctx->rule_hash, &rule->tuple);
    if (pos < 0) {
        RTE_LOG(ERR, TUPLE_HASH, "Failed to add rule: %s\n",
                rte_strerror(-pos));
        ret = pos;
        goto unlock;
    }
    
    /* Store rule data */
    memcpy(&ctx->rules[pos], rule, sizeof(struct filter_rule));
    ctx->rules[pos].hit_count = 0;
    ctx->rules[pos].last_hit_time = rte_rdtsc();
    
    g_hash_params.num_rules++;
    ret = 0;
    
    RTE_LOG(DEBUG, TUPLE_HASH, "Added rule %u at position %d\n",
            rule->rule_id, pos);

unlock:
    rte_rwlock_write_unlock(&g_hash_params.rwlock);
    return ret;
}

/* Delete rule from hash table */
int
tuple_hash_del_rule(struct app_context *ctx, const struct five_tuple *tuple)
{
    int32_t pos;
    int ret;
    
    if (!ctx || !tuple) {
        RTE_LOG(ERR, TUPLE_HASH, "Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Write lock for rule updates */
    rte_rwlock_write_lock(&g_hash_params.rwlock);
    
    /* Find rule position */
    pos = rte_hash_lookup(ctx->rule_hash, tuple);
    if (pos < 0) {
        RTE_LOG(DEBUG, TUPLE_HASH, "Rule not found for deletion\n");
        ret = -ENOENT;
        goto unlock;
    }
    
    /* Delete from hash table */
    ret = rte_hash_del_key(ctx->rule_hash, tuple);
    if (ret < 0) {
        RTE_LOG(ERR, TUPLE_HASH, "Failed to delete rule: %s\n",
                rte_strerror(-ret));
        goto unlock;
    }
    
    /* Clear rule data */
    memset(&ctx->rules[pos], 0, sizeof(struct filter_rule));
    g_hash_params.num_rules--;
    ret = 0;
    
    RTE_LOG(DEBUG, TUPLE_HASH, "Deleted rule at position %d\n", pos);

unlock:
    rte_rwlock_write_unlock(&g_hash_params.rwlock);
    return ret;
}

/* Lookup rule in hash table (fast path - read-only) */
struct filter_rule *
tuple_hash_lookup(struct app_context *ctx, const struct five_tuple *tuple)
{
    int32_t pos;
    struct filter_rule *rule = NULL;
    
    if (unlikely(!ctx || !tuple)) {
        return NULL;
    }
    
    /* Read lock for lookup operations */
    rte_rwlock_read_lock(&g_hash_params.rwlock);
    
    /* Lookup in hash table */
    pos = rte_hash_lookup(ctx->rule_hash, tuple);
    if (likely(pos >= 0)) {
        rule = &ctx->rules[pos];
        
        /* Update hit statistics atomically */
        __atomic_add_fetch(&rule->hit_count, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&rule->last_hit_time, rte_rdtsc(), __ATOMIC_RELAXED);
    }
    
    rte_rwlock_read_unlock(&g_hash_params.rwlock);
    
    return rule;
}

/* Bulk lookup for better performance */
int
tuple_hash_lookup_bulk(struct app_context *ctx,
                      const struct five_tuple **tuples,
                      uint32_t num_keys,
                      int32_t *positions)
{
    int ret;
    
    if (!ctx || !tuples || !positions) {
        return -EINVAL;
    }
    
    /* Read lock for bulk lookup */
    rte_rwlock_read_lock(&g_hash_params.rwlock);
    
    /* Bulk lookup operation */
    ret = rte_hash_lookup_bulk(ctx->rule_hash, (const void **)tuples,
                              num_keys, positions);
    
    /* Update hit statistics for found rules */
    for (uint32_t i = 0; i < num_keys; i++) {
        if (positions[i] >= 0) {
            struct filter_rule *rule = &ctx->rules[positions[i]];
            __atomic_add_fetch(&rule->hit_count, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&rule->last_hit_time, rte_rdtsc(), __ATOMIC_RELAXED);
        }
    }
    
    rte_rwlock_read_unlock(&g_hash_params.rwlock);
    
    return ret;
}

/* Get hash table statistics */
void
tuple_hash_get_stats(struct app_context *ctx, struct rte_hash_stats *stats)
{
    if (ctx && ctx->rule_hash && stats) {
        rte_rwlock_read_lock(&g_hash_params.rwlock);
        rte_hash_stats_get(ctx->rule_hash, stats);
        rte_rwlock_read_unlock(&g_hash_params.rwlock);
    }
}

/* Reset hash table */
void
tuple_hash_reset(struct app_context *ctx)
{
    if (!ctx || !ctx->rule_hash) {
        return;
    }
    
    rte_rwlock_write_lock(&g_hash_params.rwlock);
    
    rte_hash_reset(ctx->rule_hash);
    memset(ctx->rules, 0, MAX_RULES * sizeof(struct filter_rule));
    g_hash_params.num_rules = 0;
    
    rte_rwlock_write_unlock(&g_hash_params.rwlock);
    
    RTE_LOG(INFO, TUPLE_HASH, "Hash table reset\n");
}

/* Get number of rules */
uint32_t
tuple_hash_count(struct app_context *ctx)
{
    uint32_t count;
    
    if (!ctx) {
        return 0;
    }
    
    rte_rwlock_read_lock(&g_hash_params.rwlock);
    count = g_hash_params.num_rules;
    rte_rwlock_read_unlock(&g_hash_params.rwlock);
    
    return count;
}

/* Iterate through all rules */
int
tuple_hash_iterate(struct app_context *ctx,
                  int (*callback)(const struct five_tuple *tuple,
                                 const struct filter_rule *rule,
                                 void *userdata),
                  void *userdata)
{
    uint32_t next = 0;
    const void *key;
    void *data;
    int ret = 0;
    
    if (!ctx || !callback) {
        return -EINVAL;
    }
    
    rte_rwlock_read_lock(&g_hash_params.rwlock);
    
    while (rte_hash_iterate(ctx->rule_hash, &key, &data, &next) >= 0) {
        const struct five_tuple *tuple = (const struct five_tuple *)key;
        int32_t pos = (int32_t)((uintptr_t)data);
        
        if (pos >= 0 && pos < MAX_RULES) {
            const struct filter_rule *rule = &ctx->rules[pos];
            ret = callback(tuple, rule, userdata);
            if (ret != 0) {
                break;
            }
        }
    }
    
    rte_rwlock_read_unlock(&g_hash_params.rwlock);
    
    return ret;
}