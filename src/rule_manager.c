#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_ring.h>
#include <rte_rcu_qsbr.h>

#include "tuple_filter.h"

#define RTE_LOGTYPE_RULE_MANAGER RTE_LOGTYPE_USER4

/* Rule management operation types */
#define RULE_OP_ADD    1
#define RULE_OP_DELETE 2
#define RULE_OP_UPDATE 3

/* Rule management operation structure */
struct rule_operation {
    uint8_t op_type;
    uint8_t status;
    uint16_t rule_id;
    struct filter_rule rule;
    struct five_tuple key; /* For delete operations */
    uint64_t timestamp;
} __rte_aligned(64);

/* Rule manager context */
struct rule_manager_ctx {
    /* Operation queue for pending rule updates */
    struct rte_ring *op_queue;
    
    /* RCU for safe memory reclamation */
    struct rte_rcu_qsbr *rcu_qs;
    
    /* Statistics */
    uint64_t total_operations;
    uint64_t add_operations;
    uint64_t delete_operations;
    uint64_t update_operations;
    uint64_t failed_operations;
    
    /* Configuration */
    bool batch_processing;
    uint32_t batch_size;
} __rte_cache_aligned;

static struct rule_manager_ctx g_rule_mgr;

/* Initialize rule manager */
int
rule_manager_init(struct app_context *ctx)
{
    struct rte_ring *ring;
    struct rte_rcu_qsbr *rcu_qs;
    char name[RTE_RING_NAMESIZE];
    unsigned int lcore_id;
    
    if (!ctx) {
        RTE_LOG(ERR, RULE_MANAGER, "Invalid context\n");
        return -EINVAL;
    }
    
    /* Initialize rule manager context */
    memset(&g_rule_mgr, 0, sizeof(g_rule_mgr));
    
    /* Create operation queue */
    snprintf(name, sizeof(name), "rule_op_queue_%u", rte_lcore_id());
    ring = rte_ring_create(name, 4096, SOCKET_ID_ANY, 
                          RING_F_SC_DEQ | RING_F_SP_ENQ);
    if (ring == NULL) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to create operation queue: %s\n",
                rte_strerror(rte_errno));
        return -rte_errno;
    }
    g_rule_mgr.op_queue = ring;
    
    /* Initialize RCU for safe memory reclamation */
    size_t sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
    rcu_qs = rte_zmalloc_socket("rcu_qsbr", sz, RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
    if (rcu_qs == NULL) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to allocate RCU memory\n");
        rte_ring_free(ring);
        return -ENOMEM;
    }
    
    /* Initialize RCU */
    if (rte_rcu_qsbr_init(rcu_qs, RTE_MAX_LCORE) != 0) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to initialize RCU\n");
        rte_free(rcu_qs);
        rte_ring_free(ring);
        return -1;
    }
    g_rule_mgr.rcu_qs = rcu_qs;
    
    /* Register all enabled lcores for RCU */
    RTE_LCORE_FOREACH(lcore_id) {
        if (rte_lcore_is_enabled(lcore_id)) {
            rte_rcu_qsbr_thread_register(rcu_qs, lcore_id);
        }
    }
    
    /* Enable batch processing by default */
    g_rule_mgr.batch_processing = true;
    g_rule_mgr.batch_size = 16;
    
    RTE_LOG(INFO, RULE_MANAGER, "Rule manager initialized\n");
    return 0;
}

/* Destroy rule manager */
void
rule_manager_destroy(struct app_context *ctx)
{
    RTE_UNUSED(ctx);
    
    if (g_rule_mgr.op_queue) {
        rte_ring_free(g_rule_mgr.op_queue);
        g_rule_mgr.op_queue = NULL;
    }
    
    if (g_rule_mgr.rcu_qs) {
        rte_free(g_rule_mgr.rcu_qs);
        g_rule_mgr.rcu_qs = NULL;
    }
    
    RTE_LOG(INFO, RULE_MANAGER, "Rule manager destroyed\n");
}

/* Process single rule operation */
static int
process_rule_operation(struct app_context *ctx, struct rule_operation *op)
{
    int ret = 0;
    
    switch (op->op_type) {
    case RULE_OP_ADD:
        ret = tuple_hash_add_rule(ctx, &op->rule);
        if (ret == 0) {
            g_rule_mgr.add_operations++;
        }
        break;
        
    case RULE_OP_DELETE:
        ret = tuple_hash_del_rule(ctx, &op->key);
        if (ret == 0) {
            g_rule_mgr.delete_operations++;
        }
        break;
        
    case RULE_OP_UPDATE:
        /* Update is implemented as delete + add */
        ret = tuple_hash_del_rule(ctx, &op->rule.tuple);
        if (ret == 0) {
            ret = tuple_hash_add_rule(ctx, &op->rule);
            if (ret == 0) {
                g_rule_mgr.update_operations++;
            }
        }
        break;
        
    default:
        RTE_LOG(ERR, RULE_MANAGER, "Unknown operation type: %u\n", op->op_type);
        ret = -EINVAL;
        break;
    }
    
    if (ret != 0) {
        g_rule_mgr.failed_operations++;
    }
    
    g_rule_mgr.total_operations++;
    return ret;
}

/* Process rule operations from queue */
int
rule_manager_process_operations(struct app_context *ctx)
{
    struct rule_operation *ops[32];
    unsigned int nb_ops;
    unsigned int i;
    int ret = 0;
    
    if (!ctx || !g_rule_mgr.op_queue) {
        return -EINVAL;
    }
    
    /* Dequeue operations from ring */
    nb_ops = rte_ring_dequeue_burst(g_rule_mgr.op_queue, (void **)ops, 
                                   RTE_DIM(ops), NULL);
    
    if (nb_ops == 0) {
        return 0; /* No operations to process */
    }
    
    /* Update RCU quiescent state */
    rte_rcu_qsbr_quiescent(g_rule_mgr.rcu_qs, rte_lcore_id());
    
    /* Process operations */
    for (i = 0; i < nb_ops; i++) {
        if (process_rule_operation(ctx, ops[i]) != 0) {
            ret = -1;
        }
        
        /* Free operation memory */
        rte_free(ops[i]);
    }
    
    /* Synchronize RCU */
    rte_rcu_qsbr_synchronize(g_rule_mgr.rcu_qs, RTE_QSBR_THRID_INVALID);
    
    return ret;
}

/* Add rule (non-blocking) */
int
rule_manager_add(struct app_context *ctx, const struct filter_rule *rule)
{
    struct rule_operation *op;
    int ret;
    
    if (!ctx || !rule) {
        RTE_LOG(ERR, RULE_MANAGER, "Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Allocate operation structure */
    op = rte_zmalloc("rule_operation", sizeof(struct rule_operation), 
                     RTE_CACHE_LINE_SIZE);
    if (op == NULL) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to allocate operation memory\n");
        return -ENOMEM;
    }
    
    /* Initialize operation */
    op->op_type = RULE_OP_ADD;
    op->rule_id = rule->rule_id;
    memcpy(&op->rule, rule, sizeof(struct filter_rule));
    op->timestamp = rte_rdtsc();
    
    /* Enqueue operation */
    ret = rte_ring_enqueue(g_rule_mgr.op_queue, op);
    if (ret != 0) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to enqueue add operation\n");
        rte_free(op);
        return ret;
    }
    
    RTE_LOG(DEBUG, RULE_MANAGER, "Enqueued add operation for rule %u\n", 
            rule->rule_id);
    
    return 0;
}

/* Delete rule (non-blocking) */
int
rule_manager_delete(struct app_context *ctx, const struct five_tuple *tuple)
{
    struct rule_operation *op;
    int ret;
    
    if (!ctx || !tuple) {
        RTE_LOG(ERR, RULE_MANAGER, "Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Allocate operation structure */
    op = rte_zmalloc("rule_operation", sizeof(struct rule_operation), 
                     RTE_CACHE_LINE_SIZE);
    if (op == NULL) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to allocate operation memory\n");
        return -ENOMEM;
    }
    
    /* Initialize operation */
    op->op_type = RULE_OP_DELETE;
    memcpy(&op->key, tuple, sizeof(struct five_tuple));
    op->timestamp = rte_rdtsc();
    
    /* Enqueue operation */
    ret = rte_ring_enqueue(g_rule_mgr.op_queue, op);
    if (ret != 0) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to enqueue delete operation\n");
        rte_free(op);
        return ret;
    }
    
    RTE_LOG(DEBUG, RULE_MANAGER, "Enqueued delete operation\n");
    
    return 0;
}

/* Update rule (non-blocking) */
int
rule_manager_update(struct app_context *ctx, const struct filter_rule *rule)
{
    struct rule_operation *op;
    int ret;
    
    if (!ctx || !rule) {
        RTE_LOG(ERR, RULE_MANAGER, "Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Allocate operation structure */
    op = rte_zmalloc("rule_operation", sizeof(struct rule_operation), 
                     RTE_CACHE_LINE_SIZE);
    if (op == NULL) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to allocate operation memory\n");
        return -ENOMEM;
    }
    
    /* Initialize operation */
    op->op_type = RULE_OP_UPDATE;
    op->rule_id = rule->rule_id;
    memcpy(&op->rule, rule, sizeof(struct filter_rule));
    op->timestamp = rte_rdtsc();
    
    /* Enqueue operation */
    ret = rte_ring_enqueue(g_rule_mgr.op_queue, op);
    if (ret != 0) {
        RTE_LOG(ERR, RULE_MANAGER, "Failed to enqueue update operation\n");
        rte_free(op);
        return ret;
    }
    
    RTE_LOG(DEBUG, RULE_MANAGER, "Enqueued update operation for rule %u\n", 
            rule->rule_id);
    
    return 0;
}

/* Batch rule operations */
int
rule_manager_batch_add(struct app_context *ctx, const struct filter_rule *rules,
                      uint32_t num_rules)
{
    uint32_t i, failed = 0;
    int ret;
    
    if (!ctx || !rules || num_rules == 0) {
        return -EINVAL;
    }
    
    for (i = 0; i < num_rules; i++) {
        ret = rule_manager_add(ctx, &rules[i]);
        if (ret != 0) {
            failed++;
        }
    }
    
    if (failed > 0) {
        RTE_LOG(WARNING, RULE_MANAGER, 
                "Batch add: %u/%u operations failed\n", failed, num_rules);
    }
    
    return (failed == 0) ? 0 : -1;
}

/* Get rule manager statistics */
void
rule_manager_get_stats(struct rule_manager_stats *stats)
{
    if (stats) {
        stats->total_operations = g_rule_mgr.total_operations;
        stats->add_operations = g_rule_mgr.add_operations;
        stats->delete_operations = g_rule_mgr.delete_operations;
        stats->update_operations = g_rule_mgr.update_operations;
        stats->failed_operations = g_rule_mgr.failed_operations;
        stats->pending_operations = rte_ring_count(g_rule_mgr.op_queue);
    }
}

/* Reset rule manager statistics */
void
rule_manager_reset_stats(void)
{
    g_rule_mgr.total_operations = 0;
    g_rule_mgr.add_operations = 0;
    g_rule_mgr.delete_operations = 0;
    g_rule_mgr.update_operations = 0;
    g_rule_mgr.failed_operations = 0;
}

/* Print rule manager statistics */
void
rule_manager_print_stats(void)
{
    printf("\n=== Rule Manager Statistics ===\n");
    printf("Total operations:  %lu\n", g_rule_mgr.total_operations);
    printf("Add operations:    %lu\n", g_rule_mgr.add_operations);
    printf("Delete operations: %lu\n", g_rule_mgr.delete_operations);
    printf("Update operations: %lu\n", g_rule_mgr.update_operations);
    printf("Failed operations: %lu\n", g_rule_mgr.failed_operations);
    printf("Pending operations: %u\n", rte_ring_count(g_rule_mgr.op_queue));
    
    if (g_rule_mgr.total_operations > 0) {
        double success_rate = (double)(g_rule_mgr.total_operations - 
                             g_rule_mgr.failed_operations) * 100.0 / 
                             g_rule_mgr.total_operations;
        printf("Success rate:      %.2f%%\n", success_rate);
    }
    
    printf("===============================\n\n");
}

/* Configure rule manager */
int
rule_manager_configure(bool batch_processing, uint32_t batch_size)
{
    g_rule_mgr.batch_processing = batch_processing;
    g_rule_mgr.batch_size = (batch_size > 0) ? batch_size : 16;
    
    RTE_LOG(INFO, RULE_MANAGER, 
            "Configuration updated: batch_processing=%s, batch_size=%u\n",
            batch_processing ? "enabled" : "disabled", g_rule_mgr.batch_size);
    
    return 0;
}

/* Force processing of all pending operations */
int
rule_manager_flush(struct app_context *ctx)
{
    int ret = 0;
    uint32_t processed = 0;
    
    if (!ctx) {
        return -EINVAL;
    }
    
    /* Process operations until queue is empty */
    while (rte_ring_count(g_rule_mgr.op_queue) > 0) {
        int batch_ret = rule_manager_process_operations(ctx);
        if (batch_ret != 0) {
            ret = batch_ret;
        }
        processed++;
        
        /* Safety check to avoid infinite loop */
        if (processed > 1000) {
            RTE_LOG(WARNING, RULE_MANAGER, 
                    "Flush operation exceeded safety limit\n");
            break;
        }
    }
    
    RTE_LOG(DEBUG, RULE_MANAGER, "Flushed %u operation batches\n", processed);
    return ret;
}

/* Check if rule manager is idle */
bool
rule_manager_is_idle(void)
{
    return (rte_ring_count(g_rule_mgr.op_queue) == 0);
}

/* Get queue utilization percentage */
double
rule_manager_get_queue_utilization(void)
{
    uint32_t capacity = rte_ring_get_capacity(g_rule_mgr.op_queue);
    uint32_t count = rte_ring_count(g_rule_mgr.op_queue);
    
    return (double)count * 100.0 / capacity;
}