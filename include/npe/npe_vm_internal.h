/* src/npe/npe_vm_internal.h */
#ifndef NPE_VM_INTERNAL_H
#define NPE_VM_INTERNAL_H

#include "npe/npe_types.h"
#include "npe/npe_runtime.h"
#include "npe/npe_context.h"
#include <lua.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>

/*============================================================================
 * VM Structure (Internal)
 *============================================================================*/
struct npe_vm
{
    lua_State *L;
    lua_State *co;
    int co_ref;
    npe_runtime_config_t config;
    npe_context_t *ctx; /* Current context */

    /* Resource tracking */
    size_t memory_used;
    size_t memory_limit;
    uint64_t instruction_count;
    uint64_t instruction_limit;

    /* State */
    bool yielded;
    npe_yield_info_t yield_info; /* Assuming this is defined in npe_runtime.h */
    atomic_bool abort_flag;

    /* Statistics */
    uint64_t executions;

    pthread_mutex_t mutex;
};

#endif /* NPE_VM_INTERNAL_H */
