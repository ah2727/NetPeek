#ifndef NPE_VM_H
#define NPE_VM_H

#include <lua.h>
#include "npe_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Get the underlying Lua state from a VM.
     * This is the ONLY legal way to access lua_State.
     */
    lua_State *npe_vm_lua(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif
/**
 * Get the underlying lua_State pointer from the VM.
 */
void *npe_vm_state(npe_vm_t *vm);

/**
 * Register a C function into a Lua table.
 * @param vm     The NPE VM instance
 * @param table  Table name (e.g., "brute", "http") or NULL for global
 * @param name   Function name
 * @param cfunc  C function pointer (takes lua_State*, returns int)
 */
npe_error_t npe_vm_register_cfunc(npe_vm_t *vm,
                                  const char *table,
                                  const char *name,
                                  int (*cfunc)(void *L));

#endif /* NPE_VM_H */