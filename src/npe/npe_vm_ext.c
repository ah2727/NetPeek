// src/npe/npe_vm_ext.c
#include "npe/npe_runtime.h"
#include <lua.h>
#include <lauxlib.h>
#include "npe_vm_internal.h"
#include "logger.h"


/* ------------------------------------------------------------------ */
/*  Lua state accessors                                                */
/* ------------------------------------------------------------------ */

lua_State *npe_vm_lua(npe_vm_t *vm)
{
    if (!vm) {
        LOGW("npe_vm_lua: NULL vm");
        return NULL;
    }
    return vm->L;
}

lua_State *npe_vm_lua_state(npe_vm_t *vm)
{
    if (!vm) {
        LOGW("npe_vm_lua_state: NULL vm");
        return NULL;
    }
    return vm->L;
}

/* ------------------------------------------------------------------ */
/*  VM status helpers                                                   */
/* ------------------------------------------------------------------ */

int npe_vm_state(npe_vm_t *vm)
{
    if (!vm || !vm->L) {
        LOGW("npe_vm_state: invalid vm");
        return LUA_OK;
    }
    int state = lua_status(vm->L);
    LOGD("npe_vm_state: %d", state);
    return state;
}
