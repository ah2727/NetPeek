/*****************************************************************************
 * npe_runtime.c — Lua VM wrapper and runtime management
 * ───────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * Implements every function declared in include/npe/npe_runtime.h:
 *   - Single VM lifecycle (create / destroy / reset)
 *   - Script compilation and execution
 *   - Rule evaluation and action invocation
 *   - Coroutine yield / resume for async I/O
 *   - Context and argument injection
 *   - Memory / instruction queries and abort
 *   - VM pool (create / destroy / acquire / release / stats)
 *****************************************************************************/

#include "npe/npe_runtime.h"
#include "npe/npe_context.h"
#include "npe/npe_error.h"
#include "npe/npe_script.h"
#include "logger.h"
#include "npe_vm_internal.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <inttypes.h>

extern int luaopen_npe_http_lib(lua_State *L);
extern int luaopen_npe_socket(lua_State *L);
extern int luaopen_npe_json(lua_State *L);
extern int luaopen_npe_crypto(lua_State *L);
extern int luaopen_npe_dns(lua_State *L);
extern int luaopen_npe_string(lua_State *L);
extern int luaopen_npe_packet(lua_State *L);
extern int luaopen_npe_brute(lua_State *L);
extern int luaopen_npe_vuln(lua_State *L);
extern int luaopen_npe_ftp(lua_State *L);
extern int luaopen_npe_smtp(lua_State *L);
extern int luaopen_npe_mysql(lua_State *L);
extern int luaopen_npe_redis(lua_State *L);
extern int luaopen_npe_ssh(lua_State *L);
extern int luaopen_npe_smb(lua_State *L);
extern int luaopen_npe_snmp(lua_State *L);
extern int luaopen_npe_intrusive(lua_State *L);

static int require_with_cache(lua_State *L,
                              const char *modname,
                              lua_CFunction opener)
{
    opener(L);
    lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
    lua_pushvalue(L, -2);
    lua_setfield(L, -2, modname);
    lua_pop(L, 1);
    return 1;
}

static int npe_lua_require(lua_State *L)
{
    const char *modname = luaL_checkstring(L, 1);

    lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
    lua_getfield(L, -1, modname);
    if (!lua_isnil(L, -1))
    {
        return 1;
    }
    lua_pop(L, 2);

    if (strcmp(modname, "http") == 0)
        return require_with_cache(L, modname, luaopen_npe_http_lib);
    if (strcmp(modname, "socket") == 0 || strcmp(modname, "net") == 0)
        return require_with_cache(L, modname, luaopen_npe_socket);
    if (strcmp(modname, "json") == 0)
        return require_with_cache(L, modname, luaopen_npe_json);
    if (strcmp(modname, "crypto") == 0)
        return require_with_cache(L, modname, luaopen_npe_crypto);
    if (strcmp(modname, "dns") == 0)
        return require_with_cache(L, modname, luaopen_npe_dns);
    if (strcmp(modname, "string") == 0)
        return require_with_cache(L, modname, luaopen_npe_string);
    if (strcmp(modname, "packet") == 0)
        return require_with_cache(L, modname, luaopen_npe_packet);
    if (strcmp(modname, "brute") == 0)
        return require_with_cache(L, modname, luaopen_npe_brute);
    if (strcmp(modname, "vuln") == 0)
        return require_with_cache(L, modname, luaopen_npe_vuln);
    if (strcmp(modname, "intrusive") == 0)
        return require_with_cache(L, modname, luaopen_npe_intrusive);

    if (strcmp(modname, "ftp") == 0)
        return require_with_cache(L, modname, luaopen_npe_ftp);
    if (strcmp(modname, "smtp") == 0)
        return require_with_cache(L, modname, luaopen_npe_smtp);
    if (strcmp(modname, "mysql") == 0)
        return require_with_cache(L, modname, luaopen_npe_mysql);
    if (strcmp(modname, "redis") == 0)
        return require_with_cache(L, modname, luaopen_npe_redis);
    if (strcmp(modname, "ssh") == 0)
        return require_with_cache(L, modname, luaopen_npe_ssh);
    if (strcmp(modname, "smb") == 0)
        return require_with_cache(L, modname, luaopen_npe_smb);
    if (strcmp(modname, "snmp") == 0)
        return require_with_cache(L, modname, luaopen_npe_snmp);

    return luaL_error(L, "module '%s' not found", modname);
}

/*============================================================================
 * Internal Constants
 *============================================================================*/

#define VM_DEFAULT_MAX_MEMORY (64 * 1024 * 1024) /* 64 MiB       */
#define VM_DEFAULT_MAX_INSTRUCTIONS 0            /* unlimited    */
#define VM_INSTRUCTION_CHECK_INTERVAL 10000
#define VM_POOL_DEFAULT_INITIAL_SIZE 4

/*============================================================================
 * VM Pool Internals
 *============================================================================*/

typedef struct vm_pool_entry
{
    npe_vm_t *vm;
    bool in_use;
    struct vm_pool_entry *next;
} vm_pool_entry_t;

struct npe_vm_pool
{
    npe_vm_pool_config_t config;
    vm_pool_entry_t *entries;
    size_t total_count;
    size_t in_use_count;
    bool shutdown;
    pthread_mutex_t mutex;
    pthread_cond_t available;
};

/*============================================================================
 * Lua Table Builders for Host / Port
 *
 * These push a plain Lua table onto the stack that scripts can index
 * with normal field access:  host.ip, port.number, port.protocol, etc.
 *============================================================================*/

static void push_host_table(lua_State *L, const npe_host_t *host)
{
    lua_newtable(L);

    lua_pushstring(L, host->ip);
    lua_setfield(L, -2, "ip");

    lua_pushstring(L, host->hostname[0] ? host->hostname : "");
    lua_setfield(L, -2, "hostname");

    lua_pushstring(L, "up"); // Add this line
    lua_setfield(L, -2, "status");

    lua_pushinteger(L, (lua_Integer)host->port_count);
    lua_setfield(L, -2, "port_count");
}

static const char *
protocol_to_lua_string(npe_protocol_t proto)
{
    switch (proto)
    {
    case NPE_PROTO_TCP:
        return "tcp";
    case NPE_PROTO_UDP:
        return "udp";
    case NPE_PROTO_SCTP:
        return "sctp";
    default:
        return "unknown";
    }
}

static const char *
state_to_lua_string(npe_port_state_t state)
{
    switch (state)
    {
    case NPE_PORT_OPEN:
        return "open";
    case NPE_PORT_CLOSED:
        return "closed";
    case NPE_PORT_FILTERED:
        return "filtered";
    case NPE_PORT_UNFILTERED:
        return "unfiltered";
    case NPE_PORT_OPEN_FILTERED:
        return "open|filtered";
    case NPE_PORT_CLOSED_FILTERED:
        return "closed|filtered";
    default:
        return "unknown";
    }
}

static void push_port_table(lua_State *L, const npe_port_t *port)
{
    lua_newtable(L);

    lua_pushinteger(L, (lua_Integer)port->number);
    lua_setfield(L, -2, "number");

    lua_pushstring(L, protocol_to_lua_string(port->protocol));
    lua_setfield(L, -2, "protocol");

    lua_pushstring(L, state_to_lua_string(port->state)); // Changed
    lua_setfield(L, -2, "state");

    lua_pushstring(L, (port->service_name && port->service_name[0]) ? port->service_name : "");
    lua_setfield(L, -2, "service");

    lua_pushstring(L, (port->version_info && port->version_info[0]) ? port->version_info : "");
    lua_setfield(L, -2, "version");
}

static void vm_reset_coroutine(npe_vm_t *vm)
{
    if (!vm || !vm->L)
        return;

    if (vm->co_ref != LUA_NOREF)
    {
        luaL_unref(vm->L, LUA_REGISTRYINDEX, vm->co_ref);
        vm->co_ref = LUA_NOREF;
    }
    vm->co = NULL;
}

static void vm_capture_yield_info(lua_State *co, int nres, npe_yield_info_t *info)
{
    if (!co || !info)
        return;

    memset(info, 0, sizeof(*info));
    info->reason = NPE_REASON_YIELD_NONE;
    info->type = NPE_YIELD_NONE;

    if (nres >= 1 && lua_isstring(co, -nres))
    {
        const char *yt = lua_tostring(co, -nres);
        if (strcmp(yt, "read") == 0)
        {
            info->type = NPE_YIELD_READ;
            info->reason = NPE_REASON_YIELD_SOCKET_READ;
        }
        else if (strcmp(yt, "write") == 0)
        {
            info->type = NPE_YIELD_WRITE;
            info->reason = NPE_REASON_YIELD_SOCKET_WRITE;
        }
        else if (strcmp(yt, "connect") == 0)
        {
            info->type = NPE_YIELD_CONNECT;
            info->reason = NPE_REASON_YIELD_SOCKET_CONNECT;
        }
        else if (strcmp(yt, "sleep") == 0)
        {
            info->type = NPE_YIELD_SLEEP;
            info->reason = NPE_REASON_YIELD_SLEEP;
        }
        else
        {
            info->type = NPE_YIELD_UNKNOWN;
            info->reason = NPE_REASON_YIELD_NONE;
        }
    }

    if (nres >= 2 && lua_isinteger(co, -nres + 1))
        info->fd = (int)lua_tointeger(co, -nres + 1);
    else
        info->fd = -1;

    if (nres >= 3 && lua_isnumber(co, -nres + 2))
        info->timeout_ms = (int)lua_tonumber(co, -nres + 2);
    else
        info->timeout_ms = 0;
}

/*============================================================================
 * Lua Memory Allocator
 *============================================================================*/

/*
 * FIX: Only update memory_used AFTER realloc succeeds, preventing
 *      accounting corruption on allocation failure.
 */
static void *vm_allocator(void *ud, void *ptr, size_t osize, size_t nsize)
{
    npe_vm_t *vm = (npe_vm_t *)ud;

    if (nsize == 0)
    {
        if (ptr)
        {
            vm->memory_used -= osize;
            free(ptr);
        }
        return NULL;
    }

    /* Check memory cap before attempting growth */
    if (nsize > osize)
    {
        size_t delta = nsize - osize;
        if (vm->memory_limit > 0 &&
            vm->memory_used + delta > vm->memory_limit)
        {
            return NULL; /* OOM — Lua will raise an error */
        }
    }

    void *new_ptr = realloc(ptr, nsize);
    if (!new_ptr)
        return NULL; /* realloc failed — accounting unchanged */

    /* Realloc succeeded — commit the accounting change */
    if (nsize > osize)
        vm->memory_used += (nsize - osize);
    else
        vm->memory_used -= (osize - nsize);

    return new_ptr;
}

/*============================================================================
 * Lua Debug Hook (instruction limit + abort)
 *============================================================================*/

static void vm_debug_hook(lua_State *L, lua_Debug *ar)
{
    (void)ar;

    npe_vm_t *vm = *(npe_vm_t **)lua_getextraspace(L);
    if (!vm)
        return;

    vm->instruction_count++;

    /*
     * FIX: abort_flag must be atomic_bool in npe_vm_internal.h
     *      for atomic_load to work correctly across threads.
     */
    if (atomic_load(&vm->abort_flag))
    {
        luaL_error(L, "execution aborted");
        return;
    }

    if (vm->instruction_limit > 0 &&
        vm->instruction_count >= vm->instruction_limit)
    {
        luaL_error(L, "instruction count limit exceeded");
        return;
    }
}

/*============================================================================
 * NPE Standard Libraries — forward declarations
 *============================================================================*/

extern int luaopen_npe_socket(lua_State *L);
extern int luaopen_npe_http(lua_State *L);
extern int luaopen_npe_tls(lua_State *L);
extern int luaopen_npe_json(lua_State *L);
extern int luaopen_npe_crypto(lua_State *L);
extern int luaopen_npe_dns(lua_State *L);
extern int luaopen_npe_string(lua_State *L);
extern int luaopen_npe_packet(lua_State *L);
extern int luaopen_npe_brute(lua_State *L);
extern int luaopen_npe_vuln(lua_State *L);
extern int luaopen_npe_ftp(lua_State *L);
extern int luaopen_npe_smtp(lua_State *L);
extern int luaopen_npe_mysql(lua_State *L);
extern int luaopen_npe_redis(lua_State *L);
extern int luaopen_npe_smb(lua_State *L);
extern int luaopen_npe_snmp(lua_State *L);
extern int luaopen_npe_ssh(lua_State *L);
extern int luaopen_npe_intrusive(lua_State *L);

/*============================================================================
 * Library Registration (shared between create and reset)
 *============================================================================*/

static void vm_load_libraries(npe_vm_t *vm)
{
    lua_State *L = vm->L;

    /* Core Lua libs (safe subset) */
    luaL_requiref(L, "_G", luaopen_base, 1);
    lua_pop(L, 1);
    luaL_requiref(L, "string", luaopen_string, 1);
    lua_pop(L, 1);
    luaL_requiref(L, "table", luaopen_table, 1);
    lua_pop(L, 1);
    luaL_requiref(L, "math", luaopen_math, 1);
    lua_pop(L, 1);
    luaL_requiref(L, "utf8", luaopen_utf8, 1);
    lua_pop(L, 1);
    luaL_requiref(L, "coroutine", luaopen_coroutine, 1);
    lua_pop(L, 1);

    /* Sandbox: remove dangerous globals */
    if (vm->config.sandbox_enable)
    {
        lua_pushnil(L);
        lua_setglobal(L, "dofile");
        lua_pushnil(L);
        lua_setglobal(L, "loadfile");
        lua_pushnil(L);
        lua_setglobal(L, "load");
        lua_pushnil(L);
        lua_setglobal(L, "loadstring");
    }

    /* Register require function and initialize _LOADED table */
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, "_LOADED");
    lua_register(L, "require", npe_lua_require);

    /* Create global 'npe' table for all NPE modules */
    lua_newtable(L);
    /* NPE extension libraries */
    if (vm->config.load_npe_socket)
    {
        luaL_requiref(L, "npe.socket", luaopen_npe_socket, 1);
        lua_setfield(L, -2, "socket");
    }
    if (vm->config.load_npe_http)
    {
        luaL_requiref(L, "npe.http", luaopen_npe_http, 1);
        lua_setfield(L, -2, "http");
    }
    luaL_requiref(L, "npe.tls", luaopen_npe_tls, 1);
    lua_setfield(L, -2, "tls");
    if (vm->config.load_npe_json)
    {
        luaL_requiref(L, "npe.json", luaopen_npe_json, 1);
        lua_setfield(L, -2, "json");
    }
    if (vm->config.load_npe_crypto)
    {
        luaL_requiref(L, "npe.crypto", luaopen_npe_crypto, 1);
        lua_setfield(L, -2, "crypto");
    }
    if (vm->config.load_npe_dns)
    {
        luaL_requiref(L, "npe.dns", luaopen_npe_dns, 1);
        lua_setfield(L, -2, "dns");
    }
    if (vm->config.load_npe_string)
    {
        luaL_requiref(L, "npe.string", luaopen_npe_string, 1);
        lua_setfield(L, -2, "string");
    }
    if (vm->config.load_npe_packet)
    {
        luaL_requiref(L, "npe.packet", luaopen_npe_packet, 1);
        lua_setfield(L, -2, "packet");
    }
    if (vm->config.load_npe_brute)
    {
        luaL_requiref(L, "npe.brute", luaopen_npe_brute, 1);
        lua_setfield(L, -2, "brute");
    }
    if (vm->config.load_npe_vuln)
    {
        luaL_requiref(L, "npe.vuln", luaopen_npe_vuln, 1);
        lua_setfield(L, -2, "vuln");
    }
    luaL_requiref(L, "npe.intrusive", luaopen_npe_intrusive, 1);
    lua_setfield(L, -2, "intrusive");

    lua_newtable(L);
    luaL_requiref(L, "npe.proto.ftp", luaopen_npe_ftp, 1);
    lua_setfield(L, -2, "ftp");
    luaL_requiref(L, "npe.proto.smtp", luaopen_npe_smtp, 1);
    lua_setfield(L, -2, "smtp");
    luaL_requiref(L, "npe.proto.mysql", luaopen_npe_mysql, 1);
    lua_setfield(L, -2, "mysql");
    luaL_requiref(L, "npe.proto.redis", luaopen_npe_redis, 1);
    lua_setfield(L, -2, "redis");
    luaL_requiref(L, "npe.proto.ssh", luaopen_npe_ssh, 1);
    lua_setfield(L, -2, "ssh");
    luaL_requiref(L, "npe.proto.smb", luaopen_npe_smb, 1);
    lua_setfield(L, -2, "smb");
    luaL_requiref(L, "npe.proto.snmp", luaopen_npe_snmp, 1);
    lua_setfield(L, -2, "snmp");
    lua_setfield(L, -2, "proto");

    lua_setglobal(L, "npe");

    /* Async convenience wrappers at top-level npe.* */
    const char *async_helpers =
        "local s = npe.socket\n"
        "if s then\n"
        "  if not npe.socket_connect then\n"
        "    function npe.socket_connect(host, port, timeout_ms)\n"
        "      local fd = s.connect(host, port)\n"
        "      if not fd then return nil, 'connect failed' end\n"
        "      local ok, err = coroutine.yield('connect', fd, timeout_ms or 5000)\n"
        "      if not ok then s.close(fd); return nil, err end\n"
        "      return fd\n"
        "    end\n"
        "  end\n"
        "  if not npe.send then\n"
        "    function npe.send(fd, data, timeout_ms)\n"
        "      local ok, err = coroutine.yield('write', fd, timeout_ms or 5000)\n"
        "      if not ok then return nil, err end\n"
        "      local sent_ok = s.send(fd, data)\n"
        "      if sent_ok then return #data end\n"
        "      return nil, 'send failed'\n"
        "    end\n"
        "  end\n"
        "  if not npe.recv then\n"
        "    function npe.recv(fd, max_bytes, timeout_ms)\n"
        "      local ok, err = coroutine.yield('read', fd, timeout_ms or 5000)\n"
        "      if not ok then return nil, err end\n"
        "      return s.recv(fd, max_bytes)\n"
        "    end\n"
        "  end\n"
        "end\n"
        "if not npe.sleep then\n"
        "  function npe.sleep(ms)\n"
        "    local ok, err = coroutine.yield('sleep', -1, ms or 0)\n"
        "    if not ok then return nil, err end\n"
        "    return true\n"
        "  end\n"
        "end\n";

    if (luaL_dostring(L, async_helpers) != LUA_OK)
    {
        const char *emsg = lua_tostring(L, -1);
        LOGW("failed to load async helper wrappers: %s", emsg ? emsg : "unknown");
        lua_pop(L, 1);
    }

    if (luaL_dostring(L,
                      "if npe.vuln and not npe.vulns then npe.vulns = npe.vuln end\n"
                      "if npe.proto then\n"
                      "  if not npe.ssh then npe.ssh = npe.proto.ssh end\n"
                      "  if not npe.snmp then npe.snmp = npe.proto.snmp end\n"
                      "  if not npe.smb then npe.smb = npe.proto.smb end\n"
                      "  if not npe.mysql then npe.mysql = npe.proto.mysql end\n"
                      "  if not npe.redis then npe.redis = npe.proto.redis end\n"
                      "  if not npe.ftp then npe.ftp = npe.proto.ftp end\n"
                      "  if not npe.smtp then npe.smtp = npe.proto.smtp end\n"
                      "end\n"
                      "if not npe.match then\n"
                      "  npe.match = {}\n"
                      "  function npe.match.regex(pattern, subject)\n"
                      "    local ok, res = pcall(string.match, subject or '', pattern or '')\n"
                      "    if ok and res then return true, res end\n"
                      "    return false, nil\n"
                      "  end\n"
                      "  function npe.match.grepable(pattern, subject)\n"
                      "    return string.find(subject or '', pattern or '') ~= nil\n"
                      "  end\n"
                      "end\n") != LUA_OK)
    {
        lua_pop(L, 1);
    }

    /* Create 'net' alias for npe.socket */
    if (vm->config.load_npe_socket)
    {
        luaL_requiref(L, "npe.socket", luaopen_npe_socket, 1);
        lua_setglobal(L, "net");
    }

    luaL_requiref(L, "ftp", luaopen_npe_ftp, 1);
    lua_setglobal(L, "ftp");
    luaL_requiref(L, "smtp", luaopen_npe_smtp, 1);
    lua_setglobal(L, "smtp");
    luaL_requiref(L, "mysql", luaopen_npe_mysql, 1);
    lua_setglobal(L, "mysql");
    luaL_requiref(L, "redis", luaopen_npe_redis, 1);
    lua_setglobal(L, "redis");
    luaL_requiref(L, "ssh", luaopen_npe_ssh, 1);
    lua_setglobal(L, "ssh");
    luaL_requiref(L, "smb", luaopen_npe_smb, 1);
    lua_setglobal(L, "smb");
    luaL_requiref(L, "snmp", luaopen_npe_snmp, 1);
    lua_setglobal(L, "snmp");
    if (vm->config.load_npe_brute)
    {
        luaL_requiref(L, "brute", luaopen_npe_brute, 1);
        lua_setglobal(L, "brute");
    }
}

/*============================================================================
 * npe_vm_create
 *============================================================================*/

npe_error_t npe_vm_create(const npe_runtime_config_t *config,
                          npe_vm_t **out)
{
    if (!out)
    {
        LOGE("npe_vm_create: NULL out pointer");
        return NPE_ERROR_INVALID_ARG;
    }
    *out = NULL;

    npe_vm_t *vm = calloc(1, sizeof(npe_vm_t));
    if (!vm)
    {
        LOGE("npe_vm_create: allocation failed");
        return NPE_ERROR_MEMORY;
    }

    /* Apply configuration (or defaults) */
    if (config)
    {
        vm->config = *config;
    }
    else
    {
        vm->config.sandbox_enable = true;
        vm->config.max_memory_bytes = VM_DEFAULT_MAX_MEMORY;
        vm->config.max_instructions = VM_DEFAULT_MAX_INSTRUCTIONS;
        vm->config.load_npe_socket = true;
        vm->config.load_npe_http = true;
        vm->config.load_npe_json = true;
        vm->config.load_npe_crypto = true;
        vm->config.load_npe_dns = true;
        vm->config.load_npe_string = true;
        vm->config.load_npe_packet = true;
        vm->config.load_npe_brute = true;
        vm->config.load_npe_vuln = true;
    }

    vm->memory_limit = vm->config.max_memory_bytes;
    vm->instruction_limit = vm->config.max_instructions;
    vm->co = NULL;
    vm->co_ref = LUA_NOREF;

    atomic_init(&vm->abort_flag, false);
    pthread_mutex_init(&vm->mutex, NULL);

    vm->L = lua_newstate(vm_allocator, vm);
    if (!vm->L)
    {
        pthread_mutex_destroy(&vm->mutex);
        free(vm);
        LOGE("npe_vm_create: lua_newstate failed");
        return NPE_ERROR_MEMORY;
    }

    /* Store back-pointer in Lua extra space */
    *(npe_vm_t **)lua_getextraspace(vm->L) = vm;

    /* Install debug hook for instruction limit / abort */
    if (vm->instruction_limit > 0)
    {
        lua_sethook(vm->L, vm_debug_hook, LUA_MASKCOUNT,
                    VM_INSTRUCTION_CHECK_INTERVAL);
    }
    else
    {
        /* Still install hook for abort support, but at coarser interval */
        lua_sethook(vm->L, vm_debug_hook, LUA_MASKCOUNT,
                    VM_INSTRUCTION_CHECK_INTERVAL * 10);
    }

    vm_load_libraries(vm);

    LOGD("VM created: sandbox=%s, mem_limit=%zu, insn_limit=%" PRIu64,
         vm->config.sandbox_enable ? "on" : "off",
         vm->memory_limit,
         vm->instruction_limit);

    *out = vm;
    return NPE_OK;
}

/*============================================================================
 * npe_vm_destroy
 *============================================================================*/

void npe_vm_destroy(npe_vm_t **vm)
{
    if (!vm || !*vm)
        return;

    npe_vm_t *v = *vm;

    LOGD("Destroying VM (executions=%" PRIu64 ")", v->executions);

    if (v->L)
    {
        /*
         * FIX: Remove the debug hook BEFORE lua_close().
         * During lua_close() the GC runs __gc metamethods which can
         * trigger the hook; if the hook dereferences a half-torn-down
         * VM struct we get UB / crash.
         */
        vm_reset_coroutine(v);
        lua_sethook(v->L, NULL, 0, 0);
        lua_close(v->L);
        v->L = NULL;
    }

    pthread_mutex_destroy(&v->mutex);
    free(v);
    *vm = NULL;
}

/*============================================================================
 * npe_vm_reset
 *============================================================================*/

npe_error_t npe_vm_reset(npe_vm_t *vm)
{
    if (!vm || !vm->L)
    {
        LOGE("npe_vm_reset: invalid VM");
        return NPE_ERROR_INVALID_ARG;
    }

    pthread_mutex_lock(&vm->mutex);

    /* FIX: remove hook BEFORE lua_close */
    lua_sethook(vm->L, NULL, 0, 0);
    lua_close(vm->L);

    vm->memory_used = 0;
    vm->instruction_count = 0;
    vm->yielded = false;
    vm_reset_coroutine(vm);
    vm->ctx = NULL;
    vm->executions = 0;
    atomic_store(&vm->abort_flag, false);
    memset(&vm->yield_info, 0, sizeof(vm->yield_info));

    vm->L = lua_newstate(vm_allocator, vm);
    if (!vm->L)
    {
        pthread_mutex_unlock(&vm->mutex);
        LOGE("npe_vm_reset: lua_newstate failed");
        return NPE_ERROR_MEMORY;
    }

    *(npe_vm_t **)lua_getextraspace(vm->L) = vm;

    if (vm->instruction_limit > 0)
    {
        lua_sethook(vm->L, vm_debug_hook, LUA_MASKCOUNT,
                    VM_INSTRUCTION_CHECK_INTERVAL);
    }
    else
    {
        lua_sethook(vm->L, vm_debug_hook, LUA_MASKCOUNT,
                    VM_INSTRUCTION_CHECK_INTERVAL * 10);
    }

    vm_load_libraries(vm);

    pthread_mutex_unlock(&vm->mutex);
    LOGD("VM reset complete");
    return NPE_OK;
}

/*============================================================================
 * npe_vm_set_context
 *============================================================================*/

npe_error_t npe_vm_set_context(npe_vm_t *vm, npe_context_t *ctx)
{
    if (!vm)
        return NPE_ERROR_INVALID_ARG;
    vm->ctx = ctx;
    return NPE_OK;
}

/*============================================================================
 * npe_vm_set_args
 *============================================================================*/

npe_error_t npe_vm_set_args(npe_vm_t *vm, const npe_args_t *args)
{
    if (!vm || !vm->L)
        return NPE_ERROR_INVALID_ARG;
    if (!args || args->count == 0)
        return NPE_OK; /* Nothing to inject */

    pthread_mutex_lock(&vm->mutex);

    lua_getglobal(vm->L, "npe");
    if (!lua_istable(vm->L, -1))
    {
        lua_pop(vm->L, 1);
        lua_newtable(vm->L);
        lua_pushvalue(vm->L, -1);
        lua_setglobal(vm->L, "npe");
    }

    lua_newtable(vm->L);
    for (size_t i = 0; i < args->count; i++)
    {
        if (args->items[i].key && args->items[i].value)
        {
            lua_pushstring(vm->L, args->items[i].value);
            lua_setfield(vm->L, -2, args->items[i].key);
        }
    }
    lua_setfield(vm->L, -2, "args");
    lua_pop(vm->L, 1); /* pop "npe" table */

    pthread_mutex_unlock(&vm->mutex);
    return NPE_OK;
}

/*============================================================================
 * npe_vm_compile
 *============================================================================*/

npe_error_t npe_vm_compile(npe_vm_t *vm, const npe_script_t *script)
{
    if (!vm || !vm->L || !script || !script->source.text)
        return NPE_ERROR_INVALID_ARG;

    const char *name = (script->filename[0] != '\0')
                           ? script->filename
                           : "unknown";

    pthread_mutex_lock(&vm->mutex);

    LOGD("Compiling script '%s'", name);

    int status = luaL_loadbuffer(vm->L,
                                 script->source.text,
                                 strlen(script->source.text),
                                 name);
    if (status != LUA_OK)
    {
        const char *msg = lua_tostring(vm->L, -1);
        LOGE("Compile error in '%s': %s", name, msg ? msg : "(unknown)");
        lua_pop(vm->L, 1);
        pthread_mutex_unlock(&vm->mutex);
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    /* Execute the chunk to register globals (description, action, etc.) */
    status = lua_pcall(vm->L, 0, 0, 0);

    if (status != LUA_OK)
    {
        const char *msg = lua_tostring(vm->L, -1);
        LOGE("Top-level execution error in '%s': %s",
             name, msg ? msg : "(unknown)");
        lua_pop(vm->L, 1);
        pthread_mutex_unlock(&vm->mutex);
        return NPE_ERROR_SCRIPT_RUNTIME;
    }

    pthread_mutex_unlock(&vm->mutex);
    LOGD("Script '%s' compiled and registered", name);
    return NPE_OK;
}

/*============================================================================
 * npe_vm_load_script  (alias kept for backward compatibility)
 *============================================================================*/

npe_error_t npe_vm_load_script(npe_vm_t *vm, const npe_script_t *script)
{
    return npe_vm_compile(vm, script);
}

/*============================================================================
 * npe_vm_call_rule
 *============================================================================*/

npe_error_t npe_vm_call_rule(npe_vm_t *vm,
                             npe_phase_t phase,
                             const npe_host_t *host,
                             const npe_port_t *port,
                             bool *match)
{
    if (!vm || !vm->L || !match)
        return NPE_ERROR_INVALID_ARG;

    *match = false;

    const char *func_name = NULL;
    int nargs = 0;

    switch (phase)
    {
    case NPE_PHASE_PRERULE:
        func_name = "prerule";
        /* prerule() takes no arguments */
        break;
    case NPE_PHASE_HOSTRULE:
        func_name = "hostrule";
        nargs = 1; /* hostrule(host) */
        break;
    case NPE_PHASE_PORTRULE:
        func_name = "portrule";
        nargs = 2; /* portrule(host, port) */
        break;
    case NPE_PHASE_POSTRULE:
        func_name = "postrule";
        /* postrule() takes no arguments */
        break;
    default:
        LOGE("npe_vm_call_rule: unknown phase %d", (int)phase);
        return NPE_ERROR_INVALID_ARG;
    }

    pthread_mutex_lock(&vm->mutex);

    lua_getglobal(vm->L, func_name);
    if (!lua_isfunction(vm->L, -1))
    {
        /* Rule function not defined — script doesn't participate */
        lua_pop(vm->L, 1);
        pthread_mutex_unlock(&vm->mutex);
        *match = false;
        return NPE_OK;
    }

    /* Push arguments */
    if (phase == NPE_PHASE_HOSTRULE || phase == NPE_PHASE_PORTRULE)
    {
        if (!host)
        {
            lua_pop(vm->L, 1);
            pthread_mutex_unlock(&vm->mutex);
            return NPE_ERROR_INVALID_ARG;
        }
        push_host_table(vm->L, host);
    }
    if (phase == NPE_PHASE_PORTRULE)
    {
        if (!port)
        {
            lua_pop(vm->L, 2); /* function + host */
            pthread_mutex_unlock(&vm->mutex);
            return NPE_ERROR_INVALID_ARG;
        }
        push_port_table(vm->L, port);
    }

    vm->instruction_count = 0;
    atomic_store(&vm->abort_flag, false);

    int status = lua_pcall(vm->L, nargs, 1, 0);

    npe_error_t err = NPE_OK;

    if (status != LUA_OK)
    {
        const char *msg = lua_tostring(vm->L, -1);

        /* Distinguish abort from other runtime errors */
        if (msg && strstr(msg, "execution aborted"))
        {
            err = NPE_ERROR_SCRIPT_ABORTED;
            LOGW("%s() aborted", func_name);
        }
        else if (msg && strstr(msg, "instruction count limit"))
        {
            err = NPE_ERROR_TIMEOUT;
            LOGW("%s() hit instruction limit", func_name);
        }
        else
        {
            err = NPE_ERROR_SCRIPT_RUNTIME;
            LOGE("%s() runtime error: %s", func_name,
                 msg ? msg : "(unknown)");
        }
        lua_pop(vm->L, 1);
    }
    else
    {
        *match = lua_toboolean(vm->L, -1);
        lua_pop(vm->L, 1);
        LOGD("%s() → %s", func_name, *match ? "MATCH" : "no match");
    }

    pthread_mutex_unlock(&vm->mutex);
    return err;
}

/*============================================================================
 * npe_vm_call_action
 *============================================================================*/

npe_error_t npe_vm_call_action(npe_vm_t *vm,
                               const npe_host_t *host,
                               const npe_port_t *port,
                               npe_result_t *result)
{
    if (!vm || !vm->L)
        return NPE_ERROR_INVALID_ARG;

    pthread_mutex_lock(&vm->mutex);

    vm->instruction_count = 0;
    atomic_store(&vm->abort_flag, false);

    LOGD("Calling action coroutine (host=%p, port=%p)", (void *)host, (void *)port);

    vm_reset_coroutine(vm);

    lua_State *co = lua_newthread(vm->L);
    vm->co = co;
    vm->co_ref = luaL_ref(vm->L, LUA_REGISTRYINDEX);

    lua_getglobal(vm->L, "action");
    if (!lua_isfunction(vm->L, -1))
    {
        lua_pop(vm->L, 1);
        vm_reset_coroutine(vm);
        pthread_mutex_unlock(&vm->mutex);
        LOGE("action() not defined");
        return NPE_ERROR_INVALID_ARG;
    }

    lua_xmove(vm->L, co, 1);

    int nargs = 0;
    if (host)
    {
        push_host_table(co, host);
        nargs++;
    }
    if (port)
    {
        push_port_table(co, port);
        nargs++;
    }

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    int nresults = 0;
    int status = lua_resume(co, NULL, nargs, &nresults);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    double elapsed = (double)(ts_end.tv_sec - ts_start.tv_sec) * 1000.0 +
                     (double)(ts_end.tv_nsec - ts_start.tv_nsec) / 1e6;

    vm->executions++;

    npe_error_t err = NPE_OK;

    if (status == LUA_YIELD)
    {
        vm->yielded = true;
        vm_capture_yield_info(co, nresults, &vm->yield_info);
        lua_settop(co, 0);
        err = NPE_ERROR_IO;
    }
    else if (status != LUA_OK)
    {
        const char *msg = lua_tostring(co, -1);
        LOGE("lua_pcall failed: %s", msg ? msg : "(unknown)");

        if (msg && strstr(msg, "execution aborted"))
            err = NPE_ERROR_SCRIPT_ABORTED;
        else if (msg && strstr(msg, "instruction count limit"))
            err = NPE_ERROR_TIMEOUT;
        else
            err = NPE_ERROR_SCRIPT_RUNTIME;

        if (vm->ctx)
        {
            vm->ctx->last_error = err;
            if (msg)
            {
                strncpy(vm->ctx->last_error_msg, msg,
                        sizeof(vm->ctx->last_error_msg) - 1);
                vm->ctx->last_error_msg[sizeof(vm->ctx->last_error_msg) - 1] = '\0';
            }
        }
        lua_settop(co, 0);
        vm_reset_coroutine(vm);
    }
    else
    {
        if (result)
        {
            int top = lua_gettop(co);

            if (top > 0)
            {
                if (lua_isstring(co, top))
                {
                    const char *s = lua_tostring(co, top);
                    result->output.type = NPE_VAL_STRING;
                    result->output.v.s = s ? strdup(s) : NULL;
                }
                else if (lua_isinteger(co, top))
                {
                    result->output.type = NPE_VAL_INT;
                    result->output.v.i = (int64_t)lua_tointeger(co, top);
                }
                else if (lua_isnumber(co, top))
                {
                    result->output.type = NPE_VAL_FLOAT;
                    result->output.v.f = lua_tonumber(co, top);
                }
                else if (lua_isboolean(co, top))
                {
                    result->output.type = NPE_VAL_BOOL;
                    result->output.v.b = lua_toboolean(co, top);
                }
                else if (lua_istable(co, top))
                {
                    result->output.type = NPE_VAL_TABLE;
                }
                else
                {
                    result->output.type = NPE_VAL_NIL;
                }
            }
            else
            {
                result->output.type = NPE_VAL_NIL;
            }
        }
        lua_settop(co, 0);
        vm->yielded = false;
        memset(&vm->yield_info, 0, sizeof(vm->yield_info));
        vm_reset_coroutine(vm);
    }

    if (result)
    {
        result->status = err;
        result->elapsed_ms = elapsed;
    }

    pthread_mutex_unlock(&vm->mutex);
    return err;
}

/*============================================================================
 * Coroutine Yield / Resume
 *============================================================================*/

bool npe_vm_is_yielded(const npe_vm_t *vm)
{
    return vm ? vm->yielded : false;
}

npe_error_t npe_vm_yield_info(const npe_vm_t *vm,
                              npe_yield_info_t *info)
{
    if (!vm || !info)
        return NPE_ERROR_INVALID_ARG;
    if (!vm->yielded)
        return NPE_ERROR_INVALID_ARG;
    *info = vm->yield_info;
    return NPE_OK;
}

npe_error_t npe_vm_resume(npe_vm_t *vm, npe_error_t io_error)
{
    if (!vm || !vm->L || !vm->co)
        return NPE_ERROR_INVALID_ARG;
    if (!vm->yielded)
        return NPE_ERROR_INVALID_ARG;

    pthread_mutex_lock(&vm->mutex);

    /*
     * Push the I/O result onto the coroutine stack so the Lua code
     * that called coroutine.yield() receives it as the return value.
     *
     * Convention:
     *   - On success (io_error == NPE_OK): push true
     *   - On error:  push nil, error_string
     *
     * FIX #4: removed unused variable 'nresults'.
     */

    vm->yielded = false;
    memset(&vm->yield_info, 0, sizeof(vm->yield_info));

    int nresume_args;
    if (io_error == NPE_OK)
    {
        lua_pushboolean(vm->co, 1);
        nresume_args = 1;
    }
    else
    {
        lua_pushnil(vm->co);
        lua_pushstring(vm->co, npe_error_string(io_error));
        nresume_args = 2;
    }

    int nres = 0;
    int status = lua_resume(vm->co, NULL, nresume_args, &nres);

    npe_error_t err = NPE_OK;

    switch (status)
    {
    case LUA_OK:
        /*
         * Coroutine finished — clean return values off the stack.
         */
        LOGD("VM resume: coroutine completed");
        lua_settop(vm->co, 0);
        vm_reset_coroutine(vm);
        break;

    case LUA_YIELD:
        /*
         * Coroutine yielded again (another async I/O request).
         * Capture yield info from the values the script pushed before
         * calling coroutine.yield().
         *
         * Convention: yield(type_string, fd_or_handle, timeout_ms)
         */
        vm->yielded = true;
        vm_capture_yield_info(vm->co, nres, &vm->yield_info);

        /* Pop yield return values */
        lua_settop(vm->co, 0);

        LOGD("VM resume: yielded again (type=%d, fd=%d, timeout=%d)",
             vm->yield_info.type,
             vm->yield_info.fd,
             vm->yield_info.timeout_ms);
        break;

    default:
    {
        /* Runtime error during resume */
        const char *msg = lua_tostring(vm->co, -1);

        if (msg && strstr(msg, "execution aborted"))
            err = NPE_ERROR_SCRIPT_ABORTED;
        else if (msg && strstr(msg, "instruction count limit"))
            err = NPE_ERROR_TIMEOUT;
        else
            err = NPE_ERROR_SCRIPT_RUNTIME;

        LOGE("VM resume error: %s", msg ? msg : "(unknown)");
        lua_settop(vm->co, 0);
        vm_reset_coroutine(vm);
        break;
    }
    }

    pthread_mutex_unlock(&vm->mutex);
    return err;
}

/*============================================================================
 * Query Helpers
 *============================================================================*/

size_t npe_vm_memory_usage(const npe_vm_t *vm)
{
    return vm ? vm->memory_used : 0;
}

uint64_t npe_vm_instruction_count(const npe_vm_t *vm)
{
    return vm ? vm->instruction_count : 0;
}

/*============================================================================
 * npe_vm_abort
 *============================================================================*/

npe_error_t npe_vm_abort(npe_vm_t *vm)
{
    if (!vm)
        return NPE_ERROR_INVALID_ARG;

    atomic_store(&vm->abort_flag, true);
    LOGD("VM abort requested");
    return NPE_OK;
}

/*============================================================================
 * VM Pool — Create
 *============================================================================*/

npe_error_t npe_vm_pool_create(const npe_vm_pool_config_t *config,
                               npe_vm_pool_t **out)
{
    if (!out)
        return NPE_ERROR_INVALID_ARG;
    *out = NULL;

    npe_vm_pool_t *pool = calloc(1, sizeof(npe_vm_pool_t));
    if (!pool)
        return NPE_ERROR_MEMORY;

    if (config)
        pool->config = *config;
    else
        pool->config.initial_size = VM_POOL_DEFAULT_INITIAL_SIZE;

    size_t n = pool->config.initial_size;
    if (n == 0)
        n = VM_POOL_DEFAULT_INITIAL_SIZE;

    pool->entries = calloc(n, sizeof(vm_pool_entry_t));
    if (!pool->entries)
    {
        free(pool);
        return NPE_ERROR_MEMORY;
    }

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->available, NULL);

    pool->total_count = 0;
    pool->in_use_count = 0;
    pool->shutdown = false;

    /* Pre-create VMs */
    for (size_t i = 0; i < n; i++)
    {
        npe_vm_t *vm = NULL;

        /* FIX #5: vm_config is already const npe_runtime_config_t * */
        npe_error_t err = npe_vm_create(pool->config.vm_config, &vm);
        if (err != NPE_OK)
        {
            LOGE("Pool: failed to create VM %zu/%zu: %s",
                 i, n, npe_error_string(err));

            /* Destroy already-created VMs and clean up */
            for (size_t j = 0; j < pool->total_count; j++)
            {
                npe_vm_destroy(&pool->entries[j].vm);
            }
            pthread_mutex_destroy(&pool->mutex);
            pthread_cond_destroy(&pool->available);
            free(pool->entries);
            free(pool);
            return err;
        }

        pool->entries[i].vm = vm;
        pool->entries[i].in_use = false;
        pool->entries[i].next = NULL;
        pool->total_count++;
    }

    LOGI("VM pool created: %zu VMs", pool->total_count);

    *out = pool;
    return NPE_OK;
}

/*============================================================================
 * VM Pool — Destroy
 *============================================================================*/

void npe_vm_pool_destroy(npe_vm_pool_t **pool)
{
    if (!pool || !*pool)
        return;

    npe_vm_pool_t *p = *pool;

    /* Signal shutdown to unblock any threads waiting in acquire */
    pthread_mutex_lock(&p->mutex);
    p->shutdown = true;
    pthread_cond_broadcast(&p->available);
    pthread_mutex_unlock(&p->mutex);

    /*
     * Give brief window for blocked threads to wake and exit.
     * In a real system the caller should ensure no threads are
     * still calling acquire before destroying the pool.
     */
    struct timespec ts = {0, 10 * 1000 * 1000}; /* 10 ms */
    nanosleep(&ts, NULL);

    for (size_t i = 0; i < p->total_count; i++)
    {
        if (p->entries[i].vm)
        {
            if (p->entries[i].in_use)
            {
                LOGW("Pool destroy: VM %zu still in use — forcing destroy", i);
            }
            npe_vm_destroy(&p->entries[i].vm);
        }
    }

    pthread_mutex_destroy(&p->mutex);
    pthread_cond_destroy(&p->available);
    free(p->entries);
    free(p);
    *pool = NULL;

    LOGI("VM pool destroyed");
}

/*============================================================================
 * VM Pool — Acquire
 *
 * FIX: This was the PRIMARY cause of the worker-thread freeze.
 *      Previously there was no shutdown check, so threads blocked
 *      forever on pthread_cond_wait when the engine was shutting
 *      down and all VMs were in use.
 *============================================================================*/

npe_error_t npe_vm_pool_acquire(npe_vm_pool_t *pool, npe_vm_t **out)
{
    if (!pool || !out)
        return NPE_ERROR_INVALID_ARG;
    *out = NULL;

    pthread_mutex_lock(&pool->mutex);

    /* Wait until a VM becomes available OR the pool shuts down */
    while (!pool->shutdown)
    {
        /* Scan for a free VM */
        for (size_t i = 0; i < pool->total_count; i++)
        {
            if (!pool->entries[i].in_use && pool->entries[i].vm)
            {
                pool->entries[i].in_use = true;
                pool->in_use_count++;
                *out = pool->entries[i].vm;

                LOGD("Pool acquire: VM %zu (in_use=%zu/%zu)",
                     i, pool->in_use_count, pool->total_count);

                pthread_mutex_unlock(&pool->mutex);
                return NPE_OK;
            }
        }

        /*
         * No VM available right now — block until one is released
         * or the pool shuts down.
         */
        LOGD("Pool acquire: all %zu VMs busy — waiting", pool->total_count);
        pthread_cond_wait(&pool->available, &pool->mutex);
    }

    /*
     * If we reach here, the pool is shutting down.
     * Unblock the caller with an error so the worker thread can exit.
     */
    pthread_mutex_unlock(&pool->mutex);
    LOGW("Pool acquire: pool is shutting down");
    return NPE_ERROR_GENERIC;
}

/*============================================================================
 * VM Pool — Release
 *
 * Signature matches header: npe_vm_pool_release(pool, npe_vm_t **vm)
 * Sets *vm = NULL after release for caller safety.
 *
 * FIX: Do NOT call npe_vm_reset while holding pool->mutex,
 *      because reset locks vm->mutex internally. Reset outside
 *      the critical section to avoid ABBA deadlock.
 *============================================================================*/

npe_error_t npe_vm_pool_release(npe_vm_pool_t *pool, npe_vm_t **vm)
{
    if (!pool || !vm || !*vm)
        return NPE_ERROR_INVALID_ARG;

    npe_vm_t *released_vm = *vm;
    *vm = NULL; /* Prevent caller from using it after release */

    /*
     * Reset the VM OUTSIDE the pool lock to avoid lock ordering issues.
     * vm->mutex is acquired inside npe_vm_reset; if we held pool->mutex
     * here we would create a potential ABBA deadlock with other paths
     * that lock vm->mutex first then pool->mutex.
     */
    npe_error_t reset_err = npe_vm_reset(released_vm);
    if (reset_err != NPE_OK)
    {
        LOGW("Pool release: VM reset failed (%s), returning anyway",
             npe_error_string(reset_err));
    }

    pthread_mutex_lock(&pool->mutex);

    bool found = false;
    for (size_t i = 0; i < pool->total_count; i++)
    {
        if (pool->entries[i].vm == released_vm)
        {
            pool->entries[i].in_use = false;
            if (pool->in_use_count > 0)
                pool->in_use_count--;
            found = true;

            LOGD("Pool release: VM %zu (in_use=%zu/%zu)",
                 i, pool->in_use_count, pool->total_count);
            break;
        }
    }

    if (!found)
    {
        LOGE("Pool release: VM %p not found in pool — this is a bug",
             (void *)released_vm);
        pthread_mutex_unlock(&pool->mutex);
        return NPE_ERROR_GENERIC;
    }

    /* Wake ONE thread waiting in acquire */
    pthread_cond_signal(&pool->available);

    pthread_mutex_unlock(&pool->mutex);
    return NPE_OK;
}

/*============================================================================
 * VM Pool — Statistics
 *============================================================================*/

size_t npe_vm_pool_idle_count(const npe_vm_pool_t *pool)
{
    if (!pool)
        return 0;

    /*
     * We need the lock to read in_use_count safely, but the
     * header declares this as taking const*.  We cast away const
     * for the mutex — this is acceptable for a diagnostic function.
     */
    npe_vm_pool_t *p = (npe_vm_pool_t *)pool;

    pthread_mutex_lock(&p->mutex);
    size_t idle = (p->total_count > p->in_use_count)
                      ? (p->total_count - p->in_use_count)
                      : 0;
    pthread_mutex_unlock(&p->mutex);

    return idle;
}

size_t npe_vm_pool_total_count(const npe_vm_pool_t *pool)
{
    if (!pool)
        return 0;

    npe_vm_pool_t *p = (npe_vm_pool_t *)pool;

    pthread_mutex_lock(&p->mutex);
    size_t total = p->total_count;
    pthread_mutex_unlock(&p->mutex);

    return total;
}
