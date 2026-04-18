#ifndef NPE_LIB_DNS_H
#define NPE_LIB_DNS_H

#include <lua.h>
#include <lauxlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <arpa/inet.h>   /* INET6_ADDRSTRLEN */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DNS CONSTANTS
 * ============================================================================ */

#define NPE_DNS_MAX_NAME_LEN        253
#define NPE_DNS_MAX_RECORDS         256
#define NPE_DNS_DEFAULT_TIMEOUT     5000
#define NPE_DNS_DEFAULT_TIMEOUT_MS  5000
#define NPE_DNS_PORT                53

/* ============================================================================
 * DNS RECORD TYPES
 * ============================================================================ */

typedef enum {
    NPE_DNS_A     = 1,
    NPE_DNS_NS    = 2,
    NPE_DNS_CNAME = 5,
    NPE_DNS_SOA   = 6,
    NPE_DNS_PTR   = 12,
    NPE_DNS_MX    = 15,
    NPE_DNS_TXT   = 16,
    NPE_DNS_AAAA  = 28,
    NPE_DNS_SRV   = 33,
    NPE_DNS_ANY   = 255
} npe_dns_type_t;

/* ============================================================================
 * DNS RESPONSE STRUCTURES
 * ============================================================================ */

typedef struct {
    char     name[NPE_DNS_MAX_NAME_LEN + 1];
    uint16_t type;
    uint32_t ttl;
    char     value[1024];

    /* MX / SRV fields */
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char     target[NPE_DNS_MAX_NAME_LEN + 1];

    /* SOA fields */
    uint32_t soa_serial;
    uint32_t soa_refresh;
    uint32_t soa_retry;
    uint32_t soa_expire;
    uint32_t soa_minimum;
    char     soa_mname[NPE_DNS_MAX_NAME_LEN + 1];
    char     soa_rname[NPE_DNS_MAX_NAME_LEN + 1];
} npe_dns_record_t;

typedef struct {
    npe_dns_record_t *records;          /* heap-allocated array */
    size_t            record_count;
    int               rcode;
    int               is_truncated;
    int               is_authoritative;
    bool              used_tcp;
    double            elapsed_ms;

    /* Query metadata */
    uint16_t          qtype;
    char              hostname[NPE_DNS_MAX_NAME_LEN + 1];
    char              nameserver[INET6_ADDRSTRLEN];
} npe_dns_result_t;

/* ============================================================================
 * C-LEVEL API
 * ============================================================================ */

int  npe_dns_query(const char *hostname, uint16_t qtype,
                   const char *nameserver, uint32_t timeout_ms,
                   npe_dns_result_t *result);
int  npe_dns_resolve(const char *hostname, const char *nameserver,
                     uint32_t timeout_ms, npe_dns_result_t *result);
int  npe_dns_resolve6(const char *hostname, const char *nameserver,
                      uint32_t timeout_ms, npe_dns_result_t *result);
int  npe_dns_reverse(const char *ip, const char *nameserver,
                     uint32_t timeout_ms, npe_dns_result_t *result);
int  npe_dns_mx(const char *hostname, const char *nameserver,
                uint32_t timeout_ms, npe_dns_result_t *result);
int  npe_dns_ns(const char *hostname, const char *nameserver,
                uint32_t timeout_ms, npe_dns_result_t *result);
int  npe_dns_txt(const char *hostname, const char *nameserver,
                 uint32_t timeout_ms, npe_dns_result_t *result);
int  npe_dns_srv(const char *hostname, const char *nameserver,
                 uint32_t timeout_ms, npe_dns_result_t *result);
int  npe_dns_soa(const char *hostname, const char *nameserver,
                 uint32_t timeout_ms, npe_dns_result_t *result);
void npe_dns_result_free(npe_dns_result_t *result);

/* ============================================================================
 * LUA API FUNCTIONS
 * ============================================================================ */

int npe_lua_dns_resolve(lua_State *L);
int npe_lua_dns_resolve6(lua_State *L);
int npe_lua_dns_reverse(lua_State *L);
int npe_lua_dns_mx(lua_State *L);
int npe_lua_dns_ns(lua_State *L);
int npe_lua_dns_txt(lua_State *L);
int npe_lua_dns_srv(lua_State *L);
int npe_lua_dns_soa(lua_State *L);
int npe_lua_dns_axfr(lua_State *L);
int npe_lua_dns_query(lua_State *L);

/* ============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================ */

int npe_lib_dns_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_DNS_H */
