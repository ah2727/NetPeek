/*****************************************************************************
 * npe_lib_brute.h — Brute-force attack framework
 *
 * Provides reusable credential brute-force logic for NPE scripts.
 * Supports dictionary attacks, combinatorial generation, adaptive delays,
 * multi-threading, and protocol‑specific authentication callbacks.
 *
 * Lua API:
 *   brute.new(options)
 *   brute:add_username_list(list)
 *   brute:add_password_list(list)
 *   brute:run(callback)
 *   brute:stop()
 *
 *****************************************************************************/

#ifndef NPE_LIB_BRUTE_H
#define NPE_LIB_BRUTE_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct npe_vm npe_vm_t;
typedef struct npe_context npe_context_t;

typedef struct npe_brute_engine npe_brute_engine_t;

/* credential pair */
typedef struct npe_brute_cred {
    const char *username;
    const char *password;
} npe_brute_cred_t;

/* brute result */
typedef struct npe_brute_result {
    bool success;
    const char *username;
    const char *password;
    int attempts;
} npe_brute_result_t;

/* brute options */
typedef struct npe_brute_options {

    uint32_t threads;
    uint32_t max_attempts;
    uint32_t delay_ms;
    uint32_t timeout_ms;

    bool stop_on_success;
    bool randomize;

} npe_brute_options_t;

/* callback signature used by protocol modules */
typedef npe_error_t (*npe_brute_auth_cb)(
        const char *username,
        const char *password,
        void *userdata,
        bool *success);

/* engine lifecycle */
npe_error_t npe_brute_create(
        const npe_brute_options_t *options,
        npe_brute_engine_t **engine);

void npe_brute_destroy(
        npe_brute_engine_t *engine);

/* credential lists */
npe_error_t npe_brute_add_username(
        npe_brute_engine_t *engine,
        const char *username);

npe_error_t npe_brute_add_password(
        npe_brute_engine_t *engine,
        const char *password);

npe_error_t npe_brute_load_username_file(
        npe_brute_engine_t *engine,
        const char *path);

npe_error_t npe_brute_load_password_file(
        npe_brute_engine_t *engine,
        const char *path);

/* execution */
npe_error_t npe_brute_run(
        npe_brute_engine_t *engine,
        npe_brute_auth_cb callback,
        void *userdata,
        npe_brute_result_t *result);

/* stop execution */
void npe_brute_stop(
        npe_brute_engine_t *engine);

/* statistics */
typedef struct npe_brute_stats {

    uint64_t attempts;
    uint64_t successes;
    uint64_t failures;
    uint64_t elapsed_ms;

} npe_brute_stats_t;

npe_error_t npe_brute_get_stats(
        npe_brute_engine_t *engine,
        npe_brute_stats_t *stats);

/* Lua binding */
npe_error_t npe_brute_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif
