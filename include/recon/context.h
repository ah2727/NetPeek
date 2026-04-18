#ifndef NP_RECON_CONTEXT_H
#define NP_RECON_CONTEXT_H

#include <stdint.h>
#include <time.h>
#include <signal.h>

#include "netpeek.h"

typedef struct np_recon_context
{
    np_config_t *cfg;

    uint64_t run_id;
    time_t start_ts;
    time_t end_ts;
    uint64_t start_mono_ns;
    uint64_t end_mono_ns;

    void *graph;
    void *modules;
    void *evidence;

    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t hosts_seen;
    uint64_t services_seen;

    volatile sig_atomic_t *interrupted;
} np_recon_context_t;

np_recon_context_t *np_recon_create(np_config_t *cfg);
void np_recon_destroy(np_recon_context_t *ctx);

#endif
