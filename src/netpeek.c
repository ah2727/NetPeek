#define _POSIX_C_SOURCE 200809L

#include "netpeek.h"
#include "target.h"

#include <stdlib.h>

/* ───────────────────────────────────────────── */
/* Config lifecycle                             */
/* ───────────────────────────────────────────── */

np_config_t *np_config_create(void)
{
    np_config_t *cfg = calloc(1, sizeof(np_config_t));

    if (!cfg)
        return NULL;
        
    np_evasion_init(&cfg->evasion);
    cfg->threads = NP_DEFAULT_THREADS;
    cfg->timeout_ms = NP_DEFAULT_TIMEOUT;
    cfg->scan_type = NP_SCAN_TCP_CONNECT;
    cfg->scan_type_forced = false;
    cfg->framework_mode = false;
    cfg->engine_mode = NP_ENGINE_LEGACY;
    cfg->auth_mode = NP_AUTH_MODE_INTRUSIVE;
    cfg->full_rx_threads = 2;
    cfg->full_queue_capacity = 1u << 16;
    cfg->full_max_inflight = 4096;
    cfg->full_enable_host_affinity = true;
    cfg->service_version_detect = false;
    cfg->version_intensity = 7;
    cfg->version_trace = false;
    cfg->tls_info = false;
    cfg->host_discovery_mode = NP_HOST_DISCOVERY_DEFAULT;
    cfg->host_discovery_done = false;
    cfg->dns_mode = NP_DNS_AUTO;
    cfg->traceroute_enabled = false;
    cfg->tcp_custom_flags = 0;
    cfg->zombie_probe_port = 80;
    cfg->output_fmt = NP_OUTPUT_PLAIN;
    cfg->recon_output_format = NULL;
    cfg->recon_subcommand = NULL;
    cfg->recon_style = NP_RECON_STYLE_MODERN;
    cfg->recon_style_explicit = false;
    cfg->recon_format_explicit = false;
    cfg->recon_cli_mode = false;
    cfg->recon_no_color = false;
    cfg->recon_compact = false;
    cfg->recon_summary_only = false;
    cfg->recon_verbose_detail = false;
    cfg->recon_force_serial = false;
    cfg->recon_workers = 0;
    cfg->suppress_progress = false;
    cfg->pretty_output = false;
    cfg->show_evidence = false;
    cfg->show_closed = false;
    cfg->drop_filtered_states = true;
    cfg->verbosity = NP_LOG_NORMAL;
    cfg->retries = 1;
    cfg->min_rate = 10;
    cfg->max_rate = 1000;
    cfg->max_retries = 2;
    cfg->timing_template = NP_TIMING_TEMPLATE_UNSET;
    cfg->fast_mode = false;
    cfg->min_hostgroup = 1;
    cfg->max_hostgroup = 0;
    cfg->min_parallelism = 1;
    cfg->max_parallelism = 0;
    cfg->min_rtt_timeout_ms = 100;
    cfg->max_rtt_timeout_ms = 10000;
    cfg->initial_rtt_timeout_ms = cfg->timeout_ms;
    cfg->host_timeout_ms = 0;
    cfg->scan_delay_us = 0;
    cfg->max_scan_delay_us = 0;
    cfg->udp_fast_path_mode = NP_UDP_FAST_PATH_AUTO;
    cfg->udp_batch_size = 32;
    cfg->udp_inflight_per_thread = 256;
    cfg->udp_min_probe_interval_us = 50000;
    cfg->udp_linux_advanced = false;
    cfg->os_detect = false;
    cfg->allow_partial_os_detect = false;
    cfg->osscan_guess = false;
    cfg->osscan_limit = false;
    cfg->os_builtin_only = false;
    cfg->os_target_port = 0;
    cfg->os_target_input = NULL;
    cfg->os_sigfile_path = NULL;

    return cfg;
}

void np_config_destroy(np_config_t *cfg)
{
    if (!cfg)
        return;

    for (uint32_t i = 0; i < cfg->target_count; i++)
        np_target_free_results(&cfg->targets[i]);

    free(cfg->targets);
    free(cfg->port_ranges);
    free(cfg->port_list);

    free(cfg);
}

/* ───────────────────────────────────────────── */
/* Status strings                               */
/* ───────────────────────────────────────────── */

const char *np_status_str(np_status_t s)
{
    switch (s)
    {

    case NP_OK:
        return "ok";

    case NP_ERR_ARGS:
        return "argument error";

    case NP_ERR_RESOLVE:
        return "host resolution failed";

    case NP_ERR_SOCKET:
        return "socket error";

    case NP_ERR_MEMORY:
        return "out of memory";

    case NP_ERR_PERMISSION:
        return "permission denied";

    case NP_STATUS_ERR_IO:
        return "I/O error";

    case NP_ERR_SYSTEM:
        return "system error";

    case NP_ERR_PRIVILEGE_REQUIRED:
        return "privilege required";

    default:
        return "unknown error";
    }
}

/* ───────────────────────────────────────────── */
/* Port state strings                           */
/* ───────────────────────────────────────────── */

const char *np_port_state_str(np_port_state_t state)
{
    switch (state)
    {

    case NP_PORT_OPEN:
        return "open";

    case NP_PORT_CLOSED:
        return "closed";

    case NP_PORT_FILTERED:
        return "filtered";

    case NP_PORT_UNKNOWN:

    case NP_PORT_OPEN_FILTERED:
        return "open|filtered";
    default:
        return "unknown";
    }
}
