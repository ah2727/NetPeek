#ifndef NP_SCANNER_INTERNAL_H
#define NP_SCANNER_INTERNAL_H

#define _POSIX_C_SOURCE 200809L

#include "recon/submodules/scanner/scanner.h"
#include "target.h"
#include "event_loop.h"
#include "metrics.h"
#include "utils.h"
#include "ports.h"
#include "netpeek.h"

#include <stdint.h>
#include <signal.h>
#include <pthread.h>



#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

/* tuning */
#define CONNS_PER_THREAD 128
#define NP_MAX_PORT_ATTEMPTS 3

/* UDP probe payload size (0-byte payloads are not reliably transmitted) */
#define NP_UDP_PROBE_LEN 1


#pragma once


/* ─── Work item: the SINGLE source of truth for port / target / index ─── */
typedef enum
{
    UDP_STATE_PROBING = 0,
    UDP_STATE_RESPONDED,
    UDP_STATE_ICMP_SEEN,
    UDP_STATE_TIMED_OUT
} udp_internal_state_t;

typedef struct
{
    uint16_t port;       /* actual port number — always valid */
    uint32_t target_idx; /* index into cfg->targets[]          */
    uint32_t port_idx;   /* flat 0-based index into results[]  */
    uint8_t attempt;     /* retry counter                      */
} np_work_item_t;

typedef struct
{
    np_work_item_t *items;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t size;
    pthread_mutex_t lock;
} np_work_queue_t;

/*
 * Connection slot — one in-flight socket.
 *
 * ✅ FIXED: Removed redundant target_idx / port_idx / port / attempt
 *    fields that previously shadowed item.* and caused silent mismatches.
 *    ALL consumers MUST use slot->item.port, slot->item.port_idx, etc.
 */
typedef struct
{
    int fd;
    np_work_item_t item; /* canonical tuple for this in-flight slot */
    np_timer_t timer;
    uint16_t local_src_port;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    int peer_af;
    uint16_t peer_port;
    uint8_t probes_sent;
    uint8_t probes_acked;
    uint8_t current_probe_idx;
    uint8_t dynamic_max_retries;
    udp_internal_state_t istate;
    size_t last_sent_len;
    double srtt_ms;
    double rttvar_ms;
    uint64_t zombie_until_us;
    np_port_state_t final_pending_state;
    char final_pending_reason[64];
    double final_pending_confidence;
    bool active;
    bool completed;
    bool done;
    bool zombie;
} conn_slot_t;

typedef struct
{
    np_config_t *cfg;
    np_work_queue_t *queue;
    volatile sig_atomic_t *interrupted;
    np_metrics_t *metrics;

    pthread_mutex_t *metrics_lock;

    uint32_t total_work;
    uint32_t *completed_work;
    pthread_mutex_t *completed_lock;
    
} np_worker_ctx_t;

typedef struct
{
    pthread_mutex_t lock;
    pthread_cond_t cond;
    uint32_t pending;
} np_completion_t;



/* ───────────────────────────────────────────── */
/* Scan execution context (shared by workers)    */
/* ───────────────────────────────────────────── */

typedef struct np_scan_ctx
{
    np_config_t *cfg;
    np_work_queue_t *queue;
    volatile sig_atomic_t *interrupted;
    np_metrics_t *metrics;
    pthread_mutex_t *metrics_lock;
    uint32_t total_work;
    uint32_t *completed_work;
    pthread_mutex_t *completed_lock;

} np_scan_ctx_t;

typedef struct np_task_arg
{
    np_scan_ctx_t      ctx;
    np_completion_t   *completion;
} np_task_arg_t;

/* queue */
np_status_t np_wq_init(np_work_queue_t *q, uint32_t capacity);
void np_wq_destroy(np_work_queue_t *q);
bool np_wq_pop(np_work_queue_t *q, np_work_item_t *out);
bool np_wq_push(np_work_queue_t *q, const np_work_item_t *item);
uint32_t np_wq_popped_count(np_work_queue_t *q);

/* completion */
void np_completion_init(np_completion_t *c, uint32_t count);
void np_completion_signal(np_completion_t *c);
void np_completion_wait(np_completion_t *c);
void np_completion_destroy(np_completion_t *c);

/* sockets */
int np_set_nonblocking(int fd);
int np_get_socket_error(int fd);
np_connect_rc_t np_start_connect(const np_target_t *target,
                                 uint16_t port,
                                 int timeout_ms,
                                 int *out_fd);

np_connect_rc_t np_start_connect_proxy(const np_proxy_t *proxy,
                                       const np_target_t *target,
                                       uint16_t port,
                                       uint32_t timeout_ms,
                                       int *out_fd);
int np_start_udp(const np_target_t *target, uint16_t port);

/* results */
void np_record_result(np_worker_ctx_t *ctx,
                      uint32_t target_idx,
                      uint32_t port_idx,
                      uint16_t port,
                      np_port_state_t state,
                      double rtt);

void np_mark_unstarted_remaining(np_worker_ctx_t *ctx);
void np_mark_active_interrupted(np_worker_ctx_t *ctx,
                                conn_slot_t *slots,
                                int n);

/* worker */
void np_scan_task(void *arg);
void np_udp_scan_task(void *arg);
void np_syn_scan_task(void *arg); 
void np_sctp_scan_task(void *arg);
void np_ipproto_scan_task(void *arg);
void np_idle_scan_task(void *arg);

np_status_t np_scanner_run_single_target_internal(np_config_t *cfg,
                                                  volatile sig_atomic_t *interrupted,
                                                  bool syn_shared);

np_status_t np_scan_os_detect_run_target(np_config_t *cfg,
                                         uint32_t target_idx);
np_status_t np_scan_os_detect_run(np_config_t *cfg,
                                  volatile sig_atomic_t *interrupted);

np_status_t np_udp_require_icmp_support(const np_config_t *cfg);
/* helpers */
void np_print_progress(np_work_queue_t *q,
                       uint32_t total_work,
                       uint32_t completed_work);

/* timing */
uint64_t np_now_monotonic_us(void);
bool np_host_timeout_reached(const np_config_t *cfg, uint64_t started_us);
void np_wait_probe_budget(const np_config_t *cfg, uint64_t *last_probe_us);
void np_note_probe_sent(const np_config_t *cfg);
void np_note_probe_retransmission(const np_config_t *cfg);
uint32_t np_effective_timeout_ms(const np_config_t *cfg);
void np_timing_note_rst_observation(const np_config_t *cfg, uint64_t now_us);

/* ───────────────────────────────────────────── */
/* SYN Scan Engine                               */
/* ───────────────────────────────────────────── */

np_status_t np_syn_init(void);
void np_syn_close(void);
void np_send_syn(const np_target_t *t, uint16_t port, const np_evasion_t *ev);
void np_syn_set_tcp_flags(uint8_t flags);

/* ───────────────────────────────────────────── */
/* ICMP Listener (for filtered detection)        */
/* ───────────────────────────────────────────── */

np_status_t np_icmp_init(void);
void np_icmp_close(void);
bool np_icmp_unreachable_seen(void);

uint16_t np_random_ephemeral_port(void);

/* Register SYN probe for RTT + correlation */
extern void np_syn_register_probe(uint16_t src_port,
                                  uint16_t dst_port,
                                  struct timeval *ts);

#endif /* NP_SCANNER_INTERNAL_H */
