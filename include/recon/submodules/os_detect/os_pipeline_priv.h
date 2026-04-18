#ifndef NP_OS_PIPELINE_PRIV_H
#define NP_OS_PIPELINE_PRIV_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h> /* sockaddr_in */

/* ================================================================
 *  Global Synchronization Primitives
 * ================================================================ */
#include <pthread.h>

extern pthread_mutex_t pipe_mutex;
extern pthread_mutex_t ctx_port_mutex;
/* ================================================================
 *  Pipeline Internal Configuration
 * ================================================================ */
#define NUM_STAGE2_THREADS 100
#define NUM_SCAN_THREADS 1000
#define MAX_PORTS_TO_SCAN 1024

/* ================================================================
 *  Core Project Type Includes
 * ================================================================ */
#include "recon/submodules/os_detect/os_detect.h"
#include "os_sigload.h"
#include "os_banner.h"
#include "os_db.h"
#include "os_port_discovery.h"
#include "os_tcp_probes.h"
#include "tcp_fp.h"
#include "os_fingerprint_types.h"
#include "os_pipeline_config.h"

/* ================================================================
 *  Internal Pipeline Context: Holds all state between stages
 * ================================================================ */
typedef struct np_pipeline_ctx_s
{
    /* === Inputs === */
    char target_ip[INET_ADDRSTRLEN];
    uint16_t user_port;
    const np_os_sigdb_t *db;
    bool is_localhost;
    void *config;

    /* === Stage 1: Port Discovery === */
    uint16_t open_ports[NP_PIPELINE_MAX_OPEN_PORTS];
    uint32_t open_port_count;
    uint16_t primary_open_port;
    uint16_t closed_port;

    /* === Stage 2: TCP Probing === */
    np_tcp_probe_set_t probe_results;
    np_tcp_fp_vector_t active_vector;
    bool probes_valid;
    uint32_t probe_response_count;

    /* === Stage 3: Fingerprint Build === */
    np_os_fingerprint_t fingerprint;
    bool fingerprint_valid;
    bool fingerprint_all_zero;

    /* === Stage 4: Behavior Matching === */
    const char *behavior_os_name;
    uint8_t behavior_score;
    bool behavior_valid;

    /* === Stage 5: Fingerprint Matching === */
    const np_os_fp_sig_t *fp_best_sig;
    uint8_t fp_score;
    bool fp_valid;

    np_os_match_t candidates[NP_MAX_CANDIDATES];
    int candidate_count;


    /* === Stage 7: Confidence Fusion / Final Result === */
    char final_os_name[NP_OS_NAME_LEN];
    char final_os_family[NP_OS_FAMILY_LEN];
    double final_confidence;

    np_os_result_t os_result;

    const char *banner_os;

    /* === Stage 6: Banner Grab === */
    np_os_banner_t banners[NP_PIPELINE_MAX_BANNER_PORTS];
    uint32_t banner_count;
    int banner_match_count; /* <-- ADD THIS */
    char banner_os_name[NP_OS_NAME_LEN];
    double banner_confidence;
    bool banner_valid;
} np_pipeline_ctx_t;

/* ================================================================
 *  Thread Task Structures
 * ================================================================ */
typedef struct
{
    np_pipeline_ctx_t *ctx;
    const uint16_t *ports_to_scan;
    int num_ports;
} port_scan_task_t;

typedef struct
{
    np_pipeline_ctx_t *ctx;
    uint16_t specific_port;
} np_banner_task_t;

typedef struct
{
    uint8_t initial_ttl;
    uint8_t min_dist;
    uint8_t max_dist;
    const char *os_name;
    double confidence;
} np_ttl_fp_t;
#define TTL_FP_COUNT (sizeof(ttl_fingerprints) / sizeof(ttl_fingerprints[0]))

/* ================================================================
 *  Internal Logging Interface
 * ================================================================ */
typedef enum
{
    NP_PIPE_LOG_INFO = 0,
    NP_PIPE_LOG_WARN = 1,
    NP_PIPE_LOG_ERR = 2,
    NP_PIPE_LOG_DEBUG = 3
} np_pipe_log_level_t;

void pipe_log(np_pipe_log_level_t level, const char *stage,
              const char *fmt, ...);

/* ================================================================
 *  Utility Helpers
 * ================================================================ */
bool is_localhost_address(const char *ip);
void derive_os_family(const char *os_name, char *family, size_t family_sz);
bool fingerprint_is_all_zero(const np_os_fingerprint_t *fp);
int get_ttl_from_connect(const char *ip, uint16_t port, uint32_t timeout_ms);
const char *guess_os_from_ttl(int ttl);

/* ================================================================
 *  Stage Function Declarations
 * ================================================================ */
int stage_port_discovery(np_pipeline_ctx_t *ctx);
int stage_tcp_probes(np_pipeline_ctx_t *ctx);
int stage_fingerprint_build(np_pipeline_ctx_t *ctx);
int stage_fingerprint_match(np_pipeline_ctx_t *ctx);
int stage_banner_grab(np_pipeline_ctx_t *ctx);
int stage_confidence_fusion(np_pipeline_ctx_t *ctx);
void detect_localhost_os(np_pipeline_ctx_t *ctx);
int stage_banner_collect(np_pipeline_ctx_t *ctx);
/* ================================================================
 *  Internal Helper Routines
 * ================================================================ */
int np_os_pipeline_run_probes(const char *target_ip,
                              uint16_t open_port,
                              uint16_t closed_port,
                              const np_config_t *config,
                              np_tcp_probe_set_t *responses);

int np_os_pipeline_build_fingerprint(const np_tcp_probe_set_t *responses,
                                     np_os_fingerprint_t *fp);

const char *np_os_pipeline_behavior_match(const np_tcp_probe_set_t *probes,
                                          int *out_score);

const np_os_fp_sig_t *np_os_pipeline_fp_match(const np_os_fingerprint_t *fp,
                                              const np_os_sigdb_t *db,
                                              int *score);

void *thread_port_discovery_worker(void *arg);

#endif /* NP_OS_PIPELINE_PRIV_H */
