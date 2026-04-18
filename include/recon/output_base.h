#ifndef NP_RECON_OUTPUT_BASE_H
#define NP_RECON_OUTPUT_BASE_H

#include <stdbool.h>
#include <stdint.h>

#include "recon/context.h"

typedef enum {
    NP_OUTPUT_CMD_RECON = 0,
    NP_OUTPUT_CMD_SCAN,
    NP_OUTPUT_CMD_OS_DETECT,
    NP_OUTPUT_CMD_ROUTE,
    NP_OUTPUT_CMD_SUBENUM,
    NP_OUTPUT_CMD_DNS,
    NP_OUTPUT_CMD_NPE,
    NP_OUTPUT_CMD_DIFF
} np_output_command_kind_t;

typedef struct {
    uint16_t port;
    const char *proto;
    const char *service;
    const char *state;
    const char *product;
    const char *version;
    bool tls_detected;
} np_output_doc_service_t;

typedef struct {
    const char *ip;
    const char *hostname;
    bool discovered;
    bool up;
    const char *reason;
    double rtt_ms;
    np_output_doc_service_t *services;
    uint32_t service_count;
} np_output_doc_host_t;

typedef struct {
    uint64_t run_id;
    uint64_t timestamp;
    np_output_command_kind_t command;
    np_output_doc_host_t *hosts;
    uint32_t host_count;
} np_output_doc_t;

void np_output_doc_init(np_output_doc_t *doc);
void np_output_doc_free(np_output_doc_t *doc);
np_status_t np_output_doc_from_recon(np_recon_context_t *ctx, np_output_doc_t *doc);

#endif
