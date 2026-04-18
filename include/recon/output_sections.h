#ifndef NP_RECON_OUTPUT_SECTIONS_H
#define NP_RECON_OUTPUT_SECTIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "recon/context.h"
#include "recon/query.h"

typedef struct {
    const char *key;
    const char *label;
    double seconds;
    double ratio;
} np_recon_perf_stage_t;

typedef struct {
    np_recon_perf_stage_t stages[5];
    uint32_t stage_count;
    double total_seconds;
} np_recon_perf_t;

void np_recon_estimate_performance(np_recon_context_t *ctx, np_recon_perf_t *out);
bool np_recon_should_show_version(const np_recon_context_t *ctx);
bool np_recon_should_show_os(const np_recon_context_t *ctx);
bool np_recon_service_identified(const np_service_view_t *svc);
uint32_t np_recon_count_identified_services(const np_service_view_t *services, uint32_t count);
void np_recon_format_elapsed(double seconds, char *buf, size_t len);

#endif
