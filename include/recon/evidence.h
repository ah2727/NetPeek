#ifndef NP_RECON_EVIDENCE_H
#define NP_RECON_EVIDENCE_H

#include <stdint.h>
#include <time.h>

#include "recon/context.h"

typedef struct {
    uint64_t id;
    const char *source_module;
    const char *description;
    time_t timestamp;
    double confidence;
    void *raw_data;
} np_evidence_t;

uint64_t np_evidence_add(np_recon_context_t *ctx,
                         uint64_t node_id,
                         const np_evidence_t *evidence);

uint64_t np_evidence_count(const np_recon_context_t *ctx);

#endif
