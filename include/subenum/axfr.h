#ifndef NP_SUBENUM_AXFR_H
#define NP_SUBENUM_AXFR_H

#include "subenum/result_store.h"
#include "subenum/subenum_types.h"

int np_axfr_attempt(const char *domain,
                    const np_subenum_config_t *cfg,
                    np_result_store_t *store,
                    uint16_t depth);

#endif
