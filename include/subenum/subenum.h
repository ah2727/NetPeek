#ifndef NP_SUBENUM_H
#define NP_SUBENUM_H

#include "subenum/subenum_types.h"

void np_subenum_config_init(np_subenum_config_t *cfg);
void np_subenum_config_free(np_subenum_config_t *cfg);
int np_subenum_execute(const np_subenum_config_t *cfg);

#endif
