#ifndef NP_RECON_PERSIST_H
#define NP_RECON_PERSIST_H

#include "recon/context.h"

np_status_t np_recon_persist_open(np_recon_context_t *ctx);
void np_recon_persist_close(np_recon_context_t *ctx);

np_status_t np_recon_persist_begin_run(np_recon_context_t *ctx);
np_status_t np_recon_persist_flush(np_recon_context_t *ctx);
np_status_t np_recon_persist_end_run(np_recon_context_t *ctx,
                                     np_status_t status,
                                     const char *note);

const char *np_recon_default_db_path(void);

#endif
