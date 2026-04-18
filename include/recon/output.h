#ifndef NP_RECON_OUTPUT_H
#define NP_RECON_OUTPUT_H

#include <stdbool.h>

#include "recon/context.h"

typedef struct {
    const char *format;
    const char *path;
    bool pretty;
    bool include_evidence;
    bool color;
    bool compact;
    bool summary_only;
    bool verbose;
    bool recon_cli_mode;
    np_recon_style_t style;
} np_output_config_t;

typedef struct {
    const char *name;
    const char *format;
    const char *extensions;
    np_status_t (*emit)(np_recon_context_t *, const np_output_config_t *);
} np_output_module_t;

np_status_t np_output_register(const np_output_module_t *module);
const np_output_module_t *np_output_find(const char *format);
const char *np_format_from_extension(const char *filename);
np_status_t np_recon_output_register_builtins(void);
np_status_t np_recon_apply_legacy_output_mapping(np_config_t *cfg);
np_status_t np_output_stage_run(np_recon_context_t *ctx);

#endif
