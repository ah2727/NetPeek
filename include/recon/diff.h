#ifndef NP_RECON_DIFF_H
#define NP_RECON_DIFF_H

#include <stdbool.h>

int np_recon_diff_run(const char *old_path,
                      const char *new_path,
                      const char *format,
                      const char *out_path,
                      bool use_color);

#endif
