#ifndef NP_OS_DB_H
#define NP_OS_DB_H

#include <stdint.h>
#include "recon/submodules/os_detect/os_detect.h"     
#include "os_sigload.h"    
#include "os_fingerprint.h"
#include "os_fingerprint_types.h"
#include "os_signatures.h" /* Owns np_os_fp_sig_t */

/* Function Prototypes */
int np_os_db_get_top_matches(const np_os_sigdb_t *db, 
                             const np_os_fingerprint_t *fp, 
                             np_os_match_t *matches, 
                             int max_matches);

float np_os_score_fingerprint(const np_os_fp_sig_t *sig, 
                               const np_os_fingerprint_t *fp);

#endif
