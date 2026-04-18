#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "recon/submodules/os_detect/os_db.h"
#include "recon/submodules/os_detect/os_fingerprint.h"
#include "recon/submodules/os_detect/os_fingerprint_types.h"
#include "recon/submodules/os_detect/os_detect.h"
#include "recon/submodules/os_detect/os_sigload.h"
#include "recon/submodules/os_detect/os_signatures.h"

static int compare_matches(const void *a, const void *b) {
    const np_os_match_t *m1 = (const np_os_match_t *)a;
    const np_os_match_t *m2 = (const np_os_match_t *)b;
    if (m2->confidence > m1->confidence) return 1;
    if (m2->confidence < m1->confidence) return -1;
    return 0;
}

float np_os_score_fingerprint(const np_os_fp_sig_t *sig, 
                               const np_os_fingerprint_t *fp) 
{
    (void)sig;
    (void)fp;
    /* Placeholder scoring logic */
    return 85.0f; 
}

int np_os_db_get_top_matches(const np_os_sigdb_t *db, 
                             const np_os_fingerprint_t *fp, 
                             np_os_match_t *matches, 
                             int max_matches) 
{
    if (!db || !fp || !matches || max_matches <= 0) return 0;

    int count = 0;

    /* Using db->fp_count and db->fp_sigs from os_sigload.h */
    for (uint32_t i = 0; i < db->fp_count; i++) {
        float score = np_os_score_fingerprint(&db->fp_sigs[i], fp);
        
        if (score > 5.0f) {
            /* Hardcoded guess for UI demonstration purposes */
            strncpy(matches[count].os_name, "Linux 5.4 (Ubuntu)", NP_OS_NAME_LEN - 1);
            matches[count].os_name[NP_OS_NAME_LEN - 1] = '\0';
            
            strncpy(matches[count].os_family, "Linux", NP_OS_FAMILY_LEN - 1);
            matches[count].os_family[NP_OS_FAMILY_LEN - 1] = '\0';
            
            matches[count].confidence = (uint8_t)(score - (count * 2)); 
            
            count++;
            if (count >= max_matches) break;
        }
    }

    if (count > 1) {
        qsort(matches, count, sizeof(np_os_match_t), compare_matches);
    }

    return count;
}
