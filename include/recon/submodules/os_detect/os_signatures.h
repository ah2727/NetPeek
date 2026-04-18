#ifndef NP_OS_SIGNATURES_H
#define NP_OS_SIGNATURES_H

#include <stdint.h>
#include <stdbool.h>
#include "os_fingerprint_types.h"

/*
 * -------------------------------------------------------
 * TCP/IP fingerprint signature
 * -------------------------------------------------------
 */
typedef struct {
    const char *os_name;
    const char *os_vendor;      
    const char *os_family;
    const char *os_gen;         
    const char *device_type;    
    const char *cpe;            
    
    int ttl;
    int window_size;
    int df_bit;
    int mss;
    int sack_permitted;
    int timestamp;
    int window_scale;
    
    const char *response_pattern;
    int tcp_options[20];
    int tcp_opt_count;
    int total_length;
    int weight;
} np_os_fp_sig_t;





/*
 * -------------------------------------------------------
 * Banner signature  (database entry)
 * -------------------------------------------------------
 *
 * One known pattern stored in the signature DB.
 * Compared against np_os_banner_t at match time.
 */
typedef struct
{
    const char *pattern;
    const char *os_name;
    const char *os_family;
    const char *service;

    uint8_t confidence;

} np_os_banner_sig_t;


/*
 * -------------------------------------------------------
 * Access to built-in signature tables
 * -------------------------------------------------------
 */
const np_os_fp_sig_t     *np_os_fp_signatures(uint32_t *count);
const np_os_banner_sig_t *np_os_banner_signatures(uint32_t *count);


/*
 * -------------------------------------------------------
 * Utility helpers
 * -------------------------------------------------------
 */
uint8_t np_os_fp_score(
        const np_os_fingerprint_t *fp,
        const np_os_fp_sig_t      *sig);

bool np_os_banner_pattern_match(
        const char *banner,
        const char *pattern);

#endif /* NP_OS_SIGNATURES_H */
