#ifndef NP_OS_FINGERPRINT_SCORE_H
#define NP_OS_FINGERPRINT_SCORE_H

#include <stdint.h>
#include <stdbool.h>

#include "os_fingerprint_types.h"
#include "os_signatures.h"

/* ---------------------------------------------------- */
/* Score range                                          */
/* ---------------------------------------------------- */

#define NP_SCORE_MIN 0
#define NP_SCORE_MAX 100

/* ---------------------------------------------------- */
/* Field weights (importance in OS identification)      */
/* ---------------------------------------------------- */

#define NP_W_TTL 30
#define NP_W_WINDOW 20
#define NP_W_MSS 15
#define NP_W_DF 10
#define NP_W_WSCALE 15
#define NP_W_SACK 5
#define NP_W_TIMESTAMP 5
#define NP_W_OPT_ORDER 10
#define NP_W_IP_TOTLEN 5

#define NP_SCORE_TOTAL_BASE 115

/* ---------------------------------------------------- */
/* TTL tolerance                                        */
/* ---------------------------------------------------- */

/*
* If normalized TTL doesn't match exactly, allow
* partial score if within this hop distance.
*/
#define NP_TTL_CLOSE_HOPS 10

/* ---------------------------------------------------- */
/* Window tolerance ratios                              */
/* ---------------------------------------------------- */

#define NP_WIN_TIGHT_LO 0.90
#define NP_WIN_TIGHT_HI 1.10

#define NP_WIN_LOOSE_LO 0.70
#define NP_WIN_LOOSE_HI 1.30

/* ---------------------------------------------------- */
/* MSS tolerance                                        */
/* ---------------------------------------------------- */

#define NP_MSS_TIGHT_LO 0.95
#define NP_MSS_TIGHT_HI 1.05

/* ---------------------------------------------------- */
/* Common TCP option order patterns                     */
/* ---------------------------------------------------- */

#define NP_OPTORDER_LINUX "MSTNW"
#define NP_OPTORDER_WINDOWS "MNWST"
#define NP_OPTORDER_MACOS "MWSTN"
#define NP_OPTORDER_FREEBSD "MSTNW"

/* ---------------------------------------------------- */
/* Detailed scoring breakdown (optional debug output)   */
/* ---------------------------------------------------- */

typedef struct
{
uint8_t ttl_score;
uint8_t window_score;
uint8_t mss_score;
uint8_t df_score;
uint8_t wscale_score;
uint8_t sack_score;
uint8_t timestamp_score;
uint8_t opt_order_score;
uint8_t ip_totlen_score;
uint8_t response_pat_score;

uint16_t total_earned;
uint16_t total_possible;

uint8_t normalized;
uint8_t final_score;
int weight_for_tiebreak;
} np_score_detail_t;

/* ---------------------------------------------------- */
/* Normalize raw TTL to common initial values           */
/* ---------------------------------------------------- */
/*
* Standard initial TTL values:
*
* 32
* 64
* 128
* 255
*/
uint8_t np_normalize_ttl(uint8_t raw_ttl);

/* ---------------------------------------------------- */
/* Option order similarity scoring                      */
/* ---------------------------------------------------- */

uint8_t np_option_order_score(
const uint8_t *observed,
uint8_t observed_count,
const uint8_t *expected,
uint8_t expected_count);

/* ---------------------------------------------------- */
/* Core fingerprint scoring                             */
/* ---------------------------------------------------- */

uint8_t np_fingerprint_score(
const np_os_fingerprint_t *fp,
const np_os_fp_sig_t *sig,
np_score_detail_t *detail);

/* ---------------------------------------------------- */
/* Find best signature match                            */
/* ---------------------------------------------------- */

const np_os_fp_sig_t *np_fingerprint_best_match(
const np_os_fingerprint_t *fp,
const np_os_fp_sig_t *sigs,
uint32_t sig_count,
uint8_t *out_score,
np_score_detail_t *out_detail);

/* ---------------------------------------------------- */
/* Return top N matches                                 */
/* ---------------------------------------------------- */

uint32_t np_fingerprint_top_matches(
const np_os_fingerprint_t *fp,
const np_os_fp_sig_t *sigs,
uint32_t sig_count,
uint32_t *out_indices,
uint8_t *out_scores,
uint32_t top_n);

/* ---------------------------------------------------- */
/* Debug print helper                                   */
/* ---------------------------------------------------- */

void np_score_detail_print(
const np_score_detail_t *detail,
const np_os_fp_sig_t *sig);

#endif