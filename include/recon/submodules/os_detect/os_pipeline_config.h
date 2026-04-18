#ifndef NP_OS_PIPELINE_CONFIG_H
#define NP_OS_PIPELINE_CONFIG_H

/* ================================================================ */
/*  Configuration constants                                         */
/* ================================================================ */

#define NP_PIPELINE_PROBE_TIMEOUT_MS 3000
#define NP_PIPELINE_BANNER_TIMEOUT_MS 4000
#define NP_PIPELINE_CONNECT_TIMEOUT_MS 2000
#define NP_PIPELINE_MAX_OPEN_PORTS 32
#define NP_PIPELINE_MAX_BANNER_PORTS 8
#define NP_PIPELINE_CLOSED_PORT_DEFAULT 61234

/* Weight factors for confidence fusion */
#define NP_WEIGHT_FINGERPRINT 0.45
#define NP_WEIGHT_BEHAVIOR 0.25
#define NP_WEIGHT_BANNER 0.30

/* Minimum confidence thresholds */
#define NP_MIN_FP_CONFIDENCE 10
#define NP_MIN_BANNER_CONFIDENCE 5
#define NP_MIN_FUSED_CONFIDENCE 15

#endif /* NP_PIPELINE_CONFIG_H */
