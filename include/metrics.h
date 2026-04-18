#ifndef NP_METRICS_H
#define NP_METRICS_H

#include <stdint.h>
#include "netpeek.h"

typedef struct
{
    uint64_t open_ports;
    uint64_t closed_ports;
    uint64_t filtered_ports;
    uint64_t unknown_ports;
    uint64_t open_filtered_ports;
    uint64_t total_scans;

    double   total_rtt_ms;
    uint64_t rtt_samples;
} np_metrics_t;

/* initialize metrics structure */
void np_metrics_init(np_metrics_t *m);

/* record one completed scan */
void np_metrics_update(np_metrics_t *m,
                       np_port_state_t state,
                       double rtt_ms);

/* print summary */
void np_metrics_print(const np_metrics_t *m,
                      double elapsed_sec);

#endif /* NP_METRICS_H */
