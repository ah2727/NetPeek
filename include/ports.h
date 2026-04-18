#ifndef NETPEEK_PORTS_H
#define NETPEEK_PORTS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ───────────────────────────────────────────── */
/* Port limits                                   */
/* ───────────────────────────────────────────── */

#define NP_PORT_MIN 1
#define NP_PORT_MAX 65535

/* ───────────────────────────────────────────── */
/* Limits                                        */
/* ───────────────────────────────────────────── */

#define NP_MAX_PORT_RANGES 8380

/* ───────────────────────────────────────────── */
/* Top ports                                     */
/* ───────────────────────────────────────────── */

extern const uint16_t np_top_ports[];
extern const uint16_t np_top_ports_top_1000[];
extern const uint32_t np_top_ports_count;

/* ───────────────────────────────────────────── */
/* Port range                                    */
/* ───────────────────────────────────────────── */

typedef struct {
    uint16_t start;
    uint16_t end;
} np_port_range_t;

/* ───────────────────────────────────────────── */
/* Port specification                            */
/* ───────────────────────────────────────────── */

typedef struct {
    np_port_range_t ranges[NP_MAX_PORT_RANGES];
    uint32_t        count;
} np_port_spec_t;

/* ───────────────────────────────────────────── */
/* ✅ Port iterator (SAFE, STATEFUL)              */
/* ───────────────────────────────────────────── */

typedef struct {
    uint32_t range_idx;
    uint16_t port;
    bool     started;
} np_port_iter_t;

/* ───────────────────────────────────────────── */
/* API                                           */
/* ───────────────────────────────────────────── */

/* Parse port specification string (e.g. "80,443,1000-2000", "-") */
bool np_parse_ports(const char *str, np_port_spec_t *out);

/* Total number of ports represented by spec */
uint64_t np_ports_total(const np_port_spec_t *spec);

/* Iterator API — MUST be used instead of old np_port_next() */
void np_port_iter_init(np_port_iter_t *it);

bool np_port_iter_next(const np_port_spec_t *spec,
                       np_port_iter_t       *it,
                       uint16_t             *out_port);

#ifdef __cplusplus
}
#endif

#endif /* NETPEEK_PORTS_H */
