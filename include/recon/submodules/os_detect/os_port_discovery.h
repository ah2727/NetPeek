/*
 * NetPeek - OS Port Discovery
 * Lightweight port discovery for the OS detection pipeline.
 */

#ifndef OS_PORT_DISCOVERY_H
#define OS_PORT_DISCOVERY_H

#include <stdint.h>
#include <stdbool.h>

/* ── Limits ──────────────────────────────────────────── */

#define NP_DISCOVERY_MAX_OPEN    64
#define NP_DISCOVERY_MAX_CLOSED  16

/* ── Discovery result ────────────────────────────────── */

typedef struct {
    uint16_t open_ports[NP_DISCOVERY_MAX_OPEN];
    uint32_t open_count;

    uint16_t closed_ports[NP_DISCOVERY_MAX_CLOSED];
    uint32_t closed_count;

    uint16_t closed_port;      /* first confirmed closed port (shortcut) */
    bool     has_closed;
} np_os_discovery_result_t;

/* ── API ─────────────────────────────────────────────── */

/*
 * Attempts to find a commonly open TCP port on the target.
 *
 * Parameters:
 *   ip   - Target IPv4 address string
 *   out  - Pointer where discovered port will be stored
 *
 * Returns:
 *   0  on success (open port stored in *out)
 *  -1  if no open port found
 */
int np_find_open_port(const char *ip, uint16_t *out);

/*
 * Full port discovery scan for OS detection.
 *
 * Probes common ports on `target_ip`, populating open and closed
 * port lists needed by the TCP fingerprint probes.
 *
 * Returns:
 *   0  on success
 *  -1  on failure
 */
int np_os_discover_ports(const char *target_ip,
                         uint32_t    timeout_ms,
                         np_os_discovery_result_t *result);

#endif /* OS_PORT_DISCOVERY_H */
