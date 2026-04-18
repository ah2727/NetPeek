/*
 * NetPeek - TCP Probe Behavioral Signature Database
 *
 * Database of OS behavioral fingerprints derived from
 * T1–T7 probe responses.
 */

#include "os_tcp_probes.h"

#include <stdint.h>
#include <stdbool.h>

/* ---------------------------------------------------- */
/* behavioral signature structure                       */
/* ---------------------------------------------------- */

typedef struct
{
    const char *os_name;
    const char *os_family;

    bool t1_resp;
    bool t2_resp;
    bool t3_resp;
    bool t4_resp;
    bool t5_resp;
    bool t6_resp;
    bool t7_resp;

    uint8_t t1_flags;
    uint8_t t3_flags;
    uint8_t t4_flags;

    uint8_t typical_ttl;
    uint16_t typical_window;

    /* Apple / advanced discriminators */
    bool require_timestamps;
    bool require_window_scale;
    bool forbid_rst_flood;

} np_tcp_behavior_sig_t;

/* ---------------------------------------------------- */
/* signature database                                   */
/* ---------------------------------------------------- */

static const np_tcp_behavior_sig_t tcp_probe_db[] = {

    /* ---------------- Linux kernels ---------------- */

    {
        "Linux 2.6.x",
        "Linux",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,5840,
        false,false,false
    },

    {
        "Linux 3.x",
        "Linux",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,14600,
        false,false,false
    },

    {
        "Linux 4.x",
        "Linux",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,29200,
        false,false,false
    },

    {
        "Linux 5.x / 6.x",
        "Linux",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,65535,
        false,false,false
    },

    /* ---------------- Windows ---------------- */

    {
        "Windows 7 / 8",
        "Windows",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        128,8192,
        false,false,false
    },

    {
        "Windows 10",
        "Windows",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        128,65535,
        false,false,false
    },

    {
        "Windows 11",
        "Windows",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        128,65535,
        false,false,false
    },

    /* ---------------- Apple ---------------- */

    {
        "macOS",
        "Apple",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,65535,
        true,  /* timestamps */
        true,  /* window scale */
        true   /* minimal RSTs */
    },

    {
        "iOS",
        "Apple",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,32768,
        true,
        true,
        true
    },

    /* ---------------- BSD ---------------- */

    {
        "FreeBSD",
        "BSD",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,65535,
        false,false,false
    },

    {
        "OpenBSD",
        "BSD",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,16384,
        false,false,false
    },

    /* ---------------- Network devices ---------------- */

    {
        "Cisco IOS",
        "Cisco",
        true,false,false,true,true,true,false,
        0x12,0x04,0x14,
        255,4128,
        false,false,false
    },

    {
        "Cisco IOS-XE",
        "Cisco",
        true,false,false,true,true,true,false,
        0x12,0x04,0x14,
        255,16384,
        false,false,false
    },

    /* ---------------- Embedded / IoT ---------------- */

    {
        "Embedded Linux",
        "Linux",
        true,false,true,true,true,true,false,
        0x12,0x14,0x14,
        64,5840,
        false,false,false
    },

    {
        "lwIP",
        "RTOS",
        true,false,false,true,true,true,false,
        0x12,0x04,0x14,
        255,1024,
        false,false,false
    }
};

static const uint32_t tcp_probe_db_count =
    sizeof(tcp_probe_db) / sizeof(tcp_probe_db[0]);

/* ---------------------------------------------------- */
/* database access                                      */
/* ---------------------------------------------------- */

const np_tcp_behavior_sig_t *
np_tcp_probe_db_get(uint32_t *count)
{
    if (count)
        *count = tcp_probe_db_count;

    return tcp_probe_db;
}
