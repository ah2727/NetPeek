#define _POSIX_C_SOURCE 200809L

#include "args.h"
#include "core/error.h"
#include "help.h"
#include "ports.h"
#include "proxy.h"
#include "evasion/decoy.h"
#include "evasion/spoof.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

/* ───────────────────────────────────────────── */
/* Port Parsing                                  */
/* ───────────────────────────────────────────── */

static np_status_t parse_ports(const char *str, np_config_t *cfg)
{
    if (!str || !cfg)
        return NP_ERR_ARGS;

    if (!np_parse_ports(str, &cfg->ports))
        return NP_ERR_ARGS;

    return NP_OK;
}

static void copy_capped(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    if (!src)
    {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static void set_scan_type(np_config_t *cfg, np_scan_type_t scan_type)
{
    if (!cfg) return;
    cfg->scan_type = scan_type;
    cfg->scan_type_forced = true;
}

static np_status_t parse_scanflags_mask(const char *value, uint8_t *out_mask)
{
    if (!value || !out_mask) return NP_ERR_ARGS;

    if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0)
    {
        char *endptr = NULL;
        long parsed = strtol(value, &endptr, 16);
        if (!endptr || *endptr != '\0' || parsed < 0 || parsed > 255)
            return NP_ERR_ARGS;
        *out_mask = (uint8_t)parsed;
        return NP_OK;
    }

    bool all_digits = true;
    for (const char *p = value; *p; p++) {
        if (!isdigit((unsigned char)*p)) {
            all_digits = false;
            break;
        }
    }
    if (all_digits && value[0] != '\0')
    {
        long parsed = strtol(value, NULL, 10);
        if (parsed < 0 || parsed > 255)
            return NP_ERR_ARGS;
        *out_mask = (uint8_t)parsed;
        return NP_OK;
    }

    char tmp[128];
    strncpy(tmp, value, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    uint8_t mask = 0;
    for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ","))
    {
        while (*tok == ' ' || *tok == '\t') tok++;
        for (char *p = tok; *p; p++) *p = (char)tolower((unsigned char)*p);

        if (strcmp(tok, "fin") == 0) mask |= 0x01;
        else if (strcmp(tok, "syn") == 0) mask |= 0x02;
        else if (strcmp(tok, "rst") == 0) mask |= 0x04;
        else if (strcmp(tok, "psh") == 0) mask |= 0x08;
        else if (strcmp(tok, "ack") == 0) mask |= 0x10;
        else if (strcmp(tok, "urg") == 0) mask |= 0x20;
        else if (strcmp(tok, "ece") == 0) mask |= 0x40;
        else if (strcmp(tok, "cwr") == 0) mask |= 0x80;
        else return NP_ERR_ARGS;
    }

    *out_mask = mask;
    return NP_OK;
}

static np_status_t parse_version_intensity(const char *value, uint8_t *out_level)
{
    if (!value || !out_level || value[0] == '\0')
        return NP_ERR_ARGS;

    char *endptr = NULL;
    long parsed = strtol(value, &endptr, 10);
    if (!endptr || *endptr != '\0' || parsed < 0 || parsed > 9)
        return NP_ERR_ARGS;

    *out_level = (uint8_t)parsed;
    return NP_OK;
}

static np_status_t parse_u32_arg(const char *value,
                                 uint32_t min_val,
                                 uint32_t max_val,
                                 uint32_t *out)
{
    if (!value || !out || value[0] == '\0')
        return NP_ERR_ARGS;

    char *endptr = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0')
        return NP_ERR_ARGS;
    if (parsed < min_val || parsed > max_val)
        return NP_ERR_ARGS;

    *out = (uint32_t)parsed;
    return NP_OK;
}

static np_status_t parse_time_arg_ms(const char *value,
                                     uint32_t min_ms,
                                     uint32_t max_ms,
                                     uint32_t *out_ms)
{
    if (!value || !out_ms || value[0] == '\0')
        return NP_ERR_ARGS;

    size_t len = strlen(value);
    uint64_t scale = 1000;
    size_t num_len = len;

    if (len >= 2 && strcmp(value + len - 2, "ms") == 0)
    {
        scale = 1;
        num_len = len - 2;
    }
    else if (len >= 1 && value[len - 1] == 's')
    {
        scale = 1000;
        num_len = len - 1;
    }
    else if (len >= 1 && value[len - 1] == 'm')
    {
        scale = 60000;
        num_len = len - 1;
    }
    else if (len >= 1 && value[len - 1] == 'h')
    {
        scale = 3600000;
        num_len = len - 1;
    }

    if (num_len == 0 || num_len >= 64)
        return NP_ERR_ARGS;

    char num[64];
    memcpy(num, value, num_len);
    num[num_len] = '\0';

    char *endptr = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(num, &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0')
        return NP_ERR_ARGS;

    if (parsed > (UINT64_MAX / scale))
        return NP_ERR_ARGS;

    uint64_t ms = parsed * scale;
    if (ms < min_ms || ms > max_ms)
        return NP_ERR_ARGS;

    *out_ms = (uint32_t)ms;
    return NP_OK;
}

static np_status_t parse_time_arg_us(const char *value,
                                     uint32_t min_us,
                                     uint32_t max_us,
                                     uint32_t *out_us)
{
    uint32_t parsed_ms = 0;
    if (parse_time_arg_ms(value, 0, (max_us / 1000u), &parsed_ms) != NP_OK)
        return NP_ERR_ARGS;

    uint64_t us = (uint64_t)parsed_ms * 1000u;
    if (us < min_us || us > max_us)
        return NP_ERR_ARGS;

    *out_us = (uint32_t)us;
    return NP_OK;
}

static np_status_t parse_verbosity_arg(const char *value, np_log_verbosity_t *out)
{
    if (!value || !out)
        return NP_ERR_ARGS;

    if (!np_error_parse_verbosity(value, out))
        return NP_ERR_ARGS;

    return NP_OK;
}

static np_status_t parse_udp_fast_path_mode(const char *value,
                                            np_udp_fast_path_mode_t *out)
{
    if (!value || !out)
        return NP_ERR_ARGS;

    if (strcasecmp(value, "auto") == 0)
    {
        *out = NP_UDP_FAST_PATH_AUTO;
        return NP_OK;
    }
    if (strcasecmp(value, "on") == 0)
    {
        *out = NP_UDP_FAST_PATH_ON;
        return NP_OK;
    }
    if (strcasecmp(value, "off") == 0)
    {
        *out = NP_UDP_FAST_PATH_OFF;
        return NP_OK;
    }

    return NP_ERR_ARGS;
}

static void apply_timing_template_defaults(np_config_t *cfg)
{
    if (!cfg || cfg->timing_template == NP_TIMING_TEMPLATE_UNSET)
        return;

    typedef struct
    {
        uint32_t max_retries;
        uint32_t initial_rtt_ms;
        uint32_t min_rtt_ms;
        uint32_t max_rtt_ms;
        uint32_t min_rate;
        uint32_t max_rate;
        uint32_t scan_delay_us;
        uint32_t min_hostgroup;
        uint32_t max_hostgroup;
        uint32_t min_parallelism;
        uint32_t max_parallelism;
        uint32_t udp_min_probe_interval_us;
        uint32_t udp_batch_size;
        uint32_t udp_inflight_per_thread;
    } np_template_t;

    static const np_template_t tpl[6] = {
        { 8, 5000, 1000, 20000, 1, 1, 300000000u, 1, 1, 1, 1, 300000000u, 8, 128 },
        { 6, 3000, 500, 12000, 10, 100, 100000, 1, 0, 1, 0, 100000u, 16, 192 },
        { 4, 2000, 300, 10000, 20, 400, 20000, 1, 0, 1, 0, 50000u, 32, 256 },
        { 2, 1000, 100, 8000, 50, 1000, 0, 1, 0, 1, 0, 50000u, 64, 384 },
        { 1, 500, 100, 5000, 100, 2000, 0, 1, 0, 1, 0, 25000u, 256, 1024 },
        { 0, 250, 50, 2000, 200, 5000, 0, 1, 0, 1, 0, 12000u, 256, 2048 }
    };

    np_template_t t = tpl[cfg->timing_template];

    if (!cfg->max_retries_explicit)
        cfg->max_retries = t.max_retries;
    if (!cfg->initial_rtt_timeout_explicit)
        cfg->initial_rtt_timeout_ms = t.initial_rtt_ms;
    if (!cfg->min_rtt_timeout_explicit)
        cfg->min_rtt_timeout_ms = t.min_rtt_ms;
    if (!cfg->max_rtt_timeout_explicit)
        cfg->max_rtt_timeout_ms = t.max_rtt_ms;
    if (!cfg->min_rate_explicit)
        cfg->min_rate = t.min_rate;
    if (!cfg->max_rate_explicit)
        cfg->max_rate = t.max_rate;
    if (!cfg->scan_delay_explicit)
        cfg->scan_delay_us = t.scan_delay_us;
    if (!cfg->min_hostgroup_explicit)
        cfg->min_hostgroup = t.min_hostgroup;
    if (!cfg->max_hostgroup_explicit)
        cfg->max_hostgroup = t.max_hostgroup;
    if (!cfg->min_parallelism_explicit)
        cfg->min_parallelism = t.min_parallelism;
    if (!cfg->max_parallelism_explicit)
        cfg->max_parallelism = t.max_parallelism;
    if (!cfg->udp_min_probe_interval_explicit)
        cfg->udp_min_probe_interval_us = t.udp_min_probe_interval_us;
    if (!cfg->udp_batch_size_explicit)
        cfg->udp_batch_size = t.udp_batch_size;
    if (!cfg->udp_inflight_explicit)
        cfg->udp_inflight_per_thread = t.udp_inflight_per_thread;
}

static void apply_fast_mode(np_config_t *cfg)
{
    if (!cfg || !cfg->fast_mode)
        return;

    cfg->timing_template = NP_TIMING_TEMPLATE_4;
    cfg->timing_template_explicit = true;
    cfg->drop_filtered_states = true;

    if (!cfg->threads_explicit)
    {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        cfg->threads = (ncpu > 0) ? (uint32_t)ncpu : NP_DEFAULT_THREADS;
    }

    cfg->udp_linux_advanced = true;

    if (!cfg->udp_min_probe_interval_explicit)
        cfg->udp_min_probe_interval_us = 25000u;
    if (!cfg->max_rtt_timeout_explicit)
        cfg->max_rtt_timeout_ms = 5000u;
    if (!cfg->udp_batch_size_explicit)
        cfg->udp_batch_size = 256u;

    if (!cfg->udp_inflight_explicit)
    {
        uint32_t boosted = cfg->udp_inflight_per_thread > (8192u / 2u)
                               ? 8192u
                               : cfg->udp_inflight_per_thread * 2u;
        if (boosted < 256u)
            boosted = 256u;
        cfg->udp_inflight_per_thread = boosted;
    }
}

static np_status_t validate_timing_perf(np_config_t *cfg)
{
    if (!cfg)
        return NP_ERR_ARGS;

    if (cfg->min_rate > 0 && cfg->max_rate > 0 && cfg->min_rate > cfg->max_rate)
        return NP_ERR_ARGS;

    if (cfg->min_hostgroup > 0 && cfg->max_hostgroup > 0 &&
        cfg->min_hostgroup > cfg->max_hostgroup)
        return NP_ERR_ARGS;

    if (cfg->min_parallelism > 0 && cfg->max_parallelism > 0 &&
        cfg->min_parallelism > cfg->max_parallelism)
        return NP_ERR_ARGS;

    if (cfg->min_rtt_timeout_ms > 0 && cfg->max_rtt_timeout_ms > 0 &&
        cfg->min_rtt_timeout_ms > cfg->max_rtt_timeout_ms)
        return NP_ERR_ARGS;

    if (cfg->initial_rtt_timeout_ms < cfg->min_rtt_timeout_ms)
        cfg->initial_rtt_timeout_ms = cfg->min_rtt_timeout_ms;
    if (cfg->max_rtt_timeout_ms > 0 && cfg->initial_rtt_timeout_ms > cfg->max_rtt_timeout_ms)
        cfg->initial_rtt_timeout_ms = cfg->max_rtt_timeout_ms;

    if (cfg->max_scan_delay_us > 0 && cfg->scan_delay_us > cfg->max_scan_delay_us)
        return NP_ERR_ARGS;

    return NP_OK;
}

static np_status_t parse_discovery_protocols(const char *value,
                                             uint8_t *out,
                                             uint8_t *out_count)
{
    if (!out || !out_count)
        return NP_ERR_ARGS;

    *out_count = 0;

    if (!value || value[0] == '\0')
        return NP_OK;

    char tmp[256];
    strncpy(tmp, value, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ","))
    {
        while (*tok == ' ' || *tok == '\t') tok++;
        if (*tok == '\0')
            continue;

        char *endptr = NULL;
        long parsed = strtol(tok, &endptr, 10);
        if (!endptr || *endptr != '\0' || parsed < 0 || parsed > 255)
            return NP_ERR_ARGS;

        if (*out_count >= 32)
            return NP_ERR_ARGS;

        out[(*out_count)++] = (uint8_t)parsed;
    }

    return NP_OK;
}

static np_status_t parse_short_scan_mode(np_config_t *cfg,
                                         const char *scan_arg,
                                         int argc,
                                         char *argv[])
{
    if (!cfg || !scan_arg || scan_arg[0] == '\0')
        return NP_ERR_ARGS;

    char mode = scan_arg[0];
    switch (mode)
    {
    case 'S': set_scan_type(cfg, NP_SCAN_TCP_SYN); return NP_OK;
    case 'T': set_scan_type(cfg, NP_SCAN_TCP_CONNECT); return NP_OK;
    case 'A': set_scan_type(cfg, NP_SCAN_TCP_ACK); return NP_OK;
    case 'W': set_scan_type(cfg, NP_SCAN_TCP_WINDOW); return NP_OK;
    case 'M': set_scan_type(cfg, NP_SCAN_TCP_MAIMON); return NP_OK;
    case 'U': set_scan_type(cfg, NP_SCAN_UDP); return NP_OK;
    case 'N': set_scan_type(cfg, NP_SCAN_TCP_NULL); return NP_OK;
    case 'F': set_scan_type(cfg, NP_SCAN_TCP_FIN); return NP_OK;
    case 'X': set_scan_type(cfg, NP_SCAN_TCP_XMAS); return NP_OK;
    case 'Y': set_scan_type(cfg, NP_SCAN_SCTP_INIT); return NP_OK;
    case 'Z': set_scan_type(cfg, NP_SCAN_SCTP_COOKIE_ECHO); return NP_OK;
    case 'O': set_scan_type(cfg, NP_SCAN_IP_PROTOCOL); return NP_OK;
    case 'L':
        cfg->host_discovery_mode = NP_HOST_DISCOVERY_LIST_ONLY;
        return NP_OK;
    case 'n':
        cfg->host_discovery_mode = NP_HOST_DISCOVERY_PING_ONLY;
        return NP_OK;
    case 'V':
        cfg->service_version_detect = true;
        return NP_OK;
    case 'I': {
        set_scan_type(cfg, NP_SCAN_IDLE);
        if (optind >= argc || !argv[optind] || argv[optind][0] == '-')
            return NP_ERR_ARGS;

        char zombie[NP_MAX_HOSTNAME_LEN + 32];
        strncpy(zombie, argv[optind], sizeof(zombie) - 1);
        zombie[sizeof(zombie) - 1] = '\0';
        optind++;

        char *colon = strchr(zombie, ':');
        if (colon)
        {
            *colon = '\0';
            long p = strtol(colon + 1, NULL, 10);
            if (p <= 0 || p > 65535)
                return NP_ERR_ARGS;
            cfg->zombie_probe_port = (uint16_t)p;
        }

        strncpy(cfg->zombie_host, zombie, sizeof(cfg->zombie_host) - 1);
        cfg->zombie_host[sizeof(cfg->zombie_host) - 1] = '\0';
        return NP_OK;
    }
    default:
        return NP_ERR_ARGS;
    }
}

/* ───────────────────────────────────────────── */
/* Host Normalization                            */
/* ───────────────────────────────────────────── */

static void normalize_host(const char *input, char *out, size_t outlen)
{
    if (!input || !out || outlen == 0)
        return;

    out[0] = '\0';

    const char *start = input;
    const char *scheme = strstr(input, "://");
    if (scheme)
        start = scheme + 3;

    if (*start == '[')
    {
        const char *end = strchr(start + 1, ']');
        if (!end)
        {
            copy_capped(out, outlen, start);
            return;
        }

        size_t host_len = (size_t)(end - (start + 1));
        if (host_len >= outlen)
            host_len = outlen - 1;
        memcpy(out, start + 1, host_len);
        out[host_len] = '\0';

        const char *suffix = end + 1;
        if (*suffix == '/')
        {
            size_t cur = strlen(out);
            size_t rem = outlen - cur;
            if (rem > 1)
                copy_capped(out + cur, rem, suffix);
        }
        return;
    }

    const char *path = strchr(start, '/');
    size_t end_len = path ? (size_t)(path - start) : strlen(start);

    char tmp[NP_MAX_HOSTNAME_LEN + 1];
    if (end_len >= sizeof(tmp))
        end_len = sizeof(tmp) - 1;
    memcpy(tmp, start, end_len);
    tmp[end_len] = '\0';

    char *colon = strrchr(tmp, ':');
    if (colon)
    {
        bool digits_only = true;
        for (char *p = colon + 1; *p; p++)
        {
            if (!isdigit((unsigned char)*p))
            {
                digits_only = false;
                break;
            }
        }
        if (digits_only)
        {
            char *first_colon = strchr(tmp, ':');
            if (first_colon == colon)
                *colon = '\0';
        }
    }

    copy_capped(out, outlen, tmp);
}

typedef struct
{
    np_config_t *cfg;
} np_cfg_emit_ctx_t;

typedef struct
{
    char   **items;
    uint32_t count;
    uint32_t cap;
} np_string_list_t;

typedef struct
{
    np_string_list_t *list;
} np_list_emit_ctx_t;

typedef np_status_t (*np_target_emit_fn)(const char *target, void *ctx);

static np_status_t add_target(np_config_t *cfg, const char *host);

static void trim_ws_inplace(char *s)
{
    if (!s || !*s)
        return;

    size_t len = strlen(s);
    size_t start = 0;
    while (start < len && isspace((unsigned char)s[start]))
        start++;

    size_t end = len;
    while (end > start && isspace((unsigned char)s[end - 1]))
        end--;

    if (start > 0)
        memmove(s, s + start, end - start);

    s[end - start] = '\0';
}

static bool parse_uint8_str(const char *s, int *out)
{
    if (!s || !*s || !out)
        return false;

    for (const char *p = s; *p; p++)
    {
        if (!isdigit((unsigned char)*p))
            return false;
    }

    long v = strtol(s, NULL, 10);
    if (v < 0 || v > 255)
        return false;

    *out = (int)v;
    return true;
}

static bool parse_octet_token(const char *token, int *start, int *end)
{
    if (!token || !*token || !start || !end)
        return false;

    const char *dash = strchr(token, '-');
    if (!dash)
    {
        int one = 0;
        if (!parse_uint8_str(token, &one))
            return false;
        *start = one;
        *end = one;
        return true;
    }

    if (strchr(dash + 1, '-'))
        return false;

    char left[8];
    char right[8];

    size_t lsz = (size_t)(dash - token);
    size_t rsz = strlen(dash + 1);
    if (lsz == 0 || rsz == 0 || lsz >= sizeof(left) || rsz >= sizeof(right))
        return false;

    memcpy(left, token, lsz);
    left[lsz] = '\0';
    memcpy(right, dash + 1, rsz);
    right[rsz] = '\0';

    int lo = 0;
    int hi = 0;
    if (!parse_uint8_str(left, &lo) || !parse_uint8_str(right, &hi))
        return false;
    if (hi < lo)
        return false;

    *start = lo;
    *end = hi;
    return true;
}

static bool parse_ipv4_range_spec(const char *spec,
                                  int starts[4],
                                  int ends[4])
{
    if (!spec || !*spec)
        return false;

    char copy[128];
    strncpy(copy, spec, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    char *save = NULL;
    char *tok = strtok_r(copy, ".", &save);
    int idx = 0;

    while (tok)
    {
        if (idx >= 4)
            return false;

        for (const char *p = tok; *p; p++)
        {
            if (!isdigit((unsigned char)*p) && *p != '-')
                return false;
        }

        if (!parse_octet_token(tok, &starts[idx], &ends[idx]))
            return false;

        idx++;
        tok = strtok_r(NULL, ".", &save);
    }

    return idx == 4;
}

static bool resolve_hostname_to_ipv4(const char *host, struct in_addr *out)
{
    if (!host || !*host || !out)
        return false;

    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res)
        return false;

    for (struct addrinfo *p = res; p; p = p->ai_next)
    {
        if (p->ai_family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
            *out = sin->sin_addr;
            freeaddrinfo(res);
            return true;
        }
    }

    freeaddrinfo(res);
    return false;
}

static np_status_t emit_target_to_config(const char *target, void *ctx)
{
    if (!target || !ctx)
        return NP_ERR_ARGS;

    np_cfg_emit_ctx_t *ectx = (np_cfg_emit_ctx_t *)ctx;
    if (!ectx->cfg)
        return NP_ERR_ARGS;

    char clean[NP_MAX_HOSTNAME_LEN + 1];
    normalize_host(target, clean, sizeof(clean));
    if (clean[0] == '\0')
        return NP_ERR_ARGS;

    for (uint32_t i = 0; i < ectx->cfg->target_count; i++)
    {
        if (strcasecmp(ectx->cfg->targets[i].hostname, clean) == 0)
            return NP_OK;
    }

    if (ectx->cfg->target_count >= NP_MAX_TARGETS)
        return NP_ERR_ARGS;

    return add_target(ectx->cfg, clean);
}

static bool string_list_contains(const np_string_list_t *list, const char *v)
{
    if (!list || !v)
        return false;

    for (uint32_t i = 0; i < list->count; i++)
    {
        if (strcasecmp(list->items[i], v) == 0)
            return true;
    }
    return false;
}

static np_status_t string_list_add(np_string_list_t *list, const char *value)
{
    if (!list || !value || !*value)
        return NP_ERR_ARGS;

    if (string_list_contains(list, value))
        return NP_OK;

    if (list->count >= NP_MAX_TARGETS)
        return NP_ERR_ARGS;

    if (list->count == list->cap)
    {
        uint32_t next_cap = list->cap ? (list->cap * 2) : 32;
        if (next_cap > NP_MAX_TARGETS)
            next_cap = NP_MAX_TARGETS;

        char **next_items = realloc(list->items, sizeof(char *) * next_cap);
        if (!next_items)
            return NP_ERR_MEMORY;

        list->items = next_items;
        list->cap = next_cap;
    }

    char *dup = strdup(value);
    if (!dup)
        return NP_ERR_MEMORY;

    list->items[list->count++] = dup;
    return NP_OK;
}

static void string_list_free(np_string_list_t *list)
{
    if (!list)
        return;

    for (uint32_t i = 0; i < list->count; i++)
        free(list->items[i]);

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static np_status_t emit_target_to_list(const char *target, void *ctx)
{
    if (!target || !ctx)
        return NP_ERR_ARGS;

    np_list_emit_ctx_t *ectx = (np_list_emit_ctx_t *)ctx;
    if (!ectx->list)
        return NP_ERR_ARGS;

    char clean[NP_MAX_HOSTNAME_LEN + 1];
    normalize_host(target, clean, sizeof(clean));
    if (clean[0] == '\0')
        return NP_ERR_ARGS;

    return string_list_add(ectx->list, clean);
}

static np_status_t expand_ipv4_cidr(const char *ip_or_host,
                                    int prefix,
                                    np_target_emit_fn emit,
                                    void *ctx)
{
    if (!ip_or_host || !emit || prefix < 0 || prefix > 32)
        return NP_ERR_ARGS;

    struct in_addr base;
    if (inet_pton(AF_INET, ip_or_host, &base) != 1)
    {
        if (!resolve_hostname_to_ipv4(ip_or_host, &base))
            return NP_ERR_ARGS;
    }

    uint64_t hosts = 1ULL << (32 - prefix);
    if (hosts > NP_MAX_TARGETS)
        return NP_ERR_ARGS;

    uint32_t ip = ntohl(base.s_addr);
    uint32_t mask = (prefix == 0) ? 0U : (~0U << (32 - prefix));
    uint32_t start = ip & mask;

    for (uint64_t i = 0; i < hosts; i++)
    {
        struct in_addr a;
        a.s_addr = htonl(start + (uint32_t)i);
        char buf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &a, buf, sizeof(buf)))
            return NP_ERR_SYSTEM;

        np_status_t rc = emit(buf, ctx);
        if (rc != NP_OK)
            return rc;
    }

    return NP_OK;
}

static void mask_ipv6_prefix(uint8_t bytes[16], int prefix)
{
    int full = prefix / 8;
    int rem = prefix % 8;

    for (int i = full + (rem ? 1 : 0); i < 16; i++)
        bytes[i] = 0;

    if (rem && full < 16)
    {
        uint8_t mask = (uint8_t)(0xffu << (8 - rem));
        bytes[full] &= mask;
    }
}

static void add_u32_to_ipv6(uint8_t bytes[16], uint32_t add)
{
    int idx = 15;
    uint32_t carry = add;
    while (idx >= 0 && carry > 0)
    {
        uint32_t v = (uint32_t)bytes[idx] + (carry & 0xffu);
        bytes[idx] = (uint8_t)(v & 0xffu);
        carry = (carry >> 8) + (v >> 8);
        idx--;
    }
}

static np_status_t expand_ipv6_cidr(const char *ip_or_host,
                                    int prefix,
                                    np_target_emit_fn emit,
                                    void *ctx)
{
    if (!ip_or_host || !emit || prefix < 0 || prefix > 128)
        return NP_ERR_ARGS;

    struct in6_addr base;
    if (inet_pton(AF_INET6, ip_or_host, &base) != 1)
        return NP_ERR_ARGS;

    int host_bits = 128 - prefix;
    if (host_bits < 0)
        return NP_ERR_ARGS;
    if (host_bits > 12)
        return NP_ERR_ARGS;

    uint32_t hosts = 1u << host_bits;
    if (hosts > NP_MAX_TARGETS)
        return NP_ERR_ARGS;

    uint8_t network[16];
    memcpy(network, base.s6_addr, 16);
    mask_ipv6_prefix(network, prefix);

    for (uint32_t i = 0; i < hosts; i++)
    {
        uint8_t cur[16];
        memcpy(cur, network, 16);
        add_u32_to_ipv6(cur, i);

        char buf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, cur, buf, sizeof(buf)))
            return NP_ERR_SYSTEM;

        np_status_t rc = emit(buf, ctx);
        if (rc != NP_OK)
            return rc;
    }

    return NP_OK;
}

static np_status_t expand_ipv4_range(const char *spec,
                                     np_target_emit_fn emit,
                                     void *ctx)
{
    int start[4] = {0};
    int end[4] = {0};

    if (!parse_ipv4_range_spec(spec, start, end))
        return NP_ERR_ARGS;

    uint64_t total = 1;
    for (int i = 0; i < 4; i++)
    {
        total *= (uint64_t)(end[i] - start[i] + 1);
    }

    if (total > NP_MAX_TARGETS)
        return NP_ERR_ARGS;

    char ipbuf[32];
    for (int a = start[0]; a <= end[0]; a++)
    {
        for (int b = start[1]; b <= end[1]; b++)
        {
            for (int c = start[2]; c <= end[2]; c++)
            {
                for (int d = start[3]; d <= end[3]; d++)
                {
                    snprintf(ipbuf, sizeof(ipbuf), "%d.%d.%d.%d", a, b, c, d);
                    np_status_t rc = emit(ipbuf, ctx);
                    if (rc != NP_OK)
                        return rc;
                }
            }
        }
    }

    return NP_OK;
}

static np_status_t expand_target_spec(const char *spec,
                                      np_target_emit_fn emit,
                                      void *ctx)
{
    if (!spec || !*spec || !emit)
        return NP_ERR_ARGS;

    char copy[256];
    strncpy(copy, spec, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    trim_ws_inplace(copy);
    if (copy[0] == '\0')
        return NP_OK;

    int range_start[4] = {0};
    int range_end[4] = {0};
    if (parse_ipv4_range_spec(copy, range_start, range_end))
        return expand_ipv4_range(copy, emit, ctx);

    char *slash = strchr(copy, '/');
    if (slash)
    {
        *slash = '\0';
        const char *rhs = slash + 1;
        if (*rhs == '\0')
            return NP_ERR_ARGS;

        for (const char *p = rhs; *p; p++)
        {
            if (!isdigit((unsigned char)*p))
                return NP_ERR_ARGS;
        }

        long prefix = strtol(rhs, NULL, 10);
        if (strchr(copy, ':'))
        {
            if (prefix < 0 || prefix > 128)
                return NP_ERR_ARGS;
            return expand_ipv6_cidr(copy, (int)prefix, emit, ctx);
        }

        if (prefix < 0 || prefix > 32)
            return NP_ERR_ARGS;

        return expand_ipv4_cidr(copy, (int)prefix, emit, ctx);
    }

    return emit(copy, ctx);
}

static np_status_t add_target_spec(np_config_t *cfg, const char *spec)
{
    if (!cfg || !spec)
        return NP_ERR_ARGS;

    np_cfg_emit_ctx_t ctx = { .cfg = cfg };
    return expand_target_spec(spec, emit_target_to_config, &ctx);
}

static np_status_t add_targets_from_file(np_config_t *cfg, const char *filename)
{
    if (!cfg || !filename || !*filename)
        return NP_ERR_ARGS;

    FILE *fp = fopen(filename, "r");
    if (!fp)
        return NP_STATUS_ERR_IO;

    char line[512];
    np_status_t rc = NP_OK;

    while (fgets(line, sizeof(line), fp))
    {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';

        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';

        trim_ws_inplace(line);
        if (line[0] == '\0')
            continue;

        rc = add_target_spec(cfg, line);
        if (rc != NP_OK)
            break;
    }

    fclose(fp);
    return rc;
}

static np_status_t add_excludes_from_string(np_string_list_t *list,
                                            const char *value)
{
    if (!list || !value)
        return NP_ERR_ARGS;

    char copy[1024];
    strncpy(copy, value, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    np_list_emit_ctx_t ctx = { .list = list };

    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ","))
    {
        trim_ws_inplace(tok);
        if (tok[0] == '\0')
            continue;

        np_status_t rc = expand_target_spec(tok, emit_target_to_list, &ctx);
        if (rc != NP_OK)
            return rc;
    }

    return NP_OK;
}

static np_status_t add_excludes_from_file(np_string_list_t *list,
                                          const char *filename)
{
    if (!list || !filename || !*filename)
        return NP_ERR_ARGS;

    FILE *fp = fopen(filename, "r");
    if (!fp)
        return NP_STATUS_ERR_IO;

    char line[512];
    np_status_t rc = NP_OK;
    np_list_emit_ctx_t ctx = { .list = list };

    while (fgets(line, sizeof(line), fp))
    {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';

        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';

        trim_ws_inplace(line);
        if (line[0] == '\0')
            continue;

        rc = expand_target_spec(line, emit_target_to_list, &ctx);
        if (rc != NP_OK)
            break;
    }

    fclose(fp);
    return rc;
}

static bool is_random_ipv4_allowed(uint32_t ip)
{
    uint8_t a = (uint8_t)((ip >> 24) & 0xff);
    uint8_t b = (uint8_t)((ip >> 16) & 0xff);
    uint8_t c = (uint8_t)((ip >> 8) & 0xff);

    if (a == 0 || a == 10 || a == 127)
        return false;
    if (a == 100 && (b >= 64 && b <= 127))
        return false;
    if (a == 169 && b == 254)
        return false;
    if (a == 172 && (b >= 16 && b <= 31))
        return false;
    if (a == 192 && b == 168)
        return false;
    if (a == 192 && b == 0 && c == 2)
        return false;
    if (a == 198 && b == 18)
        return false;
    if (a == 198 && b == 19)
        return false;
    if (a == 198 && b == 51 && c == 100)
        return false;
    if (a == 203 && b == 0 && c == 113)
        return false;
    if (a >= 224)
        return false;

    return true;
}

static np_status_t add_random_targets(np_config_t *cfg, uint32_t wanted)
{
    if (!cfg)
        return NP_ERR_ARGS;
    if (wanted == 0)
        return NP_OK;

    if (wanted > NP_MAX_TARGETS)
        return NP_ERR_ARGS;

    uint32_t start_count = cfg->target_count;
    uint32_t max_attempts = wanted * 64;
    uint32_t attempts = 0;
    static bool seeded = false;

    if (!seeded)
    {
        srand((unsigned int)time(NULL));
        seeded = true;
    }

    while ((cfg->target_count - start_count) < wanted)
    {
        if (attempts++ > max_attempts)
            return NP_ERR_ARGS;

        uint32_t ip = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
        if (!is_random_ipv4_allowed(ip))
            continue;

        struct in_addr addr;
        addr.s_addr = htonl(ip);
        char buf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
            return NP_ERR_SYSTEM;

        np_status_t rc = add_target_spec(cfg, buf);
        if (rc != NP_OK)
            return rc;
    }

    return NP_OK;
}

static void apply_exclusions(np_config_t *cfg, const np_string_list_t *exclude)
{
    if (!cfg || !exclude || exclude->count == 0 || cfg->target_count == 0)
        return;

    uint32_t out = 0;
    for (uint32_t i = 0; i < cfg->target_count; i++)
    {
        if (string_list_contains(exclude, cfg->targets[i].hostname))
            continue;

        if (out != i)
            cfg->targets[out] = cfg->targets[i];
        out++;
    }

    cfg->target_count = out;
}

/* ───────────────────────────────────────────── */
/* Target Parsing                                */
/* ───────────────────────────────────────────── */

static np_status_t add_target(np_config_t *cfg, const char *host)
{
    char clean[NP_MAX_HOSTNAME_LEN];

    normalize_host(host, clean, sizeof(clean));

    np_target_t *new_targets = realloc(
        cfg->targets,
        (cfg->target_count + 1) * sizeof(np_target_t));

    if (!new_targets)
        return NP_ERR_MEMORY;

    cfg->targets = new_targets;

    memset(&cfg->targets[cfg->target_count], 0, sizeof(np_target_t));

    strncpy(cfg->targets[cfg->target_count].hostname,
            clean,
            NP_MAX_HOSTNAME_LEN - 1);

    cfg->target_count++;

    return NP_OK;
}

/*
 * ✅ CIDR EXPANSION
 * Expands IPv4 CIDR (e.g. 10.0.0.0/24) into individual targets.
 * Non-CIDR input is passed through unchanged.
 */
static np_status_t add_cidr_targets(np_config_t *cfg, const char *input)
{
    return add_target_spec(cfg, input);
}

/* ───────────────────────────────────────────── */
/* Output Format Auto-Detection from Extension   */
/* ───────────────────────────────────────────── */

static np_output_fmt_t detect_output_format(const char *filename)
{
    if (!filename)
        return NP_OUTPUT_PLAIN;

    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return NP_OUTPUT_PLAIN;

    dot++; /* skip the '.' */

    if (strcasecmp(dot, "json") == 0)
        return NP_OUTPUT_JSON;

    if (strcasecmp(dot, "csv") == 0)
        return NP_OUTPUT_CSV;

    if (strcasecmp(dot, "grep") == 0 ||
        strcasecmp(dot, "gnmap") == 0 ||
        strcasecmp(dot, "greppable") == 0)
        return NP_OUTPUT_GREPPABLE;

    if (strcasecmp(dot, "xml") == 0)
        return NP_OUTPUT_XML;

    if (strcasecmp(dot, "html") == 0 ||
        strcasecmp(dot, "htm") == 0)
        return NP_OUTPUT_HTML;

    return NP_OUTPUT_PLAIN;
}

/* ───────────────────────────────────────────── */
/* Usage                                         */
/* ───────────────────────────────────────────── */

void np_args_usage(const char *prog)
{
    np_help_print_scan_usage(prog, stdout);
}

/* ───────────────────────────────────────────── */
/* CLI Parser                                    */
/* ───────────────────────────────────────────── */

np_status_t np_args_parse(int argc, char *argv[], np_config_t *cfg)
{
    bool explicit_format = false;
    bool version_tuning_seen = false;
    bool verbosity_explicit = false;
    int verbose_count = 0;
    const char *input_list_file = NULL;
    uint32_t random_target_count = 0;
    const char *exclude_value = NULL;
    const char *exclude_file = NULL;

    static struct option long_opts[] = {
        {"target", required_argument, 0, 't'},
        {"ports", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 'T'},
        {"workers", required_argument, 0, 'W'},
        {"timeout", required_argument, 0, 1005},
        {"timing-template", required_argument, 0, 1034},
        {"min-hostgroup", required_argument, 0, 1035},
        {"max-hostgroup", required_argument, 0, 1036},
        {"min-parallelism", required_argument, 0, 1037},
        {"max-parallelism", required_argument, 0, 1038},
        {"min-rtt-timeout", required_argument, 0, 1039},
        {"max-rtt-timeout", required_argument, 0, 1040},
        {"initial-rtt-timeout", required_argument, 0, 1041},
        {"host-timeout", required_argument, 0, 1042},
        {"min-rate", required_argument, 0, 1043},
        {"max-rate", required_argument, 0, 1044},
        {"max-retries", required_argument, 0, 1045},
        {"output", required_argument, 0, 'o'},

        {"syn", no_argument, 0, 1003},
        {"udp", no_argument, 0, 1004},
        {"connect", no_argument, 0, 1008},
        {"ack", no_argument, 0, 1009},
        {"window", no_argument, 0, 1010},
        {"maimon", no_argument, 0, 1011},
        {"null", no_argument, 0, 1012},
        {"fin", no_argument, 0, 1013},
        {"xmas", no_argument, 0, 1014},
        {"scanflags", required_argument, 0, 1015},
        {"idle", required_argument, 0, 1016},
        {"sctp-init", no_argument, 0, 1017},
        {"sctp-cookie", no_argument, 0, 1018},
        {"ip-proto", no_argument, 0, 1019},
        {"version-intensity", required_argument, 0, 1020},
        {"version-light", no_argument, 0, 1021},
        {"version-all", no_argument, 0, 1022},
        {"version-trace", no_argument, 0, 1023},
        {"tls-info", no_argument, 0, 1047},
        {"traceroute", no_argument, 0, 1024},
        {"dns-servers", required_argument, 0, 1025},
        {"system-dns", no_argument, 0, 1026},
        {"skip-discovery", no_argument, 0, 1027},
        {"ping-scan", no_argument, 0, 1028},
        {"list-scan", no_argument, 0, 1029},
        {"input-list", required_argument, 0, 1030},
        {"random-targets", required_argument, 0, 1031},
        {"exclude", required_argument, 0, 1032},
        {"excludefile", required_argument, 0, 1033},

        {"json", no_argument, 0, 1000},
        {"csv", no_argument, 0, 1001},
        {"grep", no_argument, 0, 1002},
        {"xml", required_argument, 0, 1050},
        {"html", required_argument, 0, 1051},
        {"full-mode", no_argument, 0, 1052},
        {"full-rx-threads", required_argument, 0, 1053},
        {"full-queue-capacity", required_argument, 0, 1054},
        {"full-max-inflight", required_argument, 0, 1055},
        {"udp-fast-path", required_argument, 0, 1056},
        {"udp-batch-size", required_argument, 0, 1057},
        {"udp-inflight", required_argument, 0, 1058},
        {"udp-min-probe-interval", required_argument, 0, 1059},
        {"udp-linux-advanced", required_argument, 0, 1060},
        {"fast", no_argument, 0, 1061},

        {"show-closed", no_argument, 0, 1006},
        {"osscan-guess", no_argument, 0, 1048},
        {"osscan-limit", no_argument, 0, 1049},
        {"verbose", no_argument, 0, 'v'},
        {"verbosity", required_argument, 0, 1046},
        {"help", no_argument, 0, 'h'},
        {"proxy", required_argument, 0, 1007},
        {"fragment", no_argument, 0, 2000},
        {"mtu", required_argument, 0, 2009},
        {"frag-order", required_argument, 0, 2010},
        {"decoy", required_argument, 0, 2001},
        {"decoys", required_argument, 0, 2001},
        {"spoof-source", required_argument, 0, 2002},
        {"data-length", required_argument, 0, 2003},
        {"ttl", required_argument, 0, 2004},
        {"source-port", required_argument, 0, 'g'},
        {"randomize-hosts", no_argument, 0, 2011},
        {"spoof-mac", required_argument, 0, 2012},
        {"badsum", no_argument, 0, 2005},
        {"scan-delay", required_argument, 0, 2006},
        {"max-scan-delay", required_argument, 0, 2008},
        {"randomize-data", no_argument, 0, 2007},
        {"scan-jitter", required_argument, 0, 2013},
        {"defeat-rst-ratelimit", no_argument, 0, 2014},

        {0, 0, 0, 0}};

    int opt;

    while ((opt = getopt_long(argc, argv, "t:p:T:W:o:s:P:g:nRvh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 't':
            if (add_cidr_targets(cfg, optarg) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 'p':
            if (parse_ports(optarg, cfg) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 'T':
            if (parse_u32_arg(optarg, 1, 100000, &cfg->threads) != NP_OK)
                return NP_ERR_ARGS;
            cfg->threads_explicit = true;
            break;

        case 'W':
        {
            uint32_t workers = 0;
            if (parse_u32_arg(optarg, 1, 100000, &workers) != NP_OK)
                return NP_ERR_ARGS;
            cfg->workers = (int)workers;
            break;
        }

        case 1005:
            if (parse_u32_arg(optarg, 1, 86400000u, &cfg->timeout_ms) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 1034:
        {
            uint32_t template_id = 0;
            if (parse_u32_arg(optarg, 0, 5, &template_id) != NP_OK)
                return NP_ERR_ARGS;
            cfg->timing_template = (np_timing_template_t)template_id;
            cfg->timing_template_explicit = true;
            break;
        }

        case 1035:
            if (parse_u32_arg(optarg, 1, NP_MAX_TARGETS, &cfg->min_hostgroup) != NP_OK)
                return NP_ERR_ARGS;
            cfg->min_hostgroup_explicit = true;
            break;

        case 1036:
            if (parse_u32_arg(optarg, 1, NP_MAX_TARGETS, &cfg->max_hostgroup) != NP_OK)
                return NP_ERR_ARGS;
            cfg->max_hostgroup_explicit = true;
            break;

        case 1037:
            if (parse_u32_arg(optarg, 1, 100000, &cfg->min_parallelism) != NP_OK)
                return NP_ERR_ARGS;
            cfg->min_parallelism_explicit = true;
            break;

        case 1038:
            if (parse_u32_arg(optarg, 1, 100000, &cfg->max_parallelism) != NP_OK)
                return NP_ERR_ARGS;
            cfg->max_parallelism_explicit = true;
            break;

        case 1039:
            if (parse_time_arg_ms(optarg, 1, 86400000u, &cfg->min_rtt_timeout_ms) != NP_OK)
                return NP_ERR_ARGS;
            cfg->min_rtt_timeout_explicit = true;
            break;

        case 1040:
            if (parse_time_arg_ms(optarg, 1, 86400000u, &cfg->max_rtt_timeout_ms) != NP_OK)
                return NP_ERR_ARGS;
            cfg->max_rtt_timeout_explicit = true;
            break;

        case 1041:
            if (parse_time_arg_ms(optarg, 1, 86400000u, &cfg->initial_rtt_timeout_ms) != NP_OK)
                return NP_ERR_ARGS;
            cfg->initial_rtt_timeout_explicit = true;
            break;

        case 1042:
            if (parse_time_arg_ms(optarg, 0, 86400000u, &cfg->host_timeout_ms) != NP_OK)
                return NP_ERR_ARGS;
            cfg->host_timeout_explicit = true;
            break;

        case 1043:
            if (parse_u32_arg(optarg, 1, 10000000u, &cfg->min_rate) != NP_OK)
                return NP_ERR_ARGS;
            cfg->min_rate_explicit = true;
            break;

        case 1044:
            if (parse_u32_arg(optarg, 1, 10000000u, &cfg->max_rate) != NP_OK)
                return NP_ERR_ARGS;
            cfg->max_rate_explicit = true;
            break;

        case 1045:
            if (parse_u32_arg(optarg, 0, 50, &cfg->max_retries) != NP_OK)
                return NP_ERR_ARGS;
            cfg->max_retries_explicit = true;
            break;

        case 'o':
            cfg->output_file = optarg;
            break;

        case 'v':
            cfg->verbose = true;
            verbose_count++;
            break;

        case 1046:
            if (parse_verbosity_arg(optarg, &cfg->verbosity) != NP_OK)
                return NP_ERR_ARGS;
            verbosity_explicit = true;
            break;

        case 'n':
            cfg->dns_mode = NP_DNS_NEVER;
            break;

        case 'R':
            cfg->dns_mode = NP_DNS_ALWAYS;
            break;

        case 's':
            if (parse_short_scan_mode(cfg, optarg, argc, argv) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 'P':
        {
            if (!optarg || optarg[0] == '\0')
                return NP_ERR_ARGS;

            char mode = optarg[0];
            const char *rest = optarg + 1;

            switch (mode)
            {
            case 'n':
                cfg->host_discovery_mode = NP_HOST_DISCOVERY_SKIP;
                break;
            case 'E':
                cfg->probe_icmp_echo = true;
                break;
            case 'P':
                cfg->probe_icmp_timestamp = true;
                break;
            case 'M':
                cfg->probe_icmp_netmask = true;
                break;
            case 'S':
                cfg->probe_tcp_syn = true;
                if (rest && rest[0] && !np_parse_ports(rest, &cfg->discovery_tcp_syn_ports))
                    return NP_ERR_ARGS;
                break;
            case 'A':
                cfg->probe_tcp_ack = true;
                if (rest && rest[0] && !np_parse_ports(rest, &cfg->discovery_tcp_ack_ports))
                    return NP_ERR_ARGS;
                break;
            case 'U':
                cfg->probe_udp = true;
                if (rest && rest[0] && !np_parse_ports(rest, &cfg->discovery_udp_ports))
                    return NP_ERR_ARGS;
                break;
            case 'Y':
                cfg->probe_sctp_init = true;
                if (rest && rest[0] && !np_parse_ports(rest, &cfg->discovery_sctp_ports))
                    return NP_ERR_ARGS;
                break;
            case 'O':
                cfg->probe_ip_proto = true;
                if (parse_discovery_protocols(rest,
                                              cfg->discovery_ip_protocols,
                                              &cfg->discovery_ip_protocol_count) != NP_OK)
                    return NP_ERR_ARGS;
                break;
            default:
                return NP_ERR_ARGS;
            }
            break;
        }

        case 1000:
            cfg->output_fmt = NP_OUTPUT_JSON;
            explicit_format = true;
            break;

        case 1001:
            cfg->output_fmt = NP_OUTPUT_CSV;
            explicit_format = true;
            break;

        case 1002:
            cfg->output_fmt = NP_OUTPUT_GREPPABLE;
            explicit_format = true;
            break;

        case 1050:
            cfg->output_fmt = NP_OUTPUT_XML;
            cfg->output_file = optarg;
            explicit_format = true;
            break;

        case 1051:
            cfg->output_fmt = NP_OUTPUT_HTML;
            cfg->output_file = optarg;
            explicit_format = true;
            break;

        case 1052:
            cfg->engine_mode = NP_ENGINE_FULL;
            cfg->service_version_detect = true;
            cfg->os_detect = true;
            break;

        case 1053:
            if (parse_u32_arg(optarg, 1, 128, &cfg->full_rx_threads) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 1054:
            if (parse_u32_arg(optarg, 1024, 1u << 24, &cfg->full_queue_capacity) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 1055:
            if (parse_u32_arg(optarg, 1, 1u << 20, &cfg->full_max_inflight) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 1056:
            if (parse_udp_fast_path_mode(optarg, &cfg->udp_fast_path_mode) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 1057:
            if (parse_u32_arg(optarg, 1, 1024, &cfg->udp_batch_size) != NP_OK)
                return NP_ERR_ARGS;
            cfg->udp_batch_size_explicit = true;
            break;

        case 1058:
            if (parse_u32_arg(optarg, 16, 8192, &cfg->udp_inflight_per_thread) != NP_OK)
                return NP_ERR_ARGS;
            cfg->udp_inflight_explicit = true;
            break;

        case 1059:
            if (parse_time_arg_us(optarg, 0, 3600000000u, &cfg->udp_min_probe_interval_us) != NP_OK)
                return NP_ERR_ARGS;
            cfg->udp_min_probe_interval_explicit = true;
            break;

        case 1060:
            if (strcasecmp(optarg, "on") == 0)
                cfg->udp_linux_advanced = true;
            else if (strcasecmp(optarg, "off") == 0)
                cfg->udp_linux_advanced = false;
            else
                return NP_ERR_ARGS;
            break;

        case 1061:
            cfg->fast_mode = true;
            break;

        case 1003:
            set_scan_type(cfg, NP_SCAN_TCP_SYN);
            break;

        case 1004:
            set_scan_type(cfg, NP_SCAN_UDP);
            break;

        case 1006:
            cfg->show_closed = true;
            break;

        case 1048:
            cfg->osscan_guess = true;
            break;

        case 1049:
            cfg->osscan_limit = true;
            break;

        case 1007:
        {
            np_status_t prc = np_proxy_parse(optarg, &cfg->proxy);
            if (prc != NP_OK)
            {
                np_error(NP_ERR_RUNTIME, "Invalid proxy URL: %s\n", optarg);
                return NP_ERR_ARGS;
            }
            break;
        }

        case 1008:
            set_scan_type(cfg, NP_SCAN_TCP_CONNECT);
            break;
        case 1009:
            set_scan_type(cfg, NP_SCAN_TCP_ACK);
            break;
        case 1010:
            set_scan_type(cfg, NP_SCAN_TCP_WINDOW);
            break;
        case 1011:
            set_scan_type(cfg, NP_SCAN_TCP_MAIMON);
            break;
        case 1012:
            set_scan_type(cfg, NP_SCAN_TCP_NULL);
            break;
        case 1013:
            set_scan_type(cfg, NP_SCAN_TCP_FIN);
            break;
        case 1014:
            set_scan_type(cfg, NP_SCAN_TCP_XMAS);
            break;
        case 1015:
            if (parse_scanflags_mask(optarg, &cfg->tcp_custom_flags) != NP_OK)
                return NP_ERR_ARGS;
            set_scan_type(cfg, NP_SCAN_TCP_CUSTOM_FLAGS);
            break;
        case 1016:
        {
            set_scan_type(cfg, NP_SCAN_IDLE);
            char zombie[NP_MAX_HOSTNAME_LEN + 32];
            strncpy(zombie, optarg, sizeof(zombie) - 1);
            zombie[sizeof(zombie) - 1] = '\0';

            char *colon = strchr(zombie, ':');
            if (colon)
            {
                *colon = '\0';
                long p = strtol(colon + 1, NULL, 10);
                if (p <= 0 || p > 65535)
                    return NP_ERR_ARGS;
                cfg->zombie_probe_port = (uint16_t)p;
            }

            strncpy(cfg->zombie_host, zombie, sizeof(cfg->zombie_host) - 1);
            cfg->zombie_host[sizeof(cfg->zombie_host) - 1] = '\0';
            break;
        }
        case 1017:
            set_scan_type(cfg, NP_SCAN_SCTP_INIT);
            break;
        case 1018:
            set_scan_type(cfg, NP_SCAN_SCTP_COOKIE_ECHO);
            break;
        case 1019:
            set_scan_type(cfg, NP_SCAN_IP_PROTOCOL);
            break;
        case 1020:
            if (parse_version_intensity(optarg, &cfg->version_intensity) != NP_OK)
                return NP_ERR_ARGS;
            version_tuning_seen = true;
            break;
        case 1021:
            cfg->version_intensity = 2;
            version_tuning_seen = true;
            break;
        case 1022:
            cfg->version_intensity = 9;
            version_tuning_seen = true;
            break;
        case 1023:
            cfg->version_trace = true;
            break;
        case 1047:
            cfg->tls_info = true;
            break;
        case 1024:
            cfg->traceroute_enabled = true;
            break;
        case 1025:
        {
            char tmp[512];
            strncpy(tmp, optarg, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';

            cfg->dns_server_count = 0;
            for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ","))
            {
                while (*tok == ' ' || *tok == '\t') tok++;
                if (*tok == '\0')
                    continue;

                if (cfg->dns_server_count >= NP_MAX_DNS_SERVERS)
                    return NP_ERR_ARGS;

                strncpy(cfg->dns_servers[cfg->dns_server_count], tok,
                        sizeof(cfg->dns_servers[cfg->dns_server_count]) - 1);
                cfg->dns_servers[cfg->dns_server_count][sizeof(cfg->dns_servers[cfg->dns_server_count]) - 1] = '\0';
                cfg->dns_server_count++;
            }
            break;
        }
        case 1026:
            cfg->dns_mode = NP_DNS_SYSTEM;
            break;
        case 1027:
            cfg->host_discovery_mode = NP_HOST_DISCOVERY_SKIP;
            break;
        case 1028:
            cfg->host_discovery_mode = NP_HOST_DISCOVERY_PING_ONLY;
            break;
        case 1029:
            cfg->host_discovery_mode = NP_HOST_DISCOVERY_LIST_ONLY;
            break;
        case 1030:
            input_list_file = optarg;
            break;
        case 1031:
        {
            char *endptr = NULL;
            long parsed = strtol(optarg, &endptr, 10);
            if (!endptr || *endptr != '\0' || parsed <= 0 || parsed > NP_MAX_TARGETS)
                return NP_ERR_ARGS;
            random_target_count = (uint32_t)parsed;
            break;
        }
        case 1032:
            exclude_value = optarg;
            break;
        case 1033:
            exclude_file = optarg;
            break;
        case 2000:
            cfg->evasion.fragment_packets = true;
            if (cfg->evasion.fragment_mtu == 0)
                cfg->evasion.fragment_mtu = 28;
            break;

        case 2009:
        {
            uint32_t mtu = 0;
            if (parse_u32_arg(optarg, 24, 65535, &mtu) != NP_OK)
                return NP_ERR_ARGS;
            cfg->evasion.fragment_mtu = (uint16_t)mtu;
            cfg->evasion.fragment_packets = true;
            break;
        }

        case 2010:
            if (strcmp(optarg, "random") == 0)
                cfg->evasion.fragment_order = NP_FRAG_ORDER_RANDOM;
            else if (strcmp(optarg, "inorder") == 0)
                cfg->evasion.fragment_order = NP_FRAG_ORDER_INORDER;
            else
                return NP_ERR_ARGS;
            break;

        case 2001:
            if (!np_decoy_parse_spec(&cfg->evasion, optarg))
                return NP_ERR_ARGS;
            break;

        case 2002:
            strncpy(cfg->evasion.spoof_source, optarg, INET_ADDRSTRLEN - 1);
            break;

        case 2003:
            cfg->evasion.data_length = atoi(optarg);
            break;

        case 2004:
        {
            uint32_t ttl = 0;
            if (parse_u32_arg(optarg, 1, 255, &ttl) != NP_OK)
                return NP_ERR_ARGS;
            cfg->evasion.ttl_value = (uint8_t)ttl;
            cfg->evasion.ttl_set = true;
            break;
        }

        case 'g':
        {
            uint32_t src_port = 0;
            if (parse_u32_arg(optarg, 1, 65535, &src_port) != NP_OK)
                return NP_ERR_ARGS;
            cfg->evasion.source_port = (uint16_t)src_port;
            cfg->evasion.source_port_set = true;
            break;
        }

        case 2011:
            cfg->evasion.randomize_hosts = true;
            cfg->randomize_hosts = true;
            break;

        case 2012:
            if (!np_spoof_parse_mac(&cfg->evasion, optarg))
                return NP_ERR_ARGS;
            break;

        case 2005:
            cfg->evasion.bad_checksum = true;
            break;

        case 2006:
            if (parse_time_arg_us(optarg, 0, 3600000000u, &cfg->scan_delay_us) != NP_OK)
                return NP_ERR_ARGS;
            cfg->scan_delay_explicit = true;
            cfg->evasion.packet_delay_us = (int)cfg->scan_delay_us;
            break;

        case 2007:
            cfg->evasion.randomize_data = true;
            break;

        case 2008:
            if (parse_time_arg_us(optarg, 0, 3600000000u, &cfg->max_scan_delay_us) != NP_OK)
                return NP_ERR_ARGS;
            cfg->max_scan_delay_explicit = true;
            break;

        case 2013:
            if (parse_time_arg_us(optarg, 0, 3600000000u, &cfg->evasion.scan_jitter_us) != NP_OK)
                return NP_ERR_ARGS;
            break;

        case 2014:
            cfg->evasion.defeat_rst_ratelimit = true;
            break;

        case 'h':
            np_args_usage(argv[0]);
            exit(0);

        default:
            np_args_usage(argv[0]);
            exit(1);
        }
    }

    while (optind < argc)
    {
        if (add_cidr_targets(cfg, argv[optind]) != NP_OK)
            return NP_ERR_ARGS;
        optind++;
    }

    if (input_list_file)
    {
        np_status_t frc = add_targets_from_file(cfg, input_list_file);
        if (frc != NP_OK)
        {
            np_error(NP_ERR_RUNTIME, "Failed to parse input targets from: %s\n", input_list_file);
            return frc;
        }
    }

    if (random_target_count > 0)
    {
        np_status_t rrc = add_random_targets(cfg, random_target_count);
        if (rrc != NP_OK)
        {
            np_error(NP_ERR_RUNTIME, "Failed to generate random targets for -iR %u\n", random_target_count);
            return rrc;
        }
    }

    if (exclude_value || exclude_file)
    {
        np_string_list_t exclude = {0};

        if (exclude_value)
        {
            np_status_t erc = add_excludes_from_string(&exclude, exclude_value);
            if (erc != NP_OK)
            {
                string_list_free(&exclude);
                np_error(NP_ERR_RUNTIME, "Invalid --exclude specification\n");
                return erc;
            }
        }

        if (exclude_file)
        {
            np_status_t erc = add_excludes_from_file(&exclude, exclude_file);
            if (erc != NP_OK)
            {
                string_list_free(&exclude);
                np_error(NP_ERR_RUNTIME, "Failed to parse --excludefile: %s\n", exclude_file);
                return erc;
            }
        }

        apply_exclusions(cfg, &exclude);
        string_list_free(&exclude);
    }

    apply_timing_template_defaults(cfg);
    apply_fast_mode(cfg);
    if (validate_timing_perf(cfg) != NP_OK)
    {
        np_error(NP_ERR_RUNTIME, "Invalid timing/performance option combination\n");
        return NP_ERR_ARGS;
    }

    cfg->evasion.packet_delay_us = (int)cfg->scan_delay_us;

    if (verbosity_explicit)
    {
        cfg->verbose = (cfg->verbosity >= NP_LOG_VERBOSE);
    }
    else
    {
        if (verbose_count <= 0)
            cfg->verbosity = NP_LOG_NORMAL;
        else if (verbose_count == 1)
            cfg->verbosity = NP_LOG_VERBOSE;
        else if (verbose_count == 2)
            cfg->verbosity = NP_LOG_DEBUG;
        else
            cfg->verbosity = NP_LOG_TRACE;
        cfg->verbose = (cfg->verbosity >= NP_LOG_VERBOSE);
    }

    if (cfg->target_count == 0)
    {
        np_error(NP_ERR_RUNTIME, "No target specified.\n");
        return NP_ERR_ARGS;
    }

    if (!cfg->service_version_detect)
    {
        if (cfg->version_trace)
        {
            np_error(NP_ERR_RUNTIME, "--version-trace requires -sV\n");
            return NP_ERR_ARGS;
        }

        if (version_tuning_seen)
        {
            np_error(NP_ERR_RUNTIME, "version tuning flags require -sV\n");
            return NP_ERR_ARGS;
        }
    }

    if ((cfg->host_discovery_mode == NP_HOST_DISCOVERY_PING_ONLY ||
         cfg->host_discovery_mode == NP_HOST_DISCOVERY_LIST_ONLY) &&
        cfg->service_version_detect)
    {
        np_error(NP_ERR_RUNTIME, "-sV cannot be used with -sn/-sL\n");
        return NP_ERR_ARGS;
    }

    if (cfg->host_discovery_mode == NP_HOST_DISCOVERY_LIST_ONLY && cfg->scan_type_forced)
    {
        np_error(NP_ERR_RUNTIME, "-sL cannot be used with explicit port scan types\n");
        return NP_ERR_ARGS;
    }

    /* ── Auto-detect output format from file extension ── */
    if (!explicit_format && cfg->output_file)
    {
        cfg->output_fmt = detect_output_format(cfg->output_file);
    }

    /* Default ports: protocol-aware fallback when -p/--ports is omitted. */
    if (cfg->ports.count == 0)
    {
        for (uint32_t i = 0; i < np_top_ports_count; i++)
        {
            if (cfg->ports.count >= NP_MAX_PORT_RANGES)
                break;

            np_port_range_t r = {
                .start = np_top_ports_top_1000[i],
                .end = np_top_ports_top_1000[i]};

            cfg->ports.ranges[cfg->ports.count++] = r;
        }
    }

    return NP_OK;
}
