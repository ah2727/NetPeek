#define _POSIX_C_SOURCE 200809L

#include "service_version.h"
#include "core/error.h"
#include "scanner_internal.h"
#include "thread_pool.h"
#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

typedef struct
{
    np_config_t *cfg;
    uint32_t target_idx;
    uint32_t port_idx;
} np_sv_task_arg_t;

typedef struct
{
    bool matched;
    int confidence;
    char service[32];
    char version[128];
    char method[32];
} np_sv_candidate_t;

static pcre2_code **g_sv_regex_cache = NULL;
static pthread_once_t g_sv_regex_once = PTHREAD_ONCE_INIT;

static void np_sv_trim(char *s);

static void np_sv_regex_cache_init_once(void)
{
    g_sv_regex_cache = calloc(NMAP_PROBES_COUNT, sizeof(*g_sv_regex_cache));
    if (!g_sv_regex_cache)
        return;

    for (unsigned int i = 0; i < NMAP_PROBES_COUNT; i++)
    {
        const char *pattern = NMAP_PROBES[i].regex;
        if (!pattern || !pattern[0])
            continue;

        int errcode = 0;
        PCRE2_SIZE erroffset = 0;

        pcre2_code *re = pcre2_compile((PCRE2_SPTR)pattern,
                                       PCRE2_ZERO_TERMINATED,
                                       0,
                                       &errcode,
                                       &erroffset,
                                       NULL);
        if (!re)
            continue;

        (void)pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
        g_sv_regex_cache[i] = re;
    }
}

static inline void np_sv_regex_cache_init(void)
{
    (void)pthread_once(&g_sv_regex_once, np_sv_regex_cache_init_once);
}

static bool np_sv_state_probe_eligible(np_port_state_t state)
{
    switch (state)
    {
    case NP_PORT_OPEN:
    case NP_PORT_OPEN_FILTERED:
        return true;
    default:
        return false;
    }
}

static void np_sv_trace(const np_config_t *cfg,
                        uint32_t target_idx,
                        uint16_t port,
                        const char *fmt,
                        ...)
{
    if (!cfg || !cfg->version_trace)
        return;

    np_error(NP_ERR_RUNTIME, "[sV] t=%u p=%u ", target_idx, port);

    va_list ap;
    va_start(ap, fmt);
    np_verror(NP_ERR_RUNTIME, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}

static void np_sv_strlcpy(char *dst, size_t cap, const char *src)
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

static const char *np_sv_guess_service_from_nmap(uint16_t port,
                                                 const char *proto)
{
    const char *best = NULL;
    float best_freq = -1.0f;

    for (unsigned int i = 0; i < NMAP_SERVICES_COUNT; i++)
    {
        const nmap_service_t *svc = &NMAP_SERVICES[i];
        if (svc->port != port)
            continue;

        if (proto && svc->protocol && strcmp(svc->protocol, proto) != 0)
            continue;

        if (!best || svc->frequency > best_freq)
        {
            best = svc->service;
            best_freq = svc->frequency;
        }
    }

    return best;
}

static size_t np_sv_normalize(char *dst, size_t dst_cap,
                              const char *src, size_t src_len)
{
    if (!dst || dst_cap == 0)
        return 0;

    if (!src || src_len == 0)
    {
        dst[0] = '\0';
        return 0;
    }

    size_t wr = 0;
    for (size_t i = 0; i < src_len && wr + 1 < dst_cap; i++)
    {
        unsigned char c = (unsigned char)src[i];
        if (c == '\r')
            continue;
        if (c == '\0')
            continue;

        if (c == '\n' || c == '\t' || (c >= 32 && c < 127))
            dst[wr++] = (char)c;
        else
            dst[wr++] = ' ';
    }

    dst[wr] = '\0';
    return wr;
}

static void np_sv_version_from_capture(const char *banner,
                                       size_t banner_len,
                                       const pcre2_code *re,
                                       pcre2_match_data *match,
                                       char *out,
                                       size_t out_cap)
{
    if (!out || out_cap == 0)
        return;

    out[0] = '\0';

    if (!match)
        return;

    PCRE2_SIZE *ov = pcre2_get_ovector_pointer(match);
    uint32_t cap_count = pcre2_get_ovector_count(match);

    for (uint32_t i = 1; i < cap_count; i++)
    {
        PCRE2_SIZE start = ov[i * 2];
        PCRE2_SIZE end = ov[i * 2 + 1];

        if (start == PCRE2_UNSET || end == PCRE2_UNSET || end <= start)
            continue;
        if (start >= banner_len)
            continue;
        if (end > banner_len)
            end = banner_len;

        size_t n = (size_t)(end - start);
        if (n >= out_cap)
            n = out_cap - 1;
        memcpy(out, banner + start, n);
        out[n] = '\0';
        np_sv_trim(out);
        if (out[0])
            return;
    }

    if (banner && banner_len > 0)
    {
        size_t n = banner_len;
        if (n >= out_cap)
            n = out_cap - 1;
        memcpy(out, banner, n);
        out[n] = '\0';
        np_sv_trim(out);
    }

    (void)re;
}

static bool np_sv_match_nmap_banner(const np_config_t *cfg,
                                    uint16_t port,
                                    const char *banner,
                                    size_t banner_len,
                                    np_sv_candidate_t *cand)
{
    if (!banner || banner_len == 0 || !cand)
        return false;

    np_sv_regex_cache_init();
    if (!g_sv_regex_cache)
        return false;

    const char *port_hint = np_sv_guess_service_from_nmap(port, "tcp");
    pcre2_match_data *md = NULL;
    int best_score = 0;
    np_sv_candidate_t best = {0};

    for (unsigned int pass = 0; pass < 3; pass++)
    {
        bool pass_only_hint = (pass == 0 && port_hint && cfg->version_intensity <= 7);
        bool allow_soft = (pass == 2 || cfg->version_intensity >= 9);
        bool global_pass = (pass > 0);

        if (pass == 1 && cfg->version_intensity < 4)
            continue;
        if (pass == 2 && cfg->version_intensity < 7)
            continue;

        for (unsigned int i = 0; i < NMAP_PROBES_COUNT; i++)
        {
            const nmap_probe_t *probe = &NMAP_PROBES[i];
            pcre2_code *re = g_sv_regex_cache[i];

            if (!re)
                continue;
            if (!allow_soft && probe->softmatch)
                continue;
            if (pass_only_hint && strcmp(probe->service, port_hint) != 0)
                continue;
            if (!global_pass && !pass_only_hint)
                continue;

            if (!md)
            {
                md = pcre2_match_data_create_from_pattern(re, NULL);
                if (!md)
                    return false;
            }

            int rc = pcre2_match(re,
                                 (PCRE2_SPTR)banner,
                                 banner_len,
                                 0,
                                 0,
                                 md,
                                 NULL);
            if (rc < 0)
                continue;

            int score = probe->softmatch ? 55 : 85;
            if (port_hint && strcmp(port_hint, probe->service) == 0)
                score += 10;
            if (cfg->version_intensity >= 9)
                score += 3;

            if (score > best_score)
            {
                memset(&best, 0, sizeof(best));
                best_score = score;
                best.matched = true;
                best.confidence = score;
                np_sv_strlcpy(best.service, sizeof(best.service), probe->service);
                np_sv_strlcpy(best.method, sizeof(best.method),
                              probe->softmatch ? "nmap-softmatch" : "nmap-regex");
                np_sv_version_from_capture(banner,
                                           banner_len,
                                           re,
                                           md,
                                           best.version,
                                           sizeof(best.version));
            }
        }

        if (best_score >= 90)
            break;
    }

    if (md)
        pcre2_match_data_free(md);

    if (!best.matched)
        return false;

    *cand = best;
    return true;
}

static void np_sv_trim(char *s)
{
    if (!s)
        return;

    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\r' || s[len - 1] == '\n' || isspace((unsigned char)s[len - 1])))
    {
        s[len - 1] = '\0';
        len--;
    }

    char *p = s;
    while (*p && isspace((unsigned char)*p))
        p++;

    if (p != s)
        memmove(s, p, strlen(p) + 1);
}

static bool np_sv_find_line_value(const char *buf,
                                  const char *key,
                                  char *out,
                                  size_t out_cap)
{
    if (!buf || !key || !out || out_cap == 0)
        return false;

    size_t key_len = strlen(key);
    const char *p = buf;
    while (*p)
    {
        if (strncasecmp(p, key, key_len) == 0)
        {
            const char *v = p + key_len;
            while (*v == ' ' || *v == '\t')
                v++;
            const char *line_end = strstr(v, "\r\n");
            if (!line_end)
                line_end = strchr(v, '\n');
            if (!line_end)
                line_end = v + strlen(v);

            size_t n = (size_t)(line_end - v);
            if (n >= out_cap)
                n = out_cap - 1;

            memcpy(out, v, n);
            out[n] = '\0';
            np_sv_trim(out);
            return out[0] != '\0';
        }

        const char *next = strchr(p, '\n');
        if (!next)
            break;
        p = next + 1;
    }

    return false;
}

static int np_sv_connect_with_timeout(const np_target_t *target,
                                      uint16_t port,
                                      uint32_t timeout_ms,
                                      int *out_fd)
{
    int fd = -1;
    np_connect_rc_t rc = np_start_connect(target, port, (int)timeout_ms, &fd);

    if (rc == NP_CONNECT_FAILED || fd < 0)
        return -1;

    if (rc == NP_CONNECT_IN_PROGRESS)
    {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0)
        {
            close(fd);
            return -1;
        }

        int err = np_get_socket_error(fd);
        if (err != 0)
        {
            close(fd);
            return -1;
        }
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    struct timeval tv;
    tv.tv_sec = (time_t)(timeout_ms / 1000);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    *out_fd = fd;
    return 0;
}

static ssize_t np_sv_recv_text(int fd, char *buf, size_t cap)
{
    if (cap == 0)
        return -1;

    ssize_t n = recv(fd, buf, cap - 1, 0);
    if (n < 0)
        return n;

    buf[n] = '\0';
    return n;
}

static ssize_t np_sv_peek_text(int fd, char *buf, size_t cap)
{
    if (cap == 0)
        return -1;

    ssize_t n = recv(fd, buf, cap - 1, MSG_PEEK);
    if (n < 0)
        return n;

    buf[n] = '\0';
    return n;
}

static void np_sv_close_fd(int *fd)
{
    if (!fd || *fd < 0)
        return;

    shutdown(*fd, SHUT_RDWR);
    close(*fd);
    *fd = -1;
}

static bool np_sv_probe_ssh(int fd, np_sv_candidate_t *cand)
{
    char buf[512];
    ssize_t n = np_sv_recv_text(fd, buf, sizeof(buf));
    if (n <= 0)
        return false;

    if (strncmp(buf, "SSH-", 4) != 0)
        return false;

    np_sv_strlcpy(cand->service, sizeof(cand->service), "ssh");
    np_sv_strlcpy(cand->version, sizeof(cand->version), buf);
    np_sv_strlcpy(cand->method, sizeof(cand->method), "ssh-banner");
    cand->confidence = 95;
    cand->matched = true;
    return true;
}

static bool np_sv_probe_ftp(int fd, np_sv_candidate_t *cand)
{
    char buf[512];
    ssize_t n = np_sv_recv_text(fd, buf, sizeof(buf));
    if (n <= 0)
        return false;

    if (strncmp(buf, "220", 3) != 0)
        return false;

    np_sv_strlcpy(cand->service, sizeof(cand->service), "ftp");
    np_sv_strlcpy(cand->version, sizeof(cand->version), buf);
    np_sv_strlcpy(cand->method, sizeof(cand->method), "ftp-banner");
    cand->confidence = 85;
    cand->matched = true;
    return true;
}

static bool np_sv_probe_smtp(int fd, np_sv_candidate_t *cand)
{
    char buf[1024];
    ssize_t n = np_sv_recv_text(fd, buf, sizeof(buf));
    if (n <= 0)
        return false;

    if (strncmp(buf, "220", 3) != 0)
        return false;

    const char *ehlo = "EHLO netpeek.local\r\n";
    (void)send(fd, ehlo, strlen(ehlo), 0);
    (void)np_sv_recv_text(fd, buf, sizeof(buf));

    np_sv_strlcpy(cand->service, sizeof(cand->service), "smtp");
    np_sv_strlcpy(cand->version, sizeof(cand->version), buf);
    np_sv_strlcpy(cand->method, sizeof(cand->method), "smtp-banner");
    cand->confidence = 88;
    cand->matched = true;
    return true;
}

static bool np_sv_probe_pop3(int fd, np_sv_candidate_t *cand)
{
    char buf[1024];
    ssize_t n = np_sv_recv_text(fd, buf, sizeof(buf));
    if (n <= 0)
        return false;

    if (strncmp(buf, "+OK", 3) != 0)
        return false;

    const char *capa = "CAPA\r\n";
    (void)send(fd, capa, strlen(capa), 0);
    (void)np_sv_recv_text(fd, buf, sizeof(buf));

    np_sv_strlcpy(cand->service, sizeof(cand->service), "pop3");
    np_sv_strlcpy(cand->version, sizeof(cand->version), buf);
    np_sv_strlcpy(cand->method, sizeof(cand->method), "pop3-banner");
    cand->confidence = 84;
    cand->matched = true;
    return true;
}

static bool np_sv_probe_imap(int fd, np_sv_candidate_t *cand)
{
    char buf[1024];
    ssize_t n = np_sv_recv_text(fd, buf, sizeof(buf));
    if (n <= 0)
        return false;

    if (strncasecmp(buf, "* OK", 4) != 0)
        return false;

    const char *capability = "a001 CAPABILITY\r\n";
    (void)send(fd, capability, strlen(capability), 0);
    (void)np_sv_recv_text(fd, buf, sizeof(buf));

    np_sv_strlcpy(cand->service, sizeof(cand->service), "imap");
    np_sv_strlcpy(cand->version, sizeof(cand->version), buf);
    np_sv_strlcpy(cand->method, sizeof(cand->method), "imap-banner");
    cand->confidence = 84;
    cand->matched = true;
    return true;
}

static bool np_sv_probe_redis(int fd, np_sv_candidate_t *cand)
{
    char buf[1024];
    const char *ping = "*1\r\n$4\r\nPING\r\n";
    if (send(fd, ping, strlen(ping), 0) < 0)
        return false;

    ssize_t n = np_sv_recv_text(fd, buf, sizeof(buf));
    if (n <= 0)
        return false;

    if (strncmp(buf, "+PONG", 5) != 0 && strncmp(buf, "-ERR", 4) != 0)
        return false;

    const char *info = "*1\r\n$4\r\nINFO\r\n";
    (void)send(fd, info, strlen(info), 0);
    (void)np_sv_recv_text(fd, buf, sizeof(buf));

    np_sv_strlcpy(cand->service, sizeof(cand->service), "redis");
    np_sv_strlcpy(cand->version, sizeof(cand->version), buf);
    np_sv_strlcpy(cand->method, sizeof(cand->method), "redis-info");
    cand->confidence = 90;
    cand->matched = true;
    return true;
}

static bool np_sv_probe_mysql(int fd, np_sv_candidate_t *cand)
{
    unsigned char buf[512];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 6)
        return false;

    if (buf[4] != 0x0a)
        return false;

    const char *ver = (const char *)&buf[5];
    np_sv_strlcpy(cand->service, sizeof(cand->service), "mysql");
    np_sv_strlcpy(cand->version, sizeof(cand->version), ver);
    np_sv_strlcpy(cand->method, sizeof(cand->method), "mysql-handshake");
    cand->confidence = 93;
    cand->matched = true;
    return true;
}

static bool np_sv_probe_http(int fd, np_sv_candidate_t *cand)
{
    char buf[2048];
    const char *req = "HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: netpeek-sv\r\n\r\n";

    if (send(fd, req, strlen(req), 0) < 0)
        return false;

    ssize_t n = np_sv_recv_text(fd, buf, sizeof(buf));
    if (n <= 0)
        return false;

    if (strncasecmp(buf, "HTTP/", 5) != 0)
        return false;

    char server[128];
    if (np_sv_find_line_value(buf, "Server:", server, sizeof(server)))
        np_sv_strlcpy(cand->version, sizeof(cand->version), server);
    else
        np_sv_strlcpy(cand->version, sizeof(cand->version), "HTTP service");

    np_sv_strlcpy(cand->service, sizeof(cand->service), "http");
    np_sv_strlcpy(cand->method, sizeof(cand->method), "http-head");
    cand->confidence = 92;
    cand->matched = true;
    return true;
}

static void np_sv_set_fallback(np_port_result_t *res)
{
    if (!res->service[0])
    {
        const char *svc = np_sv_guess_service_from_nmap(res->port, "tcp");
        if (!svc)
            svc = np_service_name(res->port);
        if (svc)
            np_sv_strlcpy(res->service, sizeof(res->service), svc);
    }
}

static void np_sv_probe_port(np_config_t *cfg,
                             uint32_t target_idx,
                             np_target_t *target,
                             np_port_result_t *res)
{
    if (!cfg || !target || !res)
        return;

    np_sv_set_fallback(res);

    int fd = -1;
    if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) != 0)
    {
        np_sv_trace(cfg, target_idx, res->port, "connect failed");
        return;
    }

    np_sv_candidate_t best;
    memset(&best, 0, sizeof(best));

    char passive_raw[4096];
    ssize_t passive_n = np_sv_peek_text(fd, passive_raw, sizeof(passive_raw));
    if (passive_n > 0)
    {
        char passive_norm[4096];
        size_t norm_len = np_sv_normalize(passive_norm,
                                          sizeof(passive_norm),
                                          passive_raw,
                                          (size_t)passive_n);
        np_sv_candidate_t pm = {0};
        if (norm_len > 0 && np_sv_match_nmap_banner(cfg,
                                                     res->port,
                                                     passive_norm,
                                                     norm_len,
                                                     &pm) &&
            pm.confidence > best.confidence)
        {
            best = pm;
            np_sv_trace(cfg,
                        target_idx,
                        res->port,
                        "nmap regex matched service=%s method=%s",
                        best.service,
                        best.method);
        }
    }

    np_sv_candidate_t cand;
    memset(&cand, 0, sizeof(cand));

    memset(&cand, 0, sizeof(cand));
    if (np_sv_probe_ssh(fd, &cand) && cand.confidence > best.confidence)
        best = cand;

    if (cfg->version_intensity >= 2)
    {
        if (best.confidence < 95 || cfg->version_intensity >= 9)
        {
            np_sv_close_fd(&fd);
            if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) == 0)
            {
                memset(&cand, 0, sizeof(cand));
                if (np_sv_probe_http(fd, &cand) && cand.confidence > best.confidence)
                    best = cand;
            }
        }

        if (best.confidence < 95 || cfg->version_intensity >= 9)
        {
            np_sv_close_fd(&fd);
            if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) == 0)
            {
                memset(&cand, 0, sizeof(cand));
                if (np_sv_probe_ftp(fd, &cand) && cand.confidence > best.confidence)
                    best = cand;
            }
        }

        if (best.confidence < 95 || cfg->version_intensity >= 9)
        {
            np_sv_close_fd(&fd);
            if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) == 0)
            {
                memset(&cand, 0, sizeof(cand));
                if (np_sv_probe_smtp(fd, &cand) && cand.confidence > best.confidence)
                    best = cand;
            }
        }

        if (best.confidence < 95 || cfg->version_intensity >= 9)
        {
            np_sv_close_fd(&fd);
            if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) == 0)
            {
                memset(&cand, 0, sizeof(cand));
                if (np_sv_probe_pop3(fd, &cand) && cand.confidence > best.confidence)
                    best = cand;
            }
        }

        if (best.confidence < 95 || cfg->version_intensity >= 9)
        {
            np_sv_close_fd(&fd);
            if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) == 0)
            {
                memset(&cand, 0, sizeof(cand));
                if (np_sv_probe_imap(fd, &cand) && cand.confidence > best.confidence)
                    best = cand;
            }
        }
    }

    if (cfg->version_intensity >= 4 && (best.confidence < 95 || cfg->version_intensity >= 9))
    {
        np_sv_close_fd(&fd);
        if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) == 0)
        {
            memset(&cand, 0, sizeof(cand));
            if (np_sv_probe_redis(fd, &cand) && cand.confidence > best.confidence)
                best = cand;
        }
    }

    if (cfg->version_intensity >= 5 && (best.confidence < 95 || cfg->version_intensity >= 9))
    {
        np_sv_close_fd(&fd);
        if (np_sv_connect_with_timeout(target, res->port, cfg->timeout_ms, &fd) == 0)
        {
            memset(&cand, 0, sizeof(cand));
            if (np_sv_probe_mysql(fd, &cand) && cand.confidence > best.confidence)
                best = cand;
        }
    }

    np_sv_close_fd(&fd);

    if (best.matched)
    {
        np_sv_strlcpy(res->service, sizeof(res->service), best.service);
        np_sv_strlcpy(res->version, sizeof(res->version), best.version);
        np_sv_strlcpy(res->service_method, sizeof(res->service_method), best.method);
        np_sv_trace(cfg, target_idx, res->port,
                    "matched service=%s method=%s",
                    res->service,
                    res->service_method);
    }
}

static void np_sv_task(void *arg)
{
    np_sv_task_arg_t *task = (np_sv_task_arg_t *)arg;
    if (!task || !task->cfg)
    {
        free(task);
        return;
    }

    if (task->target_idx >= task->cfg->target_count)
    {
        free(task);
        return;
    }

    np_target_t *target = &task->cfg->targets[task->target_idx];
    if (task->port_idx >= target->port_count)
    {
        free(task);
        return;
    }

    np_port_result_t *res = &target->results[task->port_idx];
    np_sv_probe_port(task->cfg, task->target_idx, target, res);

    free(task);
}

np_status_t np_service_version_run(np_config_t *cfg)
{
    if (!cfg)
        return NP_ERR_ARGS;

    if (!cfg->service_version_detect)
        return NP_OK;

    uint32_t jobs = 0;
    for (uint32_t t = 0; t < cfg->target_count; t++)
    {
        np_target_t *target = &cfg->targets[t];
        for (uint32_t p = 0; p < target->port_count; p++)
        {
            if (np_sv_state_probe_eligible(target->results[p].state))
                jobs++;
        }
    }

    if (jobs == 0)
        return NP_OK;

    uint32_t threads = cfg->threads ? cfg->threads : NP_DEFAULT_THREADS;
    if (threads > 64)
        threads = 64;

    np_pool_t *pool = np_pool_create(threads, jobs);
    if (!pool)
        return NP_ERR_MEMORY;

    for (uint32_t t = 0; t < cfg->target_count; t++)
    {
        np_target_t *target = &cfg->targets[t];
        for (uint32_t p = 0; p < target->port_count; p++)
        {
            if (!np_sv_state_probe_eligible(target->results[p].state))
                continue;

            np_sv_task_arg_t *task = calloc(1, sizeof(*task));
            if (!task)
            {
                np_pool_destroy(pool, true);
                return NP_ERR_MEMORY;
            }

            task->cfg = cfg;
            task->target_idx = t;
            task->port_idx = p;

            if (np_pool_submit(pool, np_sv_task, task) != 0)
            {
                free(task);
                np_pool_destroy(pool, true);
                return NP_ERR_SYSTEM;
            }
        }
    }

    np_pool_wait(pool);
    np_pool_destroy(pool, true);
    return NP_OK;
}

np_status_t np_service_version_run_target(np_config_t *cfg, uint32_t target_idx)
{
    if (!cfg)
        return NP_ERR_ARGS;

    if (!cfg->service_version_detect)
        return NP_OK;

    if (target_idx >= cfg->target_count)
        return NP_ERR_ARGS;

    np_target_t *target = &cfg->targets[target_idx];
    uint32_t jobs = 0;
    for (uint32_t p = 0; p < target->port_count; p++)
    {
        if (np_sv_state_probe_eligible(target->results[p].state))
            jobs++;
    }

    if (jobs == 0)
        return NP_OK;

    uint32_t threads = cfg->threads ? cfg->threads : NP_DEFAULT_THREADS;
    if (threads > 64)
        threads = 64;

    np_pool_t *pool = np_pool_create(threads, jobs);
    if (!pool)
        return NP_ERR_MEMORY;

    for (uint32_t p = 0; p < target->port_count; p++)
    {
        if (!np_sv_state_probe_eligible(target->results[p].state))
            continue;

        np_sv_task_arg_t *task = calloc(1, sizeof(*task));
        if (!task)
        {
            np_pool_destroy(pool, true);
            return NP_ERR_MEMORY;
        }

        task->cfg = cfg;
        task->target_idx = target_idx;
        task->port_idx = p;

        if (np_pool_submit(pool, np_sv_task, task) != 0)
        {
            free(task);
            np_pool_destroy(pool, true);
            return NP_ERR_SYSTEM;
        }
    }

    np_pool_wait(pool);
    np_pool_destroy(pool, true);
    return NP_OK;
}
