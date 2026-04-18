#define PCRE2_CODE_UNIT_WIDTH 8

#include "recon/submodules/scanner/service_detect.h"

#include <pcre2.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NP_SD_MAX_PROBES 256
#define NP_SD_MAX_MATCHES 512

typedef struct
{
    bool is_soft;
    int probe_idx;
    char service[32];
    char pattern[256];
    uint32_t options;
    pcre2_code *re;
} np_sd_match_t;

typedef struct
{
    char name[32];
    bool is_null;
    int rarity;
    uint16_t ports[64];
    int port_count;
    char payload[512];
} np_sd_probe_t;

typedef struct
{
    np_sd_probe_t probes[NP_SD_MAX_PROBES];
    int probe_count;
    np_sd_match_t matches[NP_SD_MAX_MATCHES];
    int match_count;
    bool loaded;
} np_sd_db_t;

static np_sd_db_t g_db;

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

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static void decode_escapes(char *s)
{
    char *r = s;
    char *w = s;
    while (*r)
    {
        if (*r == '\\' && r[1])
        {
            r++;
            switch (*r)
            {
            case 'r': *w++ = '\r'; break;
            case 'n': *w++ = '\n'; break;
            case 't': *w++ = '\t'; break;
            default: *w++ = *r; break;
            }
            r++;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static bool probe_has_port(const np_sd_probe_t *p, uint16_t port)
{
    if (!p || p->port_count == 0)
        return true;
    for (int i = 0; i < p->port_count; i++)
        if (p->ports[i] == port)
            return true;
    return false;
}

static int parse_ports(const char *s, uint16_t *out, int cap)
{
    int n = 0;
    char copy[256];
    copy_capped(copy, sizeof(copy), s);
    for (char *tok = strtok(copy, ","); tok && n < cap; tok = strtok(NULL, ","))
    {
        tok = trim(tok);
        long v = strtol(tok, NULL, 10);
        if (v > 0 && v <= 65535)
            out[n++] = (uint16_t)v;
    }
    return n;
}

static int find_probe_index(const char *name)
{
    for (int i = 0; i < g_db.probe_count; i++)
        if (strcmp(g_db.probes[i].name, name) == 0)
            return i;
    return -1;
}

static uint32_t flags_to_opts(const char *flags)
{
    uint32_t opts = 0;
    if (!flags) return opts;
    for (const char *p = flags; *p; p++)
    {
        if (*p == 'i') opts |= PCRE2_CASELESS;
        if (*p == 's') opts |= PCRE2_DOTALL;
        if (*p == 'm') opts |= PCRE2_MULTILINE;
    }
    return opts;
}

static bool load_db(void)
{
    if (g_db.loaded)
        return true;

    FILE *fp = fopen("data/service-probes.db", "r");
    if (!fp)
        return false;

    char line[1024];
    int current = -1;

    while (fgets(line, sizeof(line), fp))
    {
        char *p = trim(line);
        if (*p == '\0' || *p == '#')
            continue;

        if (strncmp(p, "Probe ", 6) == 0)
        {
            if (g_db.probe_count >= NP_SD_MAX_PROBES)
                break;

            np_sd_probe_t *pr = &g_db.probes[g_db.probe_count++];
            memset(pr, 0, sizeof(*pr));

            char proto[16], name[32], payload[512];
            memset(proto, 0, sizeof(proto));
            memset(name, 0, sizeof(name));
            memset(payload, 0, sizeof(payload));

            if (sscanf(p, "Probe %15s %31s q|%511[^|]|", proto, name, payload) >= 2)
            {
                copy_capped(pr->name, sizeof(pr->name), name);
                copy_capped(pr->payload, sizeof(pr->payload), payload);
                decode_escapes(pr->payload);
                pr->is_null = (strcmp(name, "NULL") == 0) || pr->payload[0] == '\0';
                pr->rarity = 1;
            }

            current = g_db.probe_count - 1;
            continue;
        }

        if (current >= 0 && strncmp(p, "ports ", 6) == 0)
        {
            np_sd_probe_t *pr = &g_db.probes[current];
            pr->port_count = parse_ports(p + 6, pr->ports, (int)(sizeof(pr->ports) / sizeof(pr->ports[0])));
            continue;
        }

        if (current >= 0 && strncmp(p, "rarity ", 7) == 0)
        {
            long v = strtol(p + 7, NULL, 10);
            if (v >= 0 && v <= 9)
                g_db.probes[current].rarity = (int)v;
            continue;
        }

        bool soft = false;
        if (strncmp(p, "softmatch ", 10) == 0)
            soft = true;
        else if (strncmp(p, "match ", 6) != 0)
            continue;

        if (g_db.match_count >= NP_SD_MAX_MATCHES)
            break;

        char *cur = p + (soft ? 10 : 6);
        char *sp = strchr(cur, ' ');
        if (!sp)
            continue;
        *sp = '\0';

        np_sd_match_t *m = &g_db.matches[g_db.match_count++];
        memset(m, 0, sizeof(*m));
        m->is_soft = soft;
        copy_capped(m->service, sizeof(m->service), cur);

        char *mstart = strstr(sp + 1, "m|");
        if (!mstart)
            continue;
        mstart += 2;
        char *mend = strchr(mstart, '|');
        if (!mend)
            continue;
        *mend = '\0';
        copy_capped(m->pattern, sizeof(m->pattern), mstart);

        char flags[16] = {0};
        sscanf(mend + 1, "%15s", flags);
        m->options = flags_to_opts(flags);
        m->probe_idx = current;

        int err = 0;
        PCRE2_SIZE off = 0;
        m->re = pcre2_compile((PCRE2_SPTR)m->pattern,
                              PCRE2_ZERO_TERMINATED,
                              m->options,
                              &err,
                              &off,
                              NULL);
    }

    fclose(fp);
    g_db.loaded = true;
    return true;
}

static int connect_target(const np_target_t *target, uint16_t port, uint32_t timeout_ms)
{
    int fd = socket(target->is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    memset(&ss, 0, sizeof(ss));

    if (target->is_ipv6)
    {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        *s6 = target->addr6;
        s6->sin6_port = htons(port);
        slen = sizeof(*s6);
    }
    else
    {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        *s4 = target->addr4;
        s4->sin_port = htons(port);
        slen = sizeof(*s4);
    }

    int flags = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    if (connect(fd, (struct sockaddr *)&ss, slen) == 0)
        return fd;

    if (errno != EINPROGRESS)
    {
        close(fd);
        return -1;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0)
    {
        close(fd);
        return -1;
    }

    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

static bool should_probe(const np_sd_probe_t *probe, uint16_t port, uint8_t intensity)
{
    if (!probe)
        return false;
    if (probe->rarity > intensity)
        return false;
    return probe_has_port(probe, port);
}

static void maybe_mark_tls(np_port_result_t *r)
{
    if (!r)
        return;
    if (strcasecmp(r->service, "https") == 0 ||
        strcasecmp(r->service, "ssl") == 0 ||
        strcasecmp(r->service, "tls") == 0)
        r->tls_detected = true;
}

np_status_t np_service_detect_run(np_config_t *cfg)
{
    if (!cfg || !cfg->service_version_detect)
        return NP_OK;

    if (!load_db())
        return NP_OK;

    for (uint32_t ti = 0; ti < cfg->target_count; ti++)
    {
        np_target_t *t = &cfg->targets[ti];
        for (uint32_t pi = 0; pi < t->port_count; pi++)
        {
            np_port_result_t *r = &t->results[pi];
            if (r->state != NP_PORT_OPEN && r->state != NP_PORT_OPEN_FILTERED)
                continue;

            int fd = connect_target(t, r->port, cfg->timeout_ms);
            if (fd < 0)
                continue;

            char recvbuf[4096];
            recvbuf[0] = '\0';

            for (int pr = 0; pr < g_db.probe_count; pr++)
            {
                np_sd_probe_t *probe = &g_db.probes[pr];
                if (!should_probe(probe, r->port, cfg->version_intensity))
                    continue;

                if (!probe->is_null && probe->payload[0])
                {
                    (void)send(fd, probe->payload, strlen(probe->payload), 0);
                }

                struct pollfd pfd = {.fd = fd, .events = POLLIN};
                int rr = poll(&pfd, 1, (int)cfg->timeout_ms);
                if (rr <= 0)
                    continue;

                ssize_t n = recv(fd, recvbuf, sizeof(recvbuf) - 1, 0);
                if (n <= 0)
                    continue;
                recvbuf[n] = '\0';

                for (int mi = 0; mi < g_db.match_count; mi++)
                {
                    np_sd_match_t *m = &g_db.matches[mi];
                    if (!m->re)
                        continue;
                    if (m->probe_idx >= 0 && m->probe_idx != pr)
                        continue;

                    pcre2_match_data *md = pcre2_match_data_create(8, NULL);
                    if (!md)
                        continue;

                    int rc = pcre2_match(m->re,
                                         (PCRE2_SPTR)recvbuf,
                                         (PCRE2_SIZE)strlen(recvbuf),
                                         0,
                                         0,
                                         md,
                                         NULL);
                    if (rc >= 0)
                    {
                        copy_capped(r->service, sizeof(r->service), m->service);
                        copy_capped(r->product, sizeof(r->product), m->service);
                        copy_capped(r->service_method, sizeof(r->service_method),
                                    m->is_soft ? "db-softmatch" : "db-match");
                        copy_capped(r->probe_name, sizeof(r->probe_name), probe->name);
                        r->service_confidence = m->is_soft ? 70 : 95;

                        if (rc > 1)
                        {
                            PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
                            size_t s = (size_t)ov[2];
                            size_t e = (size_t)ov[3];
                            if (e > s && e - s < sizeof(r->version))
                            {
                                memcpy(r->version, recvbuf + s, e - s);
                                r->version[e - s] = '\0';
                            }
                        }

                        pcre2_match_data_free(md);
                        maybe_mark_tls(r);
                        goto next_port;
                    }

                    pcre2_match_data_free(md);
                }
            }

next_port:
            close(fd);
        }
    }

    return NP_OK;
}

np_status_t np_service_detect_run_target(np_config_t *cfg, uint32_t target_idx)
{
    if (!cfg || !cfg->service_version_detect)
        return NP_OK;

    if (target_idx >= cfg->target_count)
        return NP_ERR_ARGS;

    if (!load_db())
        return NP_OK;

    np_target_t *t = &cfg->targets[target_idx];
    for (uint32_t pi = 0; pi < t->port_count; pi++)
    {
        np_port_result_t *r = &t->results[pi];
        if (r->state != NP_PORT_OPEN && r->state != NP_PORT_OPEN_FILTERED)
            continue;

        int fd = connect_target(t, r->port, cfg->timeout_ms);
        if (fd < 0)
            continue;

        char recvbuf[4096];
        recvbuf[0] = '\0';

        for (int pr = 0; pr < g_db.probe_count; pr++)
        {
            np_sd_probe_t *probe = &g_db.probes[pr];
            if (!should_probe(probe, r->port, cfg->version_intensity))
                continue;

            if (!probe->is_null && probe->payload[0])
            {
                (void)send(fd, probe->payload, strlen(probe->payload), 0);
            }

            struct pollfd pfd = {.fd = fd, .events = POLLIN};
            int rr = poll(&pfd, 1, (int)cfg->timeout_ms);
            if (rr <= 0)
                continue;

            ssize_t n = recv(fd, recvbuf, sizeof(recvbuf) - 1, 0);
            if (n <= 0)
                continue;
            recvbuf[n] = '\0';

            for (int mi = 0; mi < g_db.match_count; mi++)
            {
                np_sd_match_t *m = &g_db.matches[mi];
                if (!m->re)
                    continue;
                if (m->probe_idx >= 0 && m->probe_idx != pr)
                    continue;

                pcre2_match_data *md = pcre2_match_data_create(8, NULL);
                if (!md)
                    continue;

                int rc = pcre2_match(m->re,
                                     (PCRE2_SPTR)recvbuf,
                                     (PCRE2_SIZE)strlen(recvbuf),
                                     0,
                                     0,
                                     md,
                                     NULL);
                if (rc >= 0)
                {
                    copy_capped(r->service, sizeof(r->service), m->service);
                    copy_capped(r->product, sizeof(r->product), m->service);
                    copy_capped(r->service_method, sizeof(r->service_method),
                                m->is_soft ? "db-softmatch" : "db-match");
                    copy_capped(r->probe_name, sizeof(r->probe_name), probe->name);
                    r->service_confidence = m->is_soft ? 70 : 95;

                    if (rc > 1)
                    {
                        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
                        size_t s = (size_t)ov[2];
                        size_t e = (size_t)ov[3];
                        if (e > s && e - s < sizeof(r->version))
                        {
                            memcpy(r->version, recvbuf + s, e - s);
                            r->version[e - s] = '\0';
                        }
                    }

                    pcre2_match_data_free(md);
                    maybe_mark_tls(r);
                    goto next_port;
                }

                pcre2_match_data_free(md);
            }
        }

next_port:
        close(fd);
    }

    return NP_OK;
}
