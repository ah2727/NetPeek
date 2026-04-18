#include "sig_loader.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ensure_fp_capacity(np_os_sigdb_t *db)
{
    if (db->fp_count < db->fp_capacity)
        return 0;
    uint32_t newcap = db->fp_capacity ? db->fp_capacity * 2 : 64;
    np_os_fp_sig_t *tmp = realloc(db->fp_sigs, newcap * sizeof(*tmp));
    if (!tmp)
        return -1;
    db->fp_sigs = tmp;
    db->fp_capacity = newcap;
    return 0;
}

static char *pool_dup(np_os_sigdb_t *db, const char *s)
{
    if (!s)
        return NULL;
    char *d = strdup(s);
    if (!d)
        return NULL;
    if (db->string_count >= db->string_capacity)
    {
        uint32_t newcap = db->string_capacity ? db->string_capacity * 2 : 128;
        char **tmp = realloc(db->strings, newcap * sizeof(*tmp));
        if (!tmp)
        {
            free(d);
            return NULL;
        }
        db->strings = tmp;
        db->string_capacity = newcap;
    }
    db->strings[db->string_count++] = d;
    return d;
}

static void trim(char *s)
{
    if (!s)
        return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || isspace((unsigned char)s[n - 1])))
        s[--n] = '\0';
    char *p = s;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
}

static int parse_hex_or_dec(const char *s)
{
    if (!s || !*s)
        return 0;
    if (strspn(s, "0123456789") == strlen(s))
        return atoi(s);
    return (int)strtol(s, NULL, 16);
}

static void parse_keyvals(const char *line, np_os_fp_sig_t *sig)
{
    const char *open = strchr(line, '(');
    const char *close = strrchr(line, ')');
    if (!open || !close || close <= open)
        return;

    char buf[1024];
    size_t len = (size_t)(close - open - 1);
    if (len >= sizeof(buf))
        len = sizeof(buf) - 1;
    memcpy(buf, open + 1, len);
    buf[len] = '\0';

    for (char *tok = strtok(buf, "%"); tok; tok = strtok(NULL, "%"))
    {
        char *eq = strchr(tok, '=');
        if (!eq)
            continue;
        *eq = '\0';
        const char *k = tok;
        const char *v = eq + 1;

        if (strcmp(k, "T") == 0 || strcmp(k, "TG") == 0)
            sig->ttl = parse_hex_or_dec(v);
        else if (strcmp(k, "W") == 0 || strcmp(k, "W1") == 0)
            sig->window_size = parse_hex_or_dec(v);
        else if (strcmp(k, "DF") == 0)
            sig->df_bit = (v[0] == 'Y') ? 1 : 0;
        else if (strcmp(k, "MSS") == 0)
            sig->mss = parse_hex_or_dec(v);
        else if (strcmp(k, "O") == 0 || strcmp(k, "O1") == 0)
        {
            int n = 0;
            for (const char *p = v; *p && n < (int)(sizeof(sig->tcp_options) / sizeof(sig->tcp_options[0])); p++)
            {
                if (*p == 'M') sig->tcp_options[n++] = 2;
                else if (*p == 'N') sig->tcp_options[n++] = 1;
                else if (*p == 'T') sig->tcp_options[n++] = 8;
                else if (*p == 'W') sig->tcp_options[n++] = 3;
                else if (*p == 'S') sig->tcp_options[n++] = 4;
            }
            sig->tcp_opt_count = n;
        }
    }
}

int np_sigloader_load_blocks(np_os_sigdb_t *db, const char *path)
{
    if (!db || !path)
        return -1;

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[2048];
    int parsed = 0;
    bool in_block = false;
    np_os_fp_sig_t cur;
    char cur_name[256] = {0};
    char cur_vendor[128] = {0};
    char cur_family[128] = {0};
    char cur_gen[64] = {0};
    char cur_dev[128] = {0};

    memset(&cur, 0, sizeof(cur));
    cur.weight = 100;
    cur.df_bit = -1;
    cur.sack_permitted = -1;
    cur.timestamp = -1;
    cur.window_scale = -1;

    while (fgets(line, sizeof(line), f))
    {
        trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (strncmp(line, "Fingerprint ", 12) == 0)
        {
            if (in_block && cur_name[0])
            {
                if (ensure_fp_capacity(db) == 0)
                {
                    np_os_fp_sig_t *dst = &db->fp_sigs[db->fp_count++];
                    *dst = cur;
                    dst->os_name = pool_dup(db, cur_name);
                    dst->os_vendor = pool_dup(db, cur_vendor);
                    dst->os_family = pool_dup(db, cur_family);
                    dst->os_gen = pool_dup(db, cur_gen);
                    dst->device_type = pool_dup(db, cur_dev);
                }
                parsed++;
            }

            in_block = true;
            memset(&cur, 0, sizeof(cur));
            memset(cur_name, 0, sizeof(cur_name));
            memset(cur_vendor, 0, sizeof(cur_vendor));
            memset(cur_family, 0, sizeof(cur_family));
            memset(cur_gen, 0, sizeof(cur_gen));
            memset(cur_dev, 0, sizeof(cur_dev));
            cur.weight = 100;
            cur.df_bit = -1;
            cur.sack_permitted = -1;
            cur.timestamp = -1;
            cur.window_scale = -1;
            strncpy(cur_name, line + 12, sizeof(cur_name) - 1);
            continue;
        }

        if (!in_block)
            continue;

        if (strncmp(line, "Class ", 6) == 0)
        {
            char tmp[512];
            strncpy(tmp, line + 6, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';
            char *a = strtok(tmp, "|");
            char *b = strtok(NULL, "|");
            char *c = strtok(NULL, "|");
            char *d = strtok(NULL, "|");
            if (a) { trim(a); strncpy(cur_vendor, a, sizeof(cur_vendor) - 1); }
            if (b) { trim(b); strncpy(cur_family, b, sizeof(cur_family) - 1); }
            if (c) { trim(c); strncpy(cur_gen, c, sizeof(cur_gen) - 1); }
            if (d) { trim(d); strncpy(cur_dev, d, sizeof(cur_dev) - 1); }
            continue;
        }

        if (strncmp(line, "SEQ(", 4) == 0 ||
            strncmp(line, "OPS(", 4) == 0 ||
            strncmp(line, "WIN(", 4) == 0 ||
            strncmp(line, "ECN(", 4) == 0 ||
            strncmp(line, "T", 1) == 0)
        {
            parse_keyvals(line, &cur);
            continue;
        }
    }

    if (in_block && cur_name[0])
    {
        if (ensure_fp_capacity(db) == 0)
        {
            np_os_fp_sig_t *dst = &db->fp_sigs[db->fp_count++];
            *dst = cur;
            dst->os_name = pool_dup(db, cur_name);
            dst->os_vendor = pool_dup(db, cur_vendor);
            dst->os_family = pool_dup(db, cur_family);
            dst->os_gen = pool_dup(db, cur_gen);
            dst->device_type = pool_dup(db, cur_dev);
        }
        parsed++;
    }

    fclose(f);
    return parsed > 0 ? 1 : 0;
}

