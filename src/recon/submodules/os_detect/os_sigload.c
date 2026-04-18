#include "os_sigload.h"
#include "sig_loader.h"
#include "core/error.h"
#include "recon/submodules/os_detect/os_detect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ==================================================== */
/* Internal helpers                                     */
/* ==================================================== */

static char *dup_string(np_os_sigdb_t *db, const char *s)
{
    if (!s)
        return NULL;

    char *d = strdup(s);
    if (!d)
        return NULL;

    if (db->string_count >= db->string_capacity)
    {
        uint32_t newcap = db->string_capacity ? db->string_capacity * 2 : 64;
        char **tmp = realloc(db->strings, newcap * sizeof(char *));
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

static int ensure_fp_capacity(np_os_sigdb_t *db)
{
    if (db->fp_count < db->fp_capacity)
        return 0;

    uint32_t newcap = db->fp_capacity ? db->fp_capacity * 2 : 64;
    np_os_fp_sig_t *tmp =
        realloc(db->fp_sigs, newcap * sizeof(np_os_fp_sig_t));
    if (!tmp)
        return -1;

    db->fp_sigs = tmp;
    db->fp_capacity = newcap;
    return 0;
}

static int ensure_banner_capacity(np_os_sigdb_t *db)
{
    if (db->banner_count < db->banner_capacity)
        return 0;

    uint32_t newcap = db->banner_capacity ? db->banner_capacity * 2 : 64;
    np_os_banner_sig_t *tmp =
        realloc(db->banner_sigs, newcap * sizeof(np_os_banner_sig_t));
    if (!tmp)
        return -1;

    db->banner_sigs = tmp;
    db->banner_capacity = newcap;
    return 0;
}

/* ==================================================== */
/* Public API                                           */
/* ==================================================== */

void np_sigdb_init(np_os_sigdb_t *db)
{
    if (!db)
        return;
    memset(db, 0, sizeof(*db));
}

void np_sigdb_free(np_os_sigdb_t *db)
{
    if (!db)
        return;

    for (uint32_t i = 0; i < db->string_count; i++)
        free(db->strings[i]);

    free(db->strings);
    free(db->fp_sigs);
    free(db->banner_sigs);

    memset(db, 0, sizeof(*db));
}

/* ==================================================== */
/* Signature DB loader                                  */
/* ==================================================== */

int np_sigdb_load(np_os_sigdb_t *db, const char *path)
{
    int block_rc = np_sigloader_load_blocks(db, path);
    if (block_rc > 0)
    {
        db->loaded = true;
        return 0;
    }

    FILE *f = fopen(path, "r");
    if (!f)
    {
        np_error(NP_ERR_RUNTIME, "sigdb: cannot open %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    char line[1024];

    while (fgets(line, sizeof(line), f))
    {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char *tok = strtok(line, "|\n");
        if (!tok)
            continue;

        /* ---------------- Fingerprints ---------------- */

        if (strcmp(tok, "FP") == 0)
        {
            if (ensure_fp_capacity(db) < 0)
                break;

            np_os_fp_sig_t *sig = &db->fp_sigs[db->fp_count];
            memset(sig, 0, sizeof(*sig));

            char *name   = strtok(NULL, "|\n");
            char *family = strtok(NULL, "|\n");
            char *ttl    = strtok(NULL, "|\n");
            char *window = strtok(NULL, "|\n");
            char *df     = strtok(NULL, "|\n");
            char *mss    = strtok(NULL, "|\n");
            char *sack   = strtok(NULL, "|\n");
            char *ts     = strtok(NULL, "|\n");
            char *ws     = strtok(NULL, "|\n");
            char *weight = strtok(NULL, "|\n");

            if (!name || !family)
                continue;

            sig->os_name   = dup_string(db, name);
            sig->os_family = dup_string(db, family);

            sig->ttl            = ttl    ? atoi(ttl)    : 0;
            sig->window_size    = window ? atoi(window) : 0;
            sig->df_bit         = df     ? atoi(df)     : -1;
            sig->mss            = mss    ? atoi(mss)    : 0;
            sig->sack_permitted = sack   ? atoi(sack)   : -1;
            sig->timestamp      = ts     ? atoi(ts)     : -1;
            sig->window_scale   = ws     ? atoi(ws)     : -1;
            sig->weight         = weight ? atoi(weight) : 100;

            db->fp_count++;
        }

        /* ---------------- Banners --------------------- */

        else if (strcmp(tok, "BN") == 0)
        {
            if (ensure_banner_capacity(db) < 0)
                break;

            np_os_banner_sig_t *sig =
                &db->banner_sigs[db->banner_count];
            memset(sig, 0, sizeof(*sig));

            char *pattern = strtok(NULL, "|\n");
            char *os_name = strtok(NULL, "|\n");
            char *family  = strtok(NULL, "|\n");
            char *service = strtok(NULL, "|\n");
            char *conf    = strtok(NULL, "|\n");

            if (!pattern || !os_name)
                continue;

            sig->pattern    = dup_string(db, pattern);
            sig->os_name    = dup_string(db, os_name);
            sig->os_family  = dup_string(db, family ? family : "");
            sig->service    = dup_string(db, service ? service : "");
            sig->confidence = conf ? atoi(conf) : 50;

            db->banner_count++;
        }
    }

    fclose(f);
    db->loaded = true;
    return 0;
}

/* ==================================================== */
/* Fingerprint merge logic (FIXED)                      */
/* ==================================================== */

static int fp_probes_match(const np_os_fp_sig_t *a,
                           const np_os_fp_sig_t *b)
{
    return (a->ttl            == b->ttl &&
            a->window_size    == b->window_size &&
            a->df_bit         == b->df_bit &&
            a->mss            == b->mss &&
            a->sack_permitted == b->sack_permitted &&
            a->timestamp      == b->timestamp &&
            a->window_scale   == b->window_scale);
}

/*
 * IMPORTANT:
 * Do NOT merge Apple <-> BSD fingerprints.
 * They share probes but represent different OS families.
 */
static int family_compatible(const char *a, const char *b)
{
    if (!a || !b)
        return 0;

    if (strstr(a, "Apple") || strstr(b, "Apple"))
        return strcmp(a, b) == 0;

    return strcmp(a, b) == 0;
}

int np_sigdb_merge_builtin(np_os_sigdb_t *db)
{
    uint32_t count;
    const np_os_fp_sig_t *builtin =
        np_os_fp_signatures(&count);

    for (uint32_t i = 0; i < count; i++)
    {
        int merged = 0;

        for (uint32_t j = 0; j < db->fp_count; j++)
        {
            if (fp_probes_match(&db->fp_sigs[j], &builtin[i]) &&
                family_compatible(db->fp_sigs[j].os_family,
                                  builtin[i].os_family))
            {
                merged = 1;
                break;
            }
        }

        if (!merged)
        {
            if (ensure_fp_capacity(db) < 0)
                return -1;

            np_os_fp_sig_t *dst =
                &db->fp_sigs[db->fp_count++];

            *dst = builtin[i];
            dst->os_name   = dup_string(db, builtin[i].os_name);
            dst->os_family = dup_string(db, builtin[i].os_family);
        }
    }

    /* ----------- Banners ----------- */

    const np_os_banner_sig_t *bb =
        np_os_banner_signatures(&count);

    for (uint32_t i = 0; i < count; i++)
    {
        int found = 0;

        for (uint32_t j = 0; j < db->banner_count; j++)
        {
            if (strcmp(db->banner_sigs[j].pattern,
                       bb[i].pattern) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found)
        {
            if (ensure_banner_capacity(db) < 0)
                return -1;

            np_os_banner_sig_t *dst =
                &db->banner_sigs[db->banner_count++];

            *dst = bb[i];
            dst->pattern   = dup_string(db, bb[i].pattern);
            dst->os_name   = dup_string(db, bb[i].os_name);
            dst->os_family = dup_string(db, bb[i].os_family);
            dst->service   = dup_string(db, bb[i].service);
        }
    }

    return 0;
}

/* ==================================================== */
/* Banner matcher (NULL‑safe)                           */
/* ==================================================== */

const char *np_sigdb_match_banner(
        const np_os_sigdb_t *db,
        const np_os_banner_t *banner,
        double *out_confidence)
{
    if (!db || !banner || !banner->banner)
        return NULL;

    for (uint32_t i = 0; i < db->banner_count; i++)
    {
        const np_os_banner_sig_t *sig =
            &db->banner_sigs[i];

        if (!sig->pattern || !sig->os_name)
            continue;

        if (strstr(banner->banner, sig->pattern))
        {
            if (out_confidence)
                *out_confidence = sig->confidence / 100.0;
            return sig->os_name;
        }
    }

    return NULL;
}

/* ---------------------------------------------------- */
/* Default DB search                                    */
/* ---------------------------------------------------- */

char *np_sigdb_default_path(void)
{
    const char *env = getenv("NETPEEK_SIGDB");
    if (env)
        return strdup(env);

    const char *paths[] =
    {
        "./data/os-signatures.db",
        "./os-signatures.db",
        "./netpeek-os.db",
        "/usr/local/share/netpeek/os.db",
        "/etc/netpeek/os.db"
    };

    for (unsigned i = 0;
         i < sizeof(paths) / sizeof(paths[0]);
         i++)
    {
        FILE *f = fopen(paths[i], "r");
        if (f)
        {
            fclose(f);
            return strdup(paths[i]);
        }
    }

    return NULL;
}

/* ==================================================== */
/* Signature count query                                */
/* ==================================================== */

int np_sigdb_count(const np_os_sigdb_t *db)
{
    if (!db)
        return 0;

    return (int)(db->fp_count + db->banner_count);
}
