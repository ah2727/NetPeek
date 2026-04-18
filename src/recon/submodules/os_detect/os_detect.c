#include "recon/submodules/os_detect/os_detect.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "os_sigload.h"
#include "os_port_discovery.h" /* Added for port discovery */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>

/* ---------------------------------------------------- */
/* Tunables (future-safe)                               */
/* ---------------------------------------------------- */

#define MAX_FAMILIES            32
#define MIN_MATCH_CONFIDENCE    20
#define MIN_FAMILY_HITS         2


/* ---------------------------------------------------- */
/* Helper: Aggregate unique strings (e.g., CPEs, types) */
/* ---------------------------------------------------- */

static void aggregate_unique(char *dest, const char *src, size_t dest_sz) {
    if (!src || strlen(src) == 0) return;
    if (strstr(dest, src)) return; /* Simple deduplication */

    if (strlen(dest) > 0) {
        strncat(dest, "|", dest_sz - strlen(dest) - 1);
    }
    strncat(dest, src, dest_sz - strlen(dest) - 1);
}

/* ---------------------------------------------------- */
/* Family-first OS selection (authoritative)            */
/* ---------------------------------------------------- */

static void np_select_family_first(np_os_result_t *res)
{
    if (!res || res->match_count == 0)
        return;

    /* ---- Penalise synthetic guesses if real matches exist ---- */

    bool has_real_match = false;

    for (uint32_t i = 0; i < res->match_count; i++)
    {
        if (!res->matches[i].synthetic &&
            res->matches[i].confidence >= MIN_MATCH_CONFIDENCE)
        {
            has_real_match = true;
            break;
        }
    }

    if (has_real_match)
    {
        for (uint32_t i = 0; i < res->match_count; i++)
        {
            if (res->matches[i].synthetic)
                res->matches[i].confidence /= 3;
        }
    }

    /* ---- Aggregate scores by OS family ---- */

    np_family_score_t fams[MAX_FAMILIES];
    uint32_t fam_count = 0;

    memset(fams, 0, sizeof(fams));

    for (uint32_t i = 0; i < res->match_count; i++)
    {
        np_os_match_t *m = &res->matches[i];

        if (m->confidence < MIN_MATCH_CONFIDENCE)
            continue;

        uint32_t f;
        for (f = 0; f < fam_count; f++)
        {
            if (strcmp(fams[f].family, m->os_family) == 0)
                break;
        }

        if (f == fam_count)
        {
            if (fam_count >= MAX_FAMILIES)
                continue;

            strncpy(fams[fam_count].family,
                    m->os_family,
                    sizeof(fams[fam_count].family) - 1);

            fams[fam_count].family[sizeof(fams[fam_count].family) - 1] = '\0';
            fam_count++;
        }

        fams[f].total_score += m->confidence;
        fams[f].hit_count++;
    }

    /* ---- Select best family (normalized score) ---- */

    int best_fam_idx = -1;
    uint32_t best_norm_score = 0;

    for (uint32_t f = 0; f < fam_count; f++)
    {
        if (fams[f].hit_count < MIN_FAMILY_HITS)
            continue;

        uint32_t norm_score =
            fams[f].total_score / fams[f].hit_count;

        if (norm_score > best_norm_score)
        {
            best_norm_score = norm_score;
            best_fam_idx = (int)f;
        }
    }

    if (best_fam_idx < 0)
        return;

    const char *winner_family = fams[best_fam_idx].family;

    /* ---- Pick best OS inside winning family ---- */

    np_os_match_t *best_match = NULL;

    for (uint32_t i = 0; i < res->match_count; i++)
    {
        np_os_match_t *m = &res->matches[i];

        if (strcmp(m->os_family, winner_family) != 0)
            continue;

        if (!best_match ||
            m->confidence > best_match->confidence)
        {
            best_match = m;
        }
    }

    if (!best_match)
        return;

    strncpy(res->best_family,
            best_match->os_family,
            sizeof(res->best_family) - 1);

    strncpy(res->best_os,
            best_match->os_name,
            sizeof(res->best_os) - 1);

    res->best_family[sizeof(res->best_family) - 1] = '\0';
    res->best_os[sizeof(res->best_os) - 1] = '\0';

    res->best_confidence = best_match->confidence;
}

/* ---------------------------------------------------- */
/* Allocate result array                                */
/* ---------------------------------------------------- */

np_status_t np_os_result_alloc(np_os_config_t *cfg)
{
    if (!cfg || cfg->target_count == 0)
        return NP_STATUS_ERR;

    cfg->results =
        calloc(cfg->target_count, sizeof(np_os_result_t));

    return cfg->results ? NP_STATUS_OK : NP_STATUS_ERR;
}

/* ---------------------------------------------------- */
/* Free results                                         */
/* ---------------------------------------------------- */

void np_os_result_free(np_os_config_t *cfg)
{
    if (!cfg || !cfg->results)
        return;

    free(cfg->results);
    cfg->results = NULL;
}

/* ---------------------------------------------------- */
/* Print results                                        */
/* ---------------------------------------------------- */

void np_os_result_print(const np_os_config_t *cfg)
{
    if (!cfg)
        return;

    for (uint32_t i = 0; i < cfg->target_count; i++)
    {
        const np_os_result_t *r = &cfg->results[i];

        printf("\nOS detection results for Target %u (%s):\n", i + 1, cfg->targets[i].ip);

        if (r->best_confidence == 0)
        {
            printf("  OS details: No exact matches. (Confidence: 0%%)\n");
            continue;
        }

        /* Print Nmap-style output */
        printf("  Device type: %s\n", 
               (strlen(r->aggregated_device_type) > 0) ? r->aggregated_device_type : "general purpose");
        
        printf("  Running: %s\n", r->best_family);
        
        if (strlen(r->aggregated_cpe) > 0) {
            printf("  OS CPE: %s\n", r->aggregated_cpe);
        }

        printf("  OS details: %s (Confidence: %.0f%%)\n", 
               r->best_os, r->best_confidence);

        if (cfg->verbose)
        {
            printf("\n  Matches:\n");

            for (uint32_t m = 0; m < r->match_count; m++)
            {
                const np_os_match_t *match = &r->matches[m];

                printf("   - %s (%u%%)%s%s%s\n",
                       match->os_name,
                       match->confidence,
                       match->from_fingerprint ? " [fp]" : "",
                       match->from_banner ? " [banner]" : "",
                       match->synthetic ? " [guess]" : "");
            }
        }
    }
}

/* ---------------------------------------------------- */
/* Run OS detection                                     */
/* ---------------------------------------------------- */

np_status_t np_os_detect_run(
    np_os_config_t *cfg,
    volatile sig_atomic_t *interrupted)
{
    if (!cfg)
        return NP_STATUS_ERR;

    np_os_sigdb_t db;
    np_sigdb_init(&db);

    char *path = np_sigdb_default_path();
    if (path)
    {
        np_sigdb_load(&db, path);
        free(path);
    }

    np_sigdb_merge_builtin(&db);

    if (np_os_result_alloc(cfg) != NP_STATUS_OK)
        return NP_STATUS_ERR;

    for (uint32_t i = 0; i < cfg->target_count; i++)
    {
        if (interrupted && *interrupted)
            break;

        np_target_t *t = &cfg->targets[i];
        np_os_result_t *res = &cfg->results[i];

        printf("Scanning %s...\n", t->ip);

        /* Determine a valid open port instead of hardcoded 0 */
        uint16_t probe_port = 80; /* Safe default fallback */
        if (np_find_open_port(t->ip, &probe_port) == 0) {
            if (cfg->verbose) {
                printf("Discovered open port %u for OS fingerprinting probes.\n", probe_port);
            }
        } else {
            if (cfg->verbose) {
                printf("No open port discovered. Falling back to port %u. Confidence may be low.\n", probe_port);
            }
        }

        if (np_os_detect_pipeline_run(
                t->ip,
                probe_port,
                &db,
                res) >= 0)
        {
            np_select_family_first(res);
            
            /* Aggregate Device Type and CPE metadata from successful high-confidence matches */
            for (uint32_t m = 0; m < res->match_count; m++) {
                if (res->matches[m].confidence > MIN_MATCH_CONFIDENCE) {
                    aggregate_unique(res->aggregated_device_type, 
                                     res->matches[m].device_type, 
                                     sizeof(res->aggregated_device_type));
                    
                    aggregate_unique(res->aggregated_cpe, 
                                     res->matches[m].cpe, 
                                     sizeof(res->aggregated_cpe));
                }
            }
        }
    }

    np_sigdb_free(&db);
    return NP_STATUS_OK;
}
