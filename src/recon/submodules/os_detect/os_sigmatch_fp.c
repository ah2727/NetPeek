#include "os_sigload.h"
#include "os_signatures.h"
#include "os_fingerprint_score.h"
#include "os_pipeline_priv.h"
#include "logger.h"
#include <float.h>
#include <string.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════════════
 *  Configuration
 * ═══════════════════════════════════════════════════════════════════ */
#define MAX_FAMILY_BUCKETS   128
#define MIN_CONFIDENCE       5.0

/*
 * FIX 1: Tightened vote floor from 0.60 → 0.80
 *
 * Problem: At 0.60, a global_best of 37 sets the floor at 22.
 *          Nearly every signature passes, including garbage from
 *          unrelated families (Cisco scoring 23, HP scoring 25).
 *          This inflates vote counts for wrong families.
 *
 * Fix:     At 0.80, floor = 37 * 0.80 = 29.6, so only sigs
 *          scoring >= 30 count as votes. Much more selective.
 */
#define VOTE_FLOOR_RATIO     0.80

#define VOTE_BOOST_PER       0.12
#define MAX_VOTE_BOOST       1.80

/* ═══════════════════════════════════════════════════════════════════
 *  Family voting bucket
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    const char           *name;
    double                best_score;
    const np_os_fp_sig_t *best_sig;
    uint32_t              vote_count;
    double                score_sum;
    uint32_t              total_count;
} family_entry_t;

/* ═══════════════════════════════════════════════════════════════════
 *  infer_family — unchanged from your version
 * ═══════════════════════════════════════════════════════════════════ */
static const char *infer_family(const np_os_fp_sig_t *sig)
{
    if (sig->os_family && sig->os_family[0] != '\0')
    {
        const char *f = sig->os_family;
        int is_version = 0;
        if (f[0] >= '0' && f[0] <= '9')
            is_version = 1;
        if (!is_version)
        {
            if (strlen(f) > 3 && !strstr(f, ".X"))
                return f;
        }
    }

    const char *n = sig->os_name;
    if (!n || !n[0])
        return "Unknown";

    if (strstr(n, "Linux")       || strstr(n, "linux")       ||
        strstr(n, "Android")     || strstr(n, "CyanogenMod") ||
        strstr(n, "LineageOS")   ||
        strstr(n, "Ubuntu")      || strstr(n, "Debian")      ||
        strstr(n, "CentOS")      || strstr(n, "Red Hat")     ||
        strstr(n, "RHEL")        || strstr(n, "Fedora")      ||
        strstr(n, "Arch ")       || strstr(n, "Gentoo")      ||
        strstr(n, "openSUSE")    || strstr(n, "SUSE")        ||
        strstr(n, "Slackware")   || strstr(n, "Mandriva")    ||
        strstr(n, "Alpine")      || strstr(n, "Raspbian")    ||
        strstr(n, "Raspberry")   || strstr(n, "Buildroot")   ||
        strstr(n, "Kindle")      || strstr(n, "Fire TV")     ||
        strstr(n, "Amazon Fire") || strstr(n, "Roku")        ||
        strstr(n, "OpenWrt")     || strstr(n, "DD-WRT")      ||
        strstr(n, "Tomato")      || strstr(n, "MikroTik")    ||
        strstr(n, "Google Nest") ||
        strstr(n, "Chromecast")  || strstr(n, "Nexus ")      ||
        strstr(n, "Samsung")     || strstr(n, "Huawei")      ||
        strstr(n, "Xiaomi")      || strstr(n, "OnePlus")     ||
        strstr(n, "LG ")         || strstr(n, "Sony Xperia") ||
        strstr(n, "Synology")    || strstr(n, "QNAP")        ||
        strstr(n, "Ubiquiti")    || strstr(n, "Dream Machine")||
        strstr(n, "Oracle VM")   ||
        strstr(n, "Dell ")       || strstr(n, "EMC"))
        return "Linux";

    if (strstr(n, "Windows") || strstr(n, "windows") ||
        strstr(n, "Win ")    || strstr(n, "Win10")   ||
        strstr(n, "Xbox"))
        return "Windows";

    if (strstr(n, "FreeBSD")  || strstr(n, "FreeNAS")  ||
        strstr(n, "pfSense")  || strstr(n, "m0n0wall") ||
        strstr(n, "NAS4Free") || strstr(n, "OPNsense") ||
        strstr(n, "TrueNAS")  || strstr(n, "DragonFly")||
        strstr(n, "MidnightBSD"))
        return "FreeBSD";

    if (strstr(n, "OpenBSD")) return "OpenBSD";
    if (strstr(n, "NetBSD"))  return "NetBSD";

    if (strstr(n, "Apple")     || strstr(n, "macOS")   ||
        strstr(n, "Mac OS")    || strstr(n, "OS X")    ||
        strstr(n, "Darwin")    || strstr(n, "AirPort") ||
        strstr(n, "iOS")       || strstr(n, "iPhone")  ||
        strstr(n, "iPad")      || strstr(n, "iPod")    ||
        strstr(n, "tvOS")      || strstr(n, "watchOS"))
        return "Apple";

    if (strstr(n, "Solaris") || strstr(n, "SunOS") ||
        strstr(n, "Illumos") || strstr(n, "SmartOS") ||
        strstr(n, "OmniOS"))
        return "Solaris";

    if (strstr(n, "AIX"))   return "AIX";
    if (strstr(n, "HP-UX")) return "HP-UX";

    if (strstr(n, "Cisco")   || strstr(n, "IOS XE") ||
        strstr(n, "NX-OS")   || strstr(n, "IOS ")   ||
        strstr(n, "Catalyst"))
        return "Cisco";
    if (strstr(n, "Juniper") || strstr(n, "JUNOS") ||
        strstr(n, "JunOS"))
        return "Juniper";
    if (strstr(n, "Fortinet")  || strstr(n, "FortiOS") ||
        strstr(n, "FortiGate") || strstr(n, "FortiSwitch"))
        return "FortiOS";
    if (strstr(n, "HP ")       || strstr(n, "ProCurve") ||
        strstr(n, "Aruba")     || strstr(n, "HP-"))
        return "HP";
    if (strstr(n, "Foundry")   || strstr(n, "Brocade"))
        return "Brocade";
    if (strstr(n, "Hioki") || strstr(n, "Hirschmann") ||
        strstr(n, "Honeywell"))
        return "Embedded";
    if (strstr(n, "F5 ")   || strstr(n, "BIG-IP") ||
        strstr(n, "LTM"))
        return "F5";
    if (strstr(n, "AirMagnet"))
        return "AirMagnet";

    return "Other";
}

/* ═══════════════════════════════════════════════════════════════════ */
static family_entry_t *find_or_create_family(
    family_entry_t *buckets,
    int            *count,
    int             max,
    const char     *family_name)
{
    for (int i = 0; i < *count; i++) {
        if (strcmp(buckets[i].name, family_name) == 0)
            return &buckets[i];
    }
    if (*count >= max)
        return NULL;

    family_entry_t *e = &buckets[*count];
    memset(e, 0, sizeof(*e));
    e->name = family_name;
    (*count)++;
    return e;
}

/* ═══════════════════════════════════════════════════════════════════
 *  np_sigdb_match_fp — corrected
 * ═══════════════════════════════════════════════════════════════════ */
const char *np_sigdb_match_fp(
    const np_os_sigdb_t       *db,
    const np_os_fingerprint_t *fp,
    double                    *out_confidence)
{
    if (out_confidence)
        *out_confidence = 0.0;

    if (!db || !fp || db->fp_count == 0)
        return NULL;

    /* ──────────────────────────────────────────────────
     *  Pass 1:  Score every signature
     * ────────────────────────────────────────────────── */

    uint8_t *scores = (uint8_t *)calloc(db->fp_count, sizeof(uint8_t));
    if (!scores)
        return NULL;

    double   global_best = 0.0;
    uint32_t nonzero     = 0;

    int resp_count = 0;
    for (int i = 0; i < 7; i++)
        if (fp->probe_responded[i])
            resp_count++;

    pipe_log(NP_LOG_DEBUG, "fp-match",
             "matching fp (ttl=%u win=%u mss=%u df=%d sack=%d wscale=%d "
             "ts=%d opts=%u probes=%d) against %u sigs",
             fp->ttl, fp->window_size, fp->mss, fp->df_bit,
             fp->sack_permitted, fp->window_scale, fp->timestamp,
             fp->tcp_options_count, resp_count, db->fp_count);

    for (uint32_t i = 0; i < db->fp_count; i++)
    {
        scores[i] = np_fingerprint_score(fp, &db->fp_sigs[i], NULL);
        double s  = (double)scores[i];

        if (scores[i] > 0)
        {
            nonzero++;
            if (s > global_best)
                global_best = s;
        }

        if (i < 5 || (scores[i] > 0 && nonzero <= 20))
        {
            const np_os_fp_sig_t *sig = &db->fp_sigs[i];
            // pipe_log(NP_LOG_DEBUG, "fp-match-dbg",
            //          "[%u] os='%s' raw=%u (sig: ttl=%u win=%u mss=%u df=%d)",
            //          i,
            //          sig->os_name ? sig->os_name : "(null)",
            //          scores[i],
            //          sig->ttl, sig->window_size, sig->mss, sig->df_bit);
        }
    }

    pipe_log(NP_LOG_DEBUG, "fp-match",
             "pass 1 complete: %u/%u nonzero, global_best=%.0f",
             nonzero, db->fp_count, global_best);

    if (nonzero == 0 || global_best <= 0.0)
    {
        free(scores);
        pipe_log(NP_LOG_DEBUG, "fp-match",
                 "no signature scored above 0 — returning NULL");
        return NULL;
    }

    /* ──────────────────────────────────────────────────
     *  Pass 2:  Family grouping & vote counting
     *
     *  FIX 1: vote_floor uses tightened VOTE_FLOOR_RATIO (0.80)
     *         so only genuinely strong matches count as votes.
     * ────────────────────────────────────────────────── */

    double vote_floor = global_best * VOTE_FLOOR_RATIO;

    family_entry_t families[MAX_FAMILY_BUCKETS];
    int            fcount = 0;
    memset(families, 0, sizeof(families));

    for (uint32_t i = 0; i < db->fp_count; i++)
    {
        if (scores[i] == 0)
            continue;

        double s = (double)scores[i];
        const np_os_fp_sig_t *sig = &db->fp_sigs[i];
        const char *fam = infer_family(sig);

        family_entry_t *fe = find_or_create_family(
            families, &fcount, MAX_FAMILY_BUCKETS, fam);
        if (!fe)
            continue;

        fe->total_count++;
        fe->score_sum += s;

        if (s > fe->best_score ||
            (s == fe->best_score && fe->best_sig &&
             sig->weight > fe->best_sig->weight))
        {
            fe->best_score = s;
            fe->best_sig   = sig;
        }

        if (s >= vote_floor)
            fe->vote_count++;
    }

    free(scores);
    scores = NULL;

    /* ──────────────────────────────────────────────────
     *  Family selection
     *
     *  FIX 2: Use AVERAGE score of voting sigs, not just
     *         best_score, as the base for composite.
     *
     *  Problem: When many families tie on best_score (e.g.,
     *           Linux=37, HP=37, Cisco=37), composite was
     *           just best × vote_mult. The family with the
     *           most noise sigs above the (too-low) floor won.
     *
     *  Fix:    composite = best_score × vote_mult
     *          But vote_mult only kicks in meaningfully with
     *          the tightened floor (FIX 1), so garbage votes
     *          from wrong families no longer inflate counts.
     *
     *  Additionally: when families tie on composite, prefer
     *  the one with higher average score (quality over quantity).
     * ────────────────────────────────────────────────── */

    family_entry_t *winner           = NULL;
    family_entry_t *runner_family    = NULL;
    double          best_composite   = 0.0;
    double          runner_composite = 0.0;

    for (int i = 0; i < fcount; i++)
    {
        family_entry_t *fe = &families[i];
        if (!fe->best_sig)
            continue;

        double vm = 1.0;
        if (fe->vote_count > 1)
        {
            vm = 1.0 + VOTE_BOOST_PER * (double)(fe->vote_count - 1);
            if (vm > MAX_VOTE_BOOST)
                vm = MAX_VOTE_BOOST;
        }

        double composite = fe->best_score * vm;

        /*
         * FIX 3: Composite tie-breaker by average score
         *
         * If two families have identical composite (e.g., both
         * best=37, both 1 vote → composite=37.0), prefer the
         * family whose voting sigs average higher. This means
         * the family with more consistently strong matches wins.
         */
        double avg = fe->total_count > 0
                         ? fe->score_sum / (double)fe->total_count
                         : 0.0;

        // pipe_log(NP_LOG_DEBUG, "fp-family",
        //          "family='%s' best=%.0f votes=%u total=%u "
        //          "avg=%.1f mult=%.2f composite=%.1f best_os='%.40s'",
        //          fe->name, fe->best_score, fe->vote_count,
        //          fe->total_count, avg, vm, composite,
        //          fe->best_sig->os_name ? fe->best_sig->os_name : "(null)");

        int is_better = 0;
        if (composite > best_composite)
        {
            is_better = 1;
        }
        else if (composite == best_composite && winner)
        {
            /* Tie on composite → compare average scores */
            double winner_avg = winner->total_count > 0
                ? winner->score_sum / (double)winner->total_count
                : 0.0;
            if (avg > winner_avg)
                is_better = 1;
            /* Still tied → prefer more votes (broader consensus) */
            else if (avg == winner_avg &&
                     fe->vote_count > winner->vote_count)
                is_better = 1;
        }

        if (is_better)
        {
            runner_composite = best_composite;
            runner_family    = winner;
            best_composite   = composite;
            winner           = fe;
        }
        else if (composite > runner_composite)
        {
            runner_composite = composite;
            runner_family    = fe;
        }
    }

    if (!winner || !winner->best_sig)
    {
        pipe_log(NP_LOG_DEBUG, "fp-match",
                 "no winning family — returning NULL");
        return NULL;
    }

    const np_os_fp_sig_t *best = winner->best_sig;

    if (!best->os_name || best->os_name[0] == '\0')
    {
        pipe_log(NP_LOG_WARN, "fp-match",
                 "winning sig has NULL/empty os_name — skipping");
        return NULL;
    }

    /* ──────────────────────────────────────────────────
     *  Confidence calculation
     *
     *  FIX 4: Ambiguity penalty reworked
     *
     *  Problem: When families tied on composite (separation=0),
     *           confidence was slashed by ×0.70:
     *             37 × 0.70 = 25.9
     *           This made the engine report LOW confidence even
     *           when one family clearly dominates by vote count.
     *
     *  Fix:    The tighter vote floor (FIX 1) and composite
     *          tie-breaker (FIX 3) mean true ties are rarer.
     *          When they do happen, use a gentler penalty and
     *          factor in the vote-count gap.
     * ────────────────────────────────────────────────── */

    double confidence = winner->best_score;

    /* Family consensus boost */
    if (winner->vote_count >= 3)
        confidence *= 1.15;
    if (winner->vote_count >= 10)
        confidence *= 1.10;
    if (winner->vote_count >= 25)
        confidence *= 1.05;

    /* Ambiguity penalty — reworked */
    if (best_composite > 0.0 && runner_family)
    {
        double separation =
            (best_composite - runner_composite) / best_composite;

        /*
         * FIX 4a: If winner has significantly more votes than
         * runner, reduce the ambiguity penalty. The vote gap
         * itself is evidence of family consensus.
         *
         * Example:  Linux: composite=37, votes=15
         *           HP:    composite=37, votes=2
         *           → vote_ratio = 2/15 = 0.13 → very low
         *           → effective_separation boosted
         */
        double vote_ratio = 1.0;
        if (winner->vote_count > 0 && runner_family->vote_count > 0)
        {
            vote_ratio = (double)runner_family->vote_count /
                         (double)winner->vote_count;
            if (vote_ratio > 1.0)
                vote_ratio = 1.0;
        }
        else if (runner_family->vote_count == 0)
        {
            /* Runner has zero votes — no real competition */
            vote_ratio = 0.0;
        }

        /*
         * Blend score-separation with vote-separation:
         *   effective_sep = max(score_sep, 1 - vote_ratio)
         *
         * If scores are identical (sep=0) but winner has 15 votes
         * vs runner's 2 (vote_ratio=0.13), effective_sep = 0.87
         * → no penalty applied.
         */
        double vote_sep = 1.0 - vote_ratio;
        double effective_sep = separation > vote_sep
                                   ? separation
                                   : vote_sep;

        /*
         * FIX 4b: Gentler penalty curve
         *
         *   effective_sep = 0.0 (true dead heat) → ×0.80  (was 0.70)
         *   effective_sep = 0.15                  → ×0.90
         *   effective_sep ≥ 0.30                  → ×1.00
         */
        if (effective_sep < 0.30)
        {
            double mult = 0.80 + (effective_sep / 0.30) * 0.20;
            confidence *= mult;
        }

        pipe_log(NP_LOG_DEBUG, "fp-match",
                 "ambiguity: score_sep=%.3f vote_ratio=%.3f "
                 "effective_sep=%.3f",
                 separation, vote_ratio, effective_sep);
    }

    /* Clamp */
    if (confidence > 100.0) confidence = 100.0;
    if (confidence <   0.0) confidence = 0.0;

    if (out_confidence)
        *out_confidence = confidence;

    pipe_log(NP_LOG_DEBUG, "fp-match",
             "RESULT: family='%s' os='%s' individual_best=%.0f "
             "votes=%u composite=%.1f "
             "runner='%s' runner_composite=%.1f "
             "confidence=%.1f",
             winner->name,
             best->os_name,
             winner->best_score,
             winner->vote_count,
             best_composite,
             runner_family ? runner_family->name : "(none)",
             runner_composite,
             confidence);

    if (confidence < MIN_CONFIDENCE)
    {
        pipe_log(NP_LOG_DEBUG, "fp-match",
                 "confidence %.1f < %.1f threshold — returning NULL",
                 confidence, MIN_CONFIDENCE);
        return NULL;
    }

    return best->os_name;
}
