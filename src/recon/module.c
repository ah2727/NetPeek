#include "recon/module.h"

#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include "recon_internal.h"

typedef uint32_t (*np_module_abi_version_fn)(void);
typedef const np_module_t *(*np_module_descriptor_fn)(void);
typedef const np_module_manifest_t *(*np_module_manifest_fn)(void);

typedef enum {
    NP_SCHED_PENDING = 0,
    NP_SCHED_RUNNING,
    NP_SCHED_DONE
} np_sched_state_t;

typedef struct {
    const np_module_t *module;
    np_sched_state_t state;
    size_t deps_remaining;
    size_t failed_deps;
    bool queued;
} np_sched_item_t;

typedef struct {
    np_recon_context_t *ctx;
    np_module_registry_t *registry;
    np_sched_item_t *items;
    size_t item_count;

    uint8_t *dep_matrix;
    size_t *ready;
    size_t ready_count;

    size_t running_count;
    bool exclusive_running;
    size_t completed_count;

    pthread_mutex_t lock;
    pthread_cond_t cond;

    bool interrupted_seen;
    np_status_t first_error;
    np_module_run_record_t *records;
} np_scheduler_t;

static _Atomic uint64_t g_module_progress_total;
static _Atomic uint64_t g_module_progress_completed;
static _Atomic uint64_t g_module_progress_stage_total[NP_STAGE_COUNT];
static _Atomic uint64_t g_module_progress_stage_completed[NP_STAGE_COUNT];

void np_module_progress_reset(void)
{
    atomic_store(&g_module_progress_total, 0);
    atomic_store(&g_module_progress_completed, 0);
    for (size_t i = 0; i < NP_STAGE_COUNT; i++)
    {
        atomic_store(&g_module_progress_stage_total[i], 0);
        atomic_store(&g_module_progress_stage_completed[i], 0);
    }
}

void np_module_progress_snapshot(np_module_progress_snapshot_t *out)
{
    if (!out)
        return;

    memset(out, 0, sizeof(*out));
    out->total_modules = atomic_load(&g_module_progress_total);
    out->completed_modules = atomic_load(&g_module_progress_completed);

    for (size_t i = 0; i < NP_STAGE_COUNT; i++)
    {
        out->stage_total[i] = atomic_load(&g_module_progress_stage_total[i]);
        out->stage_completed[i] = atomic_load(&g_module_progress_stage_completed[i]);
    }
}

static uint64_t np_now_ns(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static bool np_has_allowed_ext(const char *path)
{
    size_t n = strlen(path);
#if defined(__APPLE__)
    if (n > 6 && strcmp(path + n - 6, ".dylib") == 0)
        return true;
#endif
    return n > 3 && strcmp(path + n - 3, ".so") == 0;
}

static bool np_hash_file_digest(const char *path, char out_hex[65])
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return false;

    SHA256_CTX sha;
    if (SHA256_Init(&sha) != 1)
    {
        fclose(fp);
        return false;
    }

    unsigned char buf[2048];
    size_t nread = 0;
    while ((nread = fread(buf, 1, sizeof(buf), fp)) > 0)
        (void)SHA256_Update(&sha, buf, nread);

    fclose(fp);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (SHA256_Final(digest, &sha) != 1)
        return false;

    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);

    out_hex[64] = '\0';
    return true;
}

static bool np_allowlist_match(const char *module_name,
                               const char *sha256_hex)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.netpeek/modules/allowlist.txt", home);

    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;

    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), fp))
    {
        char name[256];
        char hash[128];
        if (sscanf(line, "%255s %127s", name, hash) != 2)
            continue;
        if (strcmp(name, module_name) == 0 && strcmp(hash, sha256_hex) == 0)
        {
            ok = true;
            break;
        }
    }

    fclose(fp);
    return ok;
}

static unsigned char *np_read_file_bytes(const char *path, size_t *out_len)
{
    if (!path || !out_len)
        return NULL;

    *out_len = 0;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return NULL;
    }

    long fsz = ftell(fp);
    if (fsz < 0 || fseek(fp, 0, SEEK_SET) != 0)
    {
        fclose(fp);
        return NULL;
    }

    unsigned char *buf = malloc((size_t)fsz);
    if (!buf)
    {
        fclose(fp);
        return NULL;
    }

    if ((size_t)fsz > 0 && fread(buf, 1, (size_t)fsz, fp) != (size_t)fsz)
    {
        free(buf);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    *out_len = (size_t)fsz;
    return buf;
}

static bool np_b64_decode(const char *b64,
                          unsigned char **out,
                          size_t *out_len)
{
    if (!b64 || !out || !out_len)
        return false;

    size_t n = strlen(b64);
    if (n == 0)
        return false;

    size_t cap = (n / 4 + 2) * 3;
    unsigned char *buf = calloc(1, cap);
    if (!buf)
        return false;

    int decoded = EVP_DecodeBlock(buf,
                                  (const unsigned char *)b64,
                                  (int)n);
    if (decoded < 0)
    {
        free(buf);
        return false;
    }

    size_t pad = 0;
    if (n >= 1 && b64[n - 1] == '=')
        pad++;
    if (n >= 2 && b64[n - 2] == '=')
        pad++;

    *out_len = (size_t)decoded - pad;
    *out = buf;
    return true;
}

static bool np_verify_module_signature(const char *module_path,
                                       const np_module_manifest_t *manifest)
{
    if (!module_path || !manifest || !manifest->signer || !manifest->signature)
        return false;

    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;

    char key_path[PATH_MAX];
    snprintf(key_path,
             sizeof(key_path),
             "%s/.netpeek/modules/trusted_keys/%s.pem",
             home,
             manifest->signer);

    FILE *kfp = fopen(key_path, "rb");
    if (!kfp)
        return false;

    EVP_PKEY *pkey = PEM_read_PUBKEY(kfp, NULL, NULL, NULL);
    fclose(kfp);
    if (!pkey)
        return false;

    size_t module_len = 0;
    unsigned char *module_bytes = np_read_file_bytes(module_path, &module_len);
    if (!module_bytes)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    if (!np_b64_decode(manifest->signature, &sig, &sig_len))
    {
        free(module_bytes);
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx &&
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(ctx, sig, sig_len, module_bytes, module_len) == 1)
    {
        ok = true;
    }

    EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(sig, sig_len);
    free(sig);
    OPENSSL_cleanse(module_bytes, module_len);
    free(module_bytes);
    EVP_PKEY_free(pkey);
    return ok;
}

static bool np_path_in_modules_dir(const char *path)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;

    char trusted_dir[PATH_MAX];
    snprintf(trusted_dir, sizeof(trusted_dir), "%s/.netpeek/modules", home);

    char real_mod[PATH_MAX];
    char real_path[PATH_MAX];
    if (!realpath(trusted_dir, real_mod) || !realpath(path, real_path))
        return false;

    size_t mlen = strlen(real_mod);
    return strncmp(real_mod, real_path, mlen) == 0 &&
           (real_path[mlen] == '/' || real_path[mlen] == '\0');
}

static bool np_module_reserve(np_module_registry_t *registry)
{
    if (registry->count < registry->cap)
        return true;

    size_t next_cap = registry->cap ? registry->cap * 2 : 16;
    const np_module_t **next = realloc(registry->items, next_cap * sizeof(*next));
    if (!next)
        return false;

    registry->items = next;
    registry->cap = next_cap;
    return true;
}

static void np_registry_clear_last_run(np_module_registry_t *registry)
{
    if (!registry)
        return;

    free(registry->last_run_records);
    registry->last_run_records = NULL;
    registry->last_run_count = 0;
}

static bool np_registry_set_last_run(np_module_registry_t *registry,
                                     const np_module_run_record_t *records,
                                     size_t count)
{
    if (!registry)
        return false;

    np_registry_clear_last_run(registry);
    if (!records || count == 0)
        return true;

    registry->last_run_records = calloc(count, sizeof(*registry->last_run_records));
    if (!registry->last_run_records)
        return false;

    memcpy(registry->last_run_records, records, count * sizeof(*records));
    registry->last_run_count = count;
    return true;
}

np_module_registry_t *np_module_registry_create(void)
{
    return calloc(1, sizeof(np_module_registry_t));
}

void np_module_registry_destroy(np_module_registry_t *registry)
{
    if (!registry)
        return;

    np_registry_clear_last_run(registry);
    free(registry->items);
    free(registry);
}

np_status_t np_module_register(np_recon_context_t *ctx, const np_module_t *module)
{
    if (!ctx || !ctx->modules || !module || !module->name || !module->run)
        return NP_ERR_ARGS;

    np_module_registry_t *registry = (np_module_registry_t *)ctx->modules;
    if (!np_module_reserve(registry))
        return NP_ERR_MEMORY;

    registry->items[registry->count++] = module;
    return NP_OK;
}

static int np_module_cmp(const void *left, const void *right)
{
    const np_module_t *const *a = left;
    const np_module_t *const *b = right;

    if ((*a)->stage != (*b)->stage)
        return (int)(*a)->stage - (int)(*b)->stage;
    if ((*a)->priority < (*b)->priority)
        return -1;
    if ((*a)->priority > (*b)->priority)
        return 1;
    return strcmp((*a)->name, (*b)->name);
}

static bool np_module_allowed(const np_recon_context_t *ctx,
                              const np_module_t *module)
{
    if (!ctx || !ctx->cfg || !module)
        return false;

    switch (ctx->cfg->auth_mode)
    {
    case NP_AUTH_MODE_PASSIVE:
        return module->impact == NP_IMPACT_PASSIVE;
    case NP_AUTH_MODE_SAFE:
        return module->impact == NP_IMPACT_PASSIVE ||
               module->impact == NP_IMPACT_SAFE;
    case NP_AUTH_MODE_INTRUSIVE:
    default:
        return true;
    }
}

static bool np_ready_contains(np_scheduler_t *scheduler, size_t index)
{
    for (size_t i = 0; i < scheduler->ready_count; i++)
    {
        if (scheduler->ready[i] == index)
            return true;
    }
    return false;
}

static void np_ready_push(np_scheduler_t *scheduler, size_t index)
{
    if (!scheduler || index >= scheduler->item_count)
        return;

    if (np_ready_contains(scheduler, index))
        return;

    scheduler->ready[scheduler->ready_count++] = index;
    scheduler->items[index].queued = true;
}

static bool np_ready_take(np_scheduler_t *scheduler, size_t *out_index)
{
    if (!scheduler || !out_index || scheduler->ready_count == 0)
        return false;

    for (size_t i = 0; i < scheduler->ready_count; i++)
    {
        size_t idx = scheduler->ready[i];
        const np_module_t *module = scheduler->items[idx].module;
        bool can_run = module->parallel_safe;

        if (!module->parallel_safe)
            can_run = (scheduler->running_count == 0 && !scheduler->exclusive_running);
        else
            can_run = !scheduler->exclusive_running;

        if (!can_run)
            continue;

        for (size_t j = i + 1; j < scheduler->ready_count; j++)
            scheduler->ready[j - 1] = scheduler->ready[j];

        scheduler->ready_count--;
        scheduler->items[idx].queued = false;
        *out_index = idx;
        return true;
    }

    return false;
}

static void np_scheduler_mark_done(np_scheduler_t *scheduler,
                                   size_t index,
                                   np_module_run_status_t status,
                                   np_status_t rc,
                                   uint64_t started_ns,
                                   uint64_t ended_ns)
{
    np_sched_item_t *item = &scheduler->items[index];
    if (item->state == NP_SCHED_DONE)
        return;

    item->state = NP_SCHED_DONE;
    item->queued = false;

    scheduler->records[index].run_status = status;
    scheduler->records[index].rc = rc;
    scheduler->records[index].started_ns = started_ns;
    scheduler->records[index].ended_ns = ended_ns;

    if (status == NP_MODULE_RUN_FAILED && scheduler->first_error == NP_OK)
        scheduler->first_error = rc;

    scheduler->completed_count++;
    atomic_fetch_add(&g_module_progress_completed, 1);

    np_stage_t stage = scheduler->items[index].module->stage;
    if ((size_t)stage < NP_STAGE_COUNT)
        atomic_fetch_add(&g_module_progress_stage_completed[(size_t)stage], 1);

    bool failed_for_deps = status != NP_MODULE_RUN_OK;
    for (size_t child = 0; child < scheduler->item_count; child++)
    {
        if (scheduler->dep_matrix[index * scheduler->item_count + child] == 0)
            continue;

        np_sched_item_t *child_item = &scheduler->items[child];
        if (child_item->deps_remaining > 0)
            child_item->deps_remaining--;
        if (failed_for_deps)
            child_item->failed_deps++;
    }
}

static void np_scheduler_promote(np_scheduler_t *scheduler)
{
    bool changed = true;
    while (changed)
    {
        changed = false;

        for (size_t i = 0; i < scheduler->item_count; i++)
        {
            np_sched_item_t *item = &scheduler->items[i];
            if (item->state != NP_SCHED_PENDING || item->deps_remaining != 0)
                continue;

            if (scheduler->interrupted_seen)
            {
                uint64_t now = np_now_ns();
                np_scheduler_mark_done(scheduler,
                                       i,
                                       NP_MODULE_RUN_SKIPPED_INTERRUPT,
                                       NP_ERR_SYSTEM,
                                       now,
                                       now);
                changed = true;
                continue;
            }

            if (item->failed_deps > 0)
            {
                uint64_t now = np_now_ns();
                np_scheduler_mark_done(scheduler,
                                       i,
                                       NP_MODULE_RUN_SKIPPED_DEP,
                                       NP_ERR_SYSTEM,
                                       now,
                                       now);
                changed = true;
                continue;
            }

            if (!item->queued)
            {
                np_ready_push(scheduler, i);
                changed = true;
            }
        }
    }
}

static void *np_scheduler_worker(void *arg)
{
    np_scheduler_t *scheduler = (np_scheduler_t *)arg;

    for (;;)
    {
        pthread_mutex_lock(&scheduler->lock);

        while (1)
        {
            if (scheduler->ctx->interrupted && *scheduler->ctx->interrupted)
            {
                scheduler->interrupted_seen = true;
                if (scheduler->first_error == NP_OK)
                    scheduler->first_error = NP_ERR_SYSTEM;
                np_scheduler_promote(scheduler);
            }

            if (scheduler->completed_count >= scheduler->item_count)
            {
                pthread_mutex_unlock(&scheduler->lock);
                return NULL;
            }

            size_t next = 0;
            if (np_ready_take(scheduler, &next))
            {
                np_sched_item_t *item = &scheduler->items[next];
                const np_module_t *module = item->module;
                item->state = NP_SCHED_RUNNING;
                scheduler->running_count++;
                if (!module->parallel_safe)
                    scheduler->exclusive_running = true;

                uint64_t started_ns = np_now_ns();
                scheduler->records[next].started_ns = started_ns;
                pthread_mutex_unlock(&scheduler->lock);

                np_status_t rc = NP_OK;
                if (module->init)
                {
                    rc = module->init(scheduler->ctx);
                }

                if (rc == NP_OK)
                    rc = module->run(scheduler->ctx);

                if (module->cleanup)
                    module->cleanup(scheduler->ctx);

                uint64_t ended_ns = np_now_ns();

                pthread_mutex_lock(&scheduler->lock);
                scheduler->running_count--;
                if (!module->parallel_safe)
                    scheduler->exclusive_running = false;

                np_scheduler_mark_done(scheduler,
                                       next,
                                       rc == NP_OK ? NP_MODULE_RUN_OK : NP_MODULE_RUN_FAILED,
                                       rc,
                                       started_ns,
                                       ended_ns);
                np_scheduler_promote(scheduler);
                pthread_cond_broadcast(&scheduler->cond);
                break;
            }

            pthread_cond_wait(&scheduler->cond, &scheduler->lock);
        }

        pthread_mutex_unlock(&scheduler->lock);
    }
}

np_status_t np_module_run_stage(np_recon_context_t *ctx, np_stage_t stage)
{
    if (!ctx || !ctx->modules)
        return NP_ERR_ARGS;

    np_module_registry_t *registry = (np_module_registry_t *)ctx->modules;
    if (registry->count == 0)
    {
        np_module_progress_reset();
        return NP_OK;
    }

    np_module_progress_reset();
    np_registry_clear_last_run(registry);
    qsort(registry->items, registry->count, sizeof(*registry->items), np_module_cmp);

    np_module_run_record_t *records = calloc(registry->count, sizeof(*records));
    if (!records)
        return NP_ERR_MEMORY;

    size_t record_count = 0;
    np_status_t status = NP_OK;

    for (size_t i = 0; i < registry->count; i++)
    {
        const np_module_t *module = registry->items[i];
        if (module->stage != stage || !np_module_allowed(ctx, module))
            continue;

        atomic_fetch_add(&g_module_progress_total, 1);
        if ((size_t)module->stage < NP_STAGE_COUNT)
            atomic_fetch_add(&g_module_progress_stage_total[(size_t)module->stage], 1);

        np_module_run_record_t *record = &records[record_count++];
        strncpy(record->module_name, module->name, sizeof(record->module_name) - 1);
        record->stage = module->stage;

        uint64_t started = np_now_ns();
        np_status_t rc = NP_OK;

        if (module->init)
            rc = module->init(ctx);
        if (rc == NP_OK)
            rc = module->run(ctx);
        if (module->cleanup)
            module->cleanup(ctx);

        uint64_t ended = np_now_ns();
        record->started_ns = started;
        record->ended_ns = ended;
        record->rc = rc;
        record->run_status = rc == NP_OK ? NP_MODULE_RUN_OK : NP_MODULE_RUN_FAILED;
        atomic_fetch_add(&g_module_progress_completed, 1);
        if ((size_t)module->stage < NP_STAGE_COUNT)
            atomic_fetch_add(&g_module_progress_stage_completed[(size_t)module->stage], 1);

        if (rc != NP_OK)
        {
            status = rc;
            break;
        }
    }

    (void)np_registry_set_last_run(registry, records, record_count);
    free(records);
    return status;
}

np_status_t np_module_run_range(np_recon_context_t *ctx,
                                np_stage_t from,
                                np_stage_t to)
{
    if (!ctx || !ctx->modules || from > to)
        return NP_ERR_ARGS;

    np_module_registry_t *registry = (np_module_registry_t *)ctx->modules;
    if (registry->count == 0)
    {
        np_module_progress_reset();
        return NP_OK;
    }

    qsort(registry->items, registry->count, sizeof(*registry->items), np_module_cmp);

    size_t eligible_count = 0;
    for (size_t i = 0; i < registry->count; i++)
    {
        const np_module_t *module = registry->items[i];
        if (module->stage >= from && module->stage <= to && np_module_allowed(ctx, module))
            eligible_count++;
    }

    np_registry_clear_last_run(registry);
    np_module_progress_reset();
    if (eligible_count == 0)
        return NP_OK;

    atomic_store(&g_module_progress_total, eligible_count);

    np_scheduler_t scheduler;
    memset(&scheduler, 0, sizeof(scheduler));
    scheduler.ctx = ctx;
    scheduler.registry = registry;
    scheduler.item_count = eligible_count;
    scheduler.first_error = NP_OK;

    scheduler.items = calloc(eligible_count, sizeof(*scheduler.items));
    scheduler.dep_matrix = calloc(eligible_count * eligible_count, sizeof(*scheduler.dep_matrix));
    scheduler.ready = calloc(eligible_count, sizeof(*scheduler.ready));
    scheduler.records = calloc(eligible_count, sizeof(*scheduler.records));
    if (!scheduler.items || !scheduler.dep_matrix || !scheduler.ready || !scheduler.records)
    {
        free(scheduler.items);
        free(scheduler.dep_matrix);
        free(scheduler.ready);
        free(scheduler.records);
        return NP_ERR_MEMORY;
    }

    size_t w = 0;
    for (size_t i = 0; i < registry->count; i++)
    {
        const np_module_t *module = registry->items[i];
        if (module->stage < from || module->stage > to || !np_module_allowed(ctx, module))
            continue;

        scheduler.items[w].module = module;
        scheduler.items[w].state = NP_SCHED_PENDING;
        scheduler.records[w].stage = module->stage;
        strncpy(scheduler.records[w].module_name, module->name, sizeof(scheduler.records[w].module_name) - 1);
        if ((size_t)module->stage < NP_STAGE_COUNT)
            atomic_fetch_add(&g_module_progress_stage_total[(size_t)module->stage], 1);
        w++;
    }

    for (size_t i = 0; i < scheduler.item_count; i++)
    {
        const np_module_t *module = scheduler.items[i].module;
        for (size_t d = 0; d < module->depends_on_count; d++)
        {
            const char *dep_name = module->depends_on[d];
            size_t dep_index = scheduler.item_count;
            for (size_t j = 0; j < scheduler.item_count; j++)
            {
                if (strcmp(scheduler.items[j].module->name, dep_name) == 0)
                {
                    dep_index = j;
                    break;
                }
            }

            if (dep_index >= scheduler.item_count)
            {
                free(scheduler.items);
                free(scheduler.dep_matrix);
                free(scheduler.ready);
                free(scheduler.records);
                return NP_ERR_ARGS;
            }

            scheduler.dep_matrix[dep_index * scheduler.item_count + i] = 1;
            scheduler.items[i].deps_remaining++;
        }
    }

    if (pthread_mutex_init(&scheduler.lock, NULL) != 0 ||
        pthread_cond_init(&scheduler.cond, NULL) != 0)
    {
        free(scheduler.items);
        free(scheduler.dep_matrix);
        free(scheduler.ready);
        free(scheduler.records);
        return NP_ERR_SYSTEM;
    }

    pthread_mutex_lock(&scheduler.lock);
    np_scheduler_promote(&scheduler);
    pthread_mutex_unlock(&scheduler.lock);

    long cpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu < 1)
        cpu = 2;

    size_t worker_count = (size_t)cpu;
    if (ctx->cfg && ctx->cfg->recon_workers > 0 &&
        worker_count > (size_t)ctx->cfg->recon_workers)
        worker_count = (size_t)ctx->cfg->recon_workers;
    if (ctx->cfg && ctx->cfg->recon_force_serial)
        worker_count = 1;
    if (worker_count > scheduler.item_count)
        worker_count = scheduler.item_count;
    if (worker_count == 0)
        worker_count = 1;

    pthread_t *workers = calloc(worker_count, sizeof(*workers));
    if (!workers)
    {
        pthread_cond_destroy(&scheduler.cond);
        pthread_mutex_destroy(&scheduler.lock);
        free(scheduler.items);
        free(scheduler.dep_matrix);
        free(scheduler.ready);
        free(scheduler.records);
        return NP_ERR_MEMORY;
    }

    for (size_t i = 0; i < worker_count; i++)
    {
        if (pthread_create(&workers[i], NULL, np_scheduler_worker, &scheduler) != 0)
        {
            scheduler.first_error = NP_ERR_SYSTEM;
            pthread_mutex_lock(&scheduler.lock);
            scheduler.interrupted_seen = true;
            np_scheduler_promote(&scheduler);
            pthread_cond_broadcast(&scheduler.cond);
            pthread_mutex_unlock(&scheduler.lock);
            worker_count = i;
            break;
        }
    }

    for (size_t i = 0; i < worker_count; i++)
        pthread_join(workers[i], NULL);

    free(workers);

    pthread_cond_destroy(&scheduler.cond);
    pthread_mutex_destroy(&scheduler.lock);

    if (!np_registry_set_last_run(registry, scheduler.records, scheduler.item_count) &&
        scheduler.first_error == NP_OK)
        scheduler.first_error = NP_ERR_MEMORY;

    free(scheduler.items);
    free(scheduler.dep_matrix);
    free(scheduler.ready);
    free(scheduler.records);

    if (scheduler.first_error != NP_OK)
        return scheduler.first_error;

    return NP_OK;
}

void np_module_clear(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->modules)
        return;

    np_module_registry_t *registry = (np_module_registry_t *)ctx->modules;
    registry->count = 0;
    np_registry_clear_last_run(registry);
}

uint32_t np_module_last_run_snapshot(np_recon_context_t *ctx,
                                     np_module_run_record_t **out)
{
    if (!ctx || !ctx->modules || !out)
        return 0;

    *out = NULL;
    np_module_registry_t *registry = (np_module_registry_t *)ctx->modules;
    if (!registry->last_run_records || registry->last_run_count == 0)
        return 0;

    np_module_run_record_t *records = calloc(registry->last_run_count, sizeof(*records));
    if (!records)
        return 0;

    memcpy(records, registry->last_run_records,
           registry->last_run_count * sizeof(*records));
    *out = records;
    return (uint32_t)registry->last_run_count;
}

void np_module_run_snapshot_free(np_module_run_record_t *records)
{
    free(records);
}

np_status_t np_module_load_plugin(np_recon_context_t *ctx,
                                  const char *path,
                                  np_module_plugin_t *out_plugin)
{
    if (!ctx || !path || !out_plugin)
        return NP_ERR_ARGS;

    if (!np_has_allowed_ext(path) || !np_path_in_modules_dir(path))
        return NP_ERR_PERMISSION;

    memset(out_plugin, 0, sizeof(*out_plugin));

    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return NP_ERR_SYSTEM;

    np_module_abi_version_fn abi_fn = (np_module_abi_version_fn)dlsym(handle, "np_module_abi_version");
    np_module_descriptor_fn desc_fn = (np_module_descriptor_fn)dlsym(handle, "np_module_descriptor_v1");
    np_module_manifest_fn manifest_fn = (np_module_manifest_fn)dlsym(handle, "np_module_manifest_v1");
    if (!abi_fn || !desc_fn || !manifest_fn)
    {
        dlclose(handle);
        return NP_ERR_SYSTEM;
    }

    if (abi_fn() != NP_RECON_MODULE_ABI_V1)
    {
        dlclose(handle);
        return NP_ERR_ARGS;
    }

    const np_module_t *module = desc_fn();
    const np_module_manifest_t *manifest = manifest_fn();
    if (!module || !manifest || !manifest->module_name)
    {
        dlclose(handle);
        return NP_ERR_SYSTEM;
    }

    if (!manifest->signer || !manifest->signer[0] ||
        !manifest->signature || !manifest->signature[0])
    {
        dlclose(handle);
        return NP_ERR_PERMISSION;
    }

    char sha256_hex[65];
    if (!np_hash_file_digest(path, sha256_hex))
    {
        dlclose(handle);
        return NP_ERR_SYSTEM;
    }
    if (!np_allowlist_match(manifest->module_name, sha256_hex))
    {
        dlclose(handle);
        return NP_ERR_PERMISSION;
    }

    if (!np_verify_module_signature(path, manifest))
    {
        dlclose(handle);
        return NP_ERR_PERMISSION;
    }

    np_status_t rc = np_module_register(ctx, module);
    if (rc != NP_OK)
    {
        dlclose(handle);
        return rc;
    }

    out_plugin->dl_handle = handle;
    out_plugin->module = module;
    return NP_OK;
}

np_status_t np_module_load_dir(np_recon_context_t *ctx,
                               const char *dirpath,
                               size_t *loaded_count)
{
    if (!ctx || !dirpath)
        return NP_ERR_ARGS;

    if (loaded_count)
        *loaded_count = 0;

    DIR *dir = opendir(dirpath);
    if (!dir)
        return NP_ERR_SYSTEM;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);
        if (!np_has_allowed_ext(full_path))
            continue;

        np_module_plugin_t plugin;
        np_status_t rc = np_module_load_plugin(ctx, full_path, &plugin);
        if (rc == NP_OK && loaded_count)
            (*loaded_count)++;
    }

    closedir(dir);
    return NP_OK;
}

void np_module_unload_plugin(np_module_plugin_t *plugin)
{
    if (!plugin)
        return;

    if (plugin->dl_handle)
        dlclose(plugin->dl_handle);

    plugin->dl_handle = NULL;
    plugin->module = NULL;
}
