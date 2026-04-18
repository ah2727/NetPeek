/*****************************************************************************
 * npe_loader.c — Find, read, validate script files
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * The loader discovers .npe files on disk, reads their source into memory,
 * creates a temporary Lua state for each to extract metadata (description,
 * author, categories, entry points, dependencies), validates the structure,
 * and registers the resulting npe_script_t objects into the registry.
 *****************************************************************************/

#include "npe/npe_loader.h"
#include "core/error.h"
#include "npe/npe_types.h"
#include "npe/npe_error.h"
#include "npe/npe_script.h"
#include "npe/npe_registry.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <strings.h>  /* strcasecmp */
#include <libgen.h>   /* basename   */

/*============================================================================
 * Internal Constants
 *============================================================================*/

#define LOADER_MAX_FILES        4096
#define LOADER_MAX_FILE_SIZE    (2 * 1024 * 1024) /* 2 MiB per script */
#define LOADER_DB_MAGIC         "NPE_DB_V1\n"
#define LOADER_DB_MAGIC_LEN     10

/*============================================================================
 * Internal File Entry
 *============================================================================*/

typedef struct file_entry {
    char        path[4096];
    struct stat st;
} file_entry_t;

/*============================================================================
 * Loader Structure
 *============================================================================*/

struct npe_loader {
    /* Configuration */
    char                script_dir[4096];
    char                script_db_path[4096];
    bool                recursive;
    bool                update_db;
    npe_log_fn          log_fn;
    void               *log_userdata;
    npe_log_level_t     log_level;

    /* Discovered files */
    file_entry_t       *files;
    size_t              file_count;
    size_t              file_capacity;

    /* Statistics */
    npe_loader_stats_t  stats;

    /* Script ID counter */
    uint32_t            next_id;
};

/*============================================================================
 * Internal — Logging
 *============================================================================*/

static void loader_log(const npe_loader_t *loader,
                       npe_log_level_t     level,
                       const char         *fmt, ...)
{
    if (!loader || level > loader->log_level)
        return;

    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (loader->log_fn) {
        loader->log_fn(level, "loader", buf, loader->log_userdata);
    } else {
        const char *tag = "INFO";
        switch (level) {
            case NPE_LOG_ERROR: tag = "ERROR"; break;
            case NPE_LOG_WARN:  tag = "WARN";  break;
            case NPE_LOG_DEBUG: tag = "DEBUG"; break;
            case NPE_LOG_TRACE: tag = "TRACE"; break;
            default: break;
        }
        np_error(NP_ERR_RUNTIME, "[NPE][loader][%s] %s\n", tag, buf);
    }
}

/*============================================================================
 * Internal — File List Management
 *============================================================================*/

static npe_error_t loader_add_file(npe_loader_t      *loader,
                                   const char        *path,
                                   const struct stat *st)
{
    if (loader->file_count >= loader->file_capacity) {
        size_t new_cap = loader->file_capacity == 0 ?
                         64 : loader->file_capacity * 2;
        if (new_cap > LOADER_MAX_FILES) new_cap = LOADER_MAX_FILES;
        if (loader->file_count >= new_cap) return NPE_ERROR_MEMORY;

        file_entry_t *tmp = realloc(loader->files,
                                    new_cap * sizeof(file_entry_t));
        if (!tmp) return NPE_ERROR_MEMORY;
        loader->files         = tmp;
        loader->file_capacity = new_cap;
    }

    file_entry_t *entry = &loader->files[loader->file_count];
    snprintf(entry->path, sizeof(entry->path), "%s", path);
    entry->st = *st;
    loader->file_count++;
    return NPE_OK;
}

/*============================================================================
 * Internal — Recursive Directory Scanner
 *============================================================================*/

static npe_error_t loader_scan_dir_recursive(npe_loader_t *loader,
                                             const char   *dir_path)
{
    DIR *dir = opendir(dir_path);
    if (!dir) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Cannot open directory '%s': %s",
                   dir_path, strerror(errno));
        return NPE_ERROR_IO;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(ent->d_name, ".") == 0 ||
            strcmp(ent->d_name, "..") == 0)
            continue;

        /* Skip hidden files */
        if (ent->d_name[0] == '.')
            continue;

        /* Build full path */
        char full_path[4096];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s",
                         dir_path, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_path))
            continue;

        struct stat st;
        if (stat(full_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            if (loader->recursive) {
                loader_scan_dir_recursive(loader, full_path);
            }
        } else if (S_ISREG(st.st_mode)) {
            /* Check for .npe extension */
            size_t name_len = strlen(ent->d_name);
            size_t ext_len  = strlen(NPE_SCRIPT_EXTENSION);
            if (name_len > ext_len &&
                strcasecmp(ent->d_name + name_len - ext_len,
                           NPE_SCRIPT_EXTENSION) == 0) {
                npe_error_t err = loader_add_file(loader, full_path, &st);
                if (err != NPE_OK) {
                    loader_log(loader, NPE_LOG_WARN,
                               "Failed to add file entry: %s", full_path);
                }
            }
        }
    }

    closedir(dir);
    return NPE_OK;
}

/*============================================================================
 * Internal — Read File Contents
 *============================================================================*/

static npe_error_t loader_read_file(const char *path,
                                    char      **out_text,
                                    size_t     *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NPE_ERROR_IO;

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size < 0 || (size_t)size > LOADER_MAX_FILE_SIZE) {
        fclose(fp);
        return NPE_ERROR_IO;
    }

    char *text = malloc((size_t)size + 1);
    if (!text) {
        fclose(fp);
        return NPE_ERROR_MEMORY;
    }

    size_t nread = fread(text, 1, (size_t)size, fp);
    fclose(fp);

    if ((long)nread != size) {
        free(text);
        return NPE_ERROR_IO;
    }

    text[nread] = '\0';
    *out_text = text;
    *out_len  = nread;
    return NPE_OK;
}

/*============================================================================
 * Internal — Simple CRC64 (for script checksums)
 *============================================================================*/

static uint64_t loader_crc64(const char *data, size_t len)
{
    uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint64_t)(unsigned char)data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xC96C5795D7870F42ULL;
            else
                crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}

/*============================================================================
 * Internal — Extract Script Name from Path
 *============================================================================*/

static void loader_extract_name(const char *path, char *name, size_t name_sz)
{
    /* Get filename without directory */
    const char *last_slash = strrchr(path, '/');
    const char *fname = last_slash ? last_slash + 1 : path;

    snprintf(name, name_sz, "%s", fname);

    /* Remove .npe extension */
    size_t len = strlen(name);
    size_t ext_len = strlen(NPE_SCRIPT_EXTENSION);
    if (len > ext_len &&
        strcasecmp(name + len - ext_len, NPE_SCRIPT_EXTENSION) == 0) {
        name[len - ext_len] = '\0';
    }
}

/*============================================================================
 * Internal — Category String to Bitmask
 *============================================================================*/

static uint32_t loader_parse_category(const char *cat_str)
{
    if (!cat_str) return 0;

    if (strcasecmp(cat_str, "auth")      == 0) return NPE_CAT_AUTH;
    if (strcasecmp(cat_str, "broadcast") == 0) return NPE_CAT_BROADCAST;
    if (strcasecmp(cat_str, "brute")     == 0) return NPE_CAT_BRUTE;
    if (strcasecmp(cat_str, "default")   == 0) return NPE_CAT_DEFAULT;
    if (strcasecmp(cat_str, "discovery") == 0) return NPE_CAT_DISCOVERY;
    if (strcasecmp(cat_str, "dos")       == 0) return NPE_CAT_DOS;
    if (strcasecmp(cat_str, "exploit")   == 0) return NPE_CAT_EXPLOIT;
    if (strcasecmp(cat_str, "external")  == 0) return NPE_CAT_EXTERNAL;
    if (strcasecmp(cat_str, "fuzzer")    == 0) return NPE_CAT_FUZZER;
    if (strcasecmp(cat_str, "intrusive") == 0) return NPE_CAT_INTRUSIVE;
    if (strcasecmp(cat_str, "malware")   == 0) return NPE_CAT_MALWARE;
    if (strcasecmp(cat_str, "safe")      == 0) return NPE_CAT_SAFE;
    if (strcasecmp(cat_str, "version")   == 0) return NPE_CAT_VERSION;
    if (strcasecmp(cat_str, "vuln")      == 0) return NPE_CAT_VULN;
    return 0;
}

/*============================================================================
 * Internal — Category Bitmask to String (for DB serialization)
 *============================================================================*/

static void loader_categories_to_string(uint32_t mask, char *buf, size_t buf_sz)
{
    buf[0] = '\0';
    size_t off = 0;

    static const struct { uint32_t bit; const char *name; } cat_table[] = {
        { NPE_CAT_AUTH,      "auth"      },
        { NPE_CAT_BROADCAST, "broadcast" },
        { NPE_CAT_BRUTE,     "brute"     },
        { NPE_CAT_DEFAULT,   "default"   },
        { NPE_CAT_DISCOVERY, "discovery" },
        { NPE_CAT_DOS,       "dos"       },
        { NPE_CAT_EXPLOIT,   "exploit"   },
        { NPE_CAT_EXTERNAL,  "external"  },
        { NPE_CAT_FUZZER,    "fuzzer"    },
        { NPE_CAT_INTRUSIVE, "intrusive" },
        { NPE_CAT_MALWARE,   "malware"   },
        { NPE_CAT_SAFE,      "safe"      },
        { NPE_CAT_VERSION,   "version"   },
        { NPE_CAT_VULN,      "vuln"      },
    };

    for (size_t i = 0; i < sizeof(cat_table) / sizeof(cat_table[0]); i++) {
        if (mask & cat_table[i].bit) {
            int n = snprintf(buf + off, buf_sz - off,
                             "%s%s",
                             off > 0 ? "," : "",
                             cat_table[i].name);
            if (n < 0 || (size_t)n >= buf_sz - off) break;
            off += (size_t)n;
        }
    }
}

/*============================================================================
 * Internal — Portable Monotonic Time (milliseconds)
 *============================================================================*/

static double loader_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/*============================================================================
 * Internal — Lua Metadata Extraction
 *============================================================================*/

static void loader_extract_string_field(lua_State  *L,
                                        const char *global,
                                        char       *out,
                                        size_t      out_sz)
{
    lua_getglobal(L, global);
    if (lua_isstring(L, -1)) {
        snprintf(out, out_sz, "%s", lua_tostring(L, -1));
    }
    lua_pop(L, 1);
}

static bool loader_has_function(lua_State *L, const char *name)
{
    lua_getglobal(L, name);
    bool is_func = lua_isfunction(L, -1);
    lua_pop(L, 1);
    return is_func;
}

static uint32_t loader_extract_categories(lua_State *L)
{
    uint32_t mask = 0;

    lua_getglobal(L, "categories");
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            if (lua_isstring(L, -1)) {
                mask |= loader_parse_category(lua_tostring(L, -1));
            }
            lua_pop(L, 1); /* pop value, keep key */
        }
    } else if (lua_isstring(L, -1)) {
        /* Single string: "default" */
        mask |= loader_parse_category(lua_tostring(L, -1));
    }
    lua_pop(L, 1);

    return mask;
}

static void loader_extract_dependencies(lua_State         *L,
                                        npe_script_meta_t *meta)
{
    lua_getglobal(L, "dependencies");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return;
    }

    lua_pushnil(L);
    while (lua_next(L, -2) != 0 && meta->dependency_count < NPE_MAX_DEPENDENCIES) {
        if (lua_isstring(L, -1)) {
            snprintf(meta->dependencies[meta->dependency_count],
                     NPE_MAX_SCRIPT_NAME,
                     "%s", lua_tostring(L, -1));
            meta->dependency_count++;
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

static void loader_extract_ports(lua_State         *L,
                                 npe_script_meta_t *meta)
{
    lua_getglobal(L, "portrule_ports");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return;
    }

    lua_pushnil(L);
    while (lua_next(L, -2) != 0 &&
           meta->interest_port_count < NPE_MAX_PORTS_RULE) {
        if (lua_isinteger(L, -1)) {
            int port = (int)lua_tointeger(L, -1);
            if (port > 0 && port <= 65535) {
                meta->interest_ports[meta->interest_port_count++] =
                    (uint16_t)port;
            }
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

static void loader_extract_recon_metadata(lua_State *L,
                                          npe_script_meta_t *meta)
{
    snprintf(meta->stage, sizeof(meta->stage), "%s", "enum");
    snprintf(meta->impact, sizeof(meta->impact), "%s", "safe");

    lua_getglobal(L, "metadata");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);

        if (meta->categories & (uint32_t)NPE_CAT_INTRUSIVE)
            snprintf(meta->impact, sizeof(meta->impact), "%s", "intrusive");
        return;
    }

    lua_getfield(L, -1, "stage");
    if (lua_isstring(L, -1))
        snprintf(meta->stage, sizeof(meta->stage), "%s", lua_tostring(L, -1));
    lua_pop(L, 1);

    lua_getfield(L, -1, "impact");
    if (lua_isstring(L, -1))
        snprintf(meta->impact, sizeof(meta->impact), "%s", lua_tostring(L, -1));
    lua_pop(L, 1);

    lua_getfield(L, -1, "requires");
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0 && meta->requires_count < NPE_MAX_DEPENDENCIES) {
            if (lua_isstring(L, -1)) {
                snprintf(meta->requires[meta->requires_count],
                         NPE_MAX_SCRIPT_NAME,
                         "%s",
                         lua_tostring(L, -1));
                meta->requires_count++;
            }
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 2);
}

/*============================================================================
 * npe_loader_parse_metadata
 *============================================================================*/

npe_error_t npe_loader_parse_metadata(npe_loader_t      *loader,
                                      void              *lua_state,
                                      npe_script_meta_t *meta)
{
    if (!loader || !lua_state || !meta) return NPE_ERROR_INVALID_ARG;

    lua_State *L = (lua_State *)lua_state;
    memset(meta, 0, sizeof(*meta));

    /* Execute the script chunk to define globals */
    if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        loader_log(loader, NPE_LOG_WARN,
                   "Error executing script for metadata: %s",
                   err ? err : "unknown");
        lua_pop(L, 1);
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    /* Extract string fields */
    loader_extract_string_field(L, "description", meta->description,
                                sizeof(meta->description));
    loader_extract_string_field(L, "author", meta->author,
                                sizeof(meta->author));
    loader_extract_string_field(L, "license", meta->license,
                                sizeof(meta->license));
    loader_extract_string_field(L, "version", meta->version,
                                sizeof(meta->version));
    loader_extract_string_field(L, "usage", meta->usage,
                                sizeof(meta->usage));

    /* Extract categories */
    meta->categories = loader_extract_categories(L);

    /* Extract recon metadata (new DSL, backwards compatible) */
    loader_extract_recon_metadata(L, meta);

    /* Detect entry points */
    meta->has_prerule  = loader_has_function(L, "prerule");
    meta->has_hostrule = loader_has_function(L, "hostrule");
    meta->has_portrule = loader_has_function(L, "portrule");
    meta->has_postrule = loader_has_function(L, "postrule");
    meta->has_action   = loader_has_function(L, "action");

    /* Extract dependencies */
    loader_extract_dependencies(L, meta);

    /* Extract port interests */
    loader_extract_ports(L, meta);

    return NPE_OK;
}

/*============================================================================
 * npe_loader_create
 *============================================================================*/

npe_error_t npe_loader_create(const npe_loader_config_t *config,
                              npe_loader_t             **out)
{
    if (!out) return NPE_ERROR_INVALID_ARG;
    *out = NULL;

    npe_loader_t *loader = calloc(1, sizeof(npe_loader_t));
    if (!loader) return NPE_ERROR_MEMORY;

    if (config) {
        if (config->script_dir)
            snprintf(loader->script_dir, sizeof(loader->script_dir),
                     "%s", config->script_dir);
        if (config->script_db_path)
            snprintf(loader->script_db_path, sizeof(loader->script_db_path),
                     "%s", config->script_db_path);
        loader->recursive    = config->recursive;
        loader->update_db    = config->update_db;
        loader->log_fn       = config->log_fn;
        loader->log_userdata = config->log_userdata;
        loader->log_level    = config->log_level;
    }

    /* Defaults */
    if (loader->script_dir[0] == '\0')
        snprintf(loader->script_dir, sizeof(loader->script_dir), "scripts/");
    if (loader->script_db_path[0] == '\0')
        snprintf(loader->script_db_path, sizeof(loader->script_db_path),
                 "scripts/script.db");

    loader->recursive = true; /* default to recursive scanning */
    loader->next_id   = 1;

    *out = loader;
    return NPE_OK;
}

/*============================================================================
 * npe_loader_destroy
 *============================================================================*/

void npe_loader_destroy(npe_loader_t **loader)
{
    if (!loader || !*loader) return;

    npe_loader_t *l = *loader;
    free(l->files);
    free(l);
    *loader = NULL;
}

/*============================================================================
 * npe_loader_scan_directory
 *============================================================================*/

npe_error_t npe_loader_scan_directory(npe_loader_t *loader, size_t *count)
{
    if (!loader) return NPE_ERROR_INVALID_ARG;

    /* Reset file list */
    loader->file_count = 0;

    loader_log(loader, NPE_LOG_DEBUG,
               "Scanning directory: %s (recursive=%s)",
               loader->script_dir,
               loader->recursive ? "yes" : "no");

    npe_error_t err = loader_scan_dir_recursive(loader, loader->script_dir);

    if (count)
        *count = loader->file_count;

    loader->stats.files_found = loader->file_count;

    loader_log(loader, NPE_LOG_INFO,
               "Found %zu .npe files", loader->file_count);

    return err;
}

/*============================================================================
 * npe_loader_load_script
 *============================================================================*/

npe_error_t npe_loader_load_script(npe_loader_t  *loader,
                                   const char    *path,
                                   npe_script_t **out)
{
    if (!loader || !path || !out) return NPE_ERROR_INVALID_ARG;
    *out = NULL;

    loader_log(loader, NPE_LOG_TRACE, "Loading script: %s", path);

    /* 1. Read file */
    char   *text = NULL;
    size_t  text_len = 0;
    npe_error_t err = loader_read_file(path, &text, &text_len);
    if (err != NPE_OK) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Failed to read file '%s': %s",
                   path, npe_error_string(err));
        return err;
    }

    /* 2. Create temporary Lua state */
    lua_State *L = luaL_newstate();
    if (!L) {
        free(text);
        return NPE_ERROR_MEMORY;
    }

    /* Load safe subset of standard libraries */
    luaL_requiref(L, "_G",        luaopen_base,   1); lua_pop(L, 1);
    luaL_requiref(L, "string",    luaopen_string, 1); lua_pop(L, 1);
    luaL_requiref(L, "table",     luaopen_table,  1); lua_pop(L, 1);
    luaL_requiref(L, "math",      luaopen_math,   1); lua_pop(L, 1);
    luaL_requiref(L, "utf8",      luaopen_utf8,   1); lua_pop(L, 1);

    /* Remove dangerous functions from base */
    lua_pushnil(L); lua_setglobal(L, "dofile");
    lua_pushnil(L); lua_setglobal(L, "loadfile");
    lua_pushnil(L); lua_setglobal(L, "load");

    /* 3. Load (compile) the script */
    int load_err = luaL_loadbuffer(L, text, text_len, path);
    if (load_err != LUA_OK) {
        const char *lua_err = lua_tostring(L, -1);
        loader_log(loader, NPE_LOG_ERROR,
                   "Syntax error in '%s': %s",
                   path, lua_err ? lua_err : "unknown");
        lua_close(L);
        free(text);
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    /* 4. Extract metadata (this also executes the chunk) */
    npe_script_meta_t meta;
    err = npe_loader_parse_metadata(loader, L, &meta);
    lua_close(L);

    if (err != NPE_OK) {
        loader_log(loader, NPE_LOG_WARN,
                   "Metadata extraction failed for '%s'", path);
        free(text);
        return err;
    }

    /* 5. Build npe_script_t */
    npe_script_t *script = NULL;
    err = npe_script_create(&script);
    if (err != NPE_OK) {
        free(text);
        return err;
    }

    script->id = loader->next_id++;

    /* Name */
    loader_extract_name(path, script->filename, sizeof(script->filename));
    snprintf(meta.name, sizeof(meta.name), "%s", script->filename);

    /* Metadata */
    script->meta = meta;

    /* Source */
    script->source.path = strdup(path);
    script->source.text = text;  /* transfer ownership */
    script->source.text_len = text_len;
    script->source.checksum = loader_crc64(text, text_len);

    struct stat st;
    if (stat(path, &st) == 0)
        script->source.mtime = st.st_mtime;

    /* State */
    script->state    = NPE_SCRIPT_IDLE;
    script->selected = false;
    script->priority = 50; /* default priority */

    loader_log(loader, NPE_LOG_DEBUG,
               "Loaded script '%s': categories=0x%x, "
               "prerule=%d, hostrule=%d, portrule=%d, postrule=%d, action=%d",
               script->filename,
               meta.categories,
               meta.has_prerule, meta.has_hostrule,
               meta.has_portrule, meta.has_postrule,
               meta.has_action);

    *out = script;
    return NPE_OK;
}

/*============================================================================
 * npe_loader_validate
 *============================================================================*/

npe_error_t npe_loader_validate(npe_loader_t       *loader,
                                const npe_script_t *script)
{
    if (!loader || !script) return NPE_ERROR_INVALID_ARG;

    /* Must have at least one rule function */
    bool has_rule = script->meta.has_prerule  ||
                    script->meta.has_hostrule ||
                    script->meta.has_portrule ||
                    script->meta.has_postrule;

    if (!has_rule) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Script '%s' has no rule function "
                   "(prerule/hostrule/portrule/postrule)",
                   script->filename);
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    /* Must have an action() function */
    if (!script->meta.has_action) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Script '%s' is missing required action() function",
                   script->filename);
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    /* Name must be non-empty */
    if (script->filename[0] == '\0' && script->meta.name[0] == '\0') {
        loader_log(loader, NPE_LOG_ERROR,
                   "Script has an empty name (path: %s)",
                   script->source.path ? script->source.path : "<unknown>");
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    /* Source text must be present */
    if (!script->source.text || script->source.text_len == 0) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Script '%s' has no source text loaded",
                   script->filename);
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    /* Validate that port-rule scripts declare at least one interest port
     * (warning, not a hard error) */
    if (script->meta.has_portrule &&
        script->meta.interest_port_count == 0) {
        loader_log(loader, NPE_LOG_WARN,
                   "Script '%s' defines portrule but declares no "
                   "portrule_ports — it will match all ports",
                   script->filename);
    }

    /* Validate dependency count is within bounds */
    if (script->meta.dependency_count > NPE_MAX_DEPENDENCIES) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Script '%s' declares too many dependencies (%zu > %d)",
                   script->filename,
                   script->meta.dependency_count,
                   NPE_MAX_DEPENDENCIES);
        return NPE_ERROR_SCRIPT_SYNTAX;
    }

    loader_log(loader, NPE_LOG_TRACE,
               "Script '%s' passed validation", script->filename);

    return NPE_OK;
}

/*============================================================================
 * npe_loader_load_all
 *============================================================================*/

npe_error_t npe_loader_load_all(npe_loader_t   *loader,
                                npe_registry_t *registry)
{
    if (!loader || !registry) return NPE_ERROR_INVALID_ARG;

    double t_start = loader_time_ms();

    /* Reset statistics */
    memset(&loader->stats, 0, sizeof(loader->stats));

    /* Step 1: Scan directory for .npe files */
    size_t found = 0;
    npe_error_t err = npe_loader_scan_directory(loader, &found);
    if (err != NPE_OK && found == 0) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Directory scan failed and no files found");
        return err;
    }

    loader->stats.files_found = found;

    loader_log(loader, NPE_LOG_INFO,
               "Loading %zu script files...", found);

    /* Step 2: Load and validate each file */
    for (size_t i = 0; i < loader->file_count; i++) {
        const char *path = loader->files[i].path;

        npe_script_t *script = NULL;
        npe_error_t load_err = npe_loader_load_script(loader, path, &script);
        if (load_err != NPE_OK) {
            loader_log(loader, NPE_LOG_WARN,
                       "Failed to load '%s': %s",
                       path, npe_error_string(load_err));
            loader->stats.files_failed++;
            continue;
        }

        /* Validate the script structure */
        npe_error_t val_err = npe_loader_validate(loader, script);
        if (val_err != NPE_OK) {
            loader_log(loader, NPE_LOG_WARN,
                       "Validation failed for '%s': %s",
                       path, npe_error_string(val_err));
            npe_script_destroy(&script);
            loader->stats.files_failed++;
            continue;
        }

        /* Register the script into the registry */
        npe_error_t reg_err = npe_registry_add_script(registry, script);
        if (reg_err != NPE_OK) {
            loader_log(loader, NPE_LOG_WARN,
                       "Failed to register script '%s': %s",
                       script->filename, npe_error_string(reg_err));
            npe_script_destroy(&script);
            loader->stats.files_failed++;
            continue;
        }

        loader->stats.files_loaded++;
    }

    double t_end = loader_time_ms();
    loader->stats.load_time_ms = t_end - t_start;

    loader_log(loader, NPE_LOG_INFO,
               "Load complete: %zu loaded, %zu failed, %.1f ms",
               loader->stats.files_loaded,
               loader->stats.files_failed,
               loader->stats.load_time_ms);

    /* Step 3: Optionally rebuild the script database */
    if (loader->update_db && loader->stats.files_loaded > 0) {
        npe_error_t db_err = npe_loader_build_database(loader, registry);
        if (db_err != NPE_OK) {
            loader_log(loader, NPE_LOG_WARN,
                       "Failed to update script.db: %s",
                       npe_error_string(db_err));
            /* Non-fatal: scripts are still loaded in memory */
        }
    }

    return NPE_OK;
}

/*============================================================================
 * npe_loader_build_database
 *============================================================================*/

npe_error_t npe_loader_build_database(npe_loader_t         *loader,
                                      const npe_registry_t *registry)
{
    if (!loader || !registry) return NPE_ERROR_INVALID_ARG;

    FILE *fp = fopen(loader->script_db_path, "wb");
    if (!fp) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Cannot open script.db for writing: '%s': %s",
                   loader->script_db_path, strerror(errno));
        return NPE_ERROR_IO;
    }

    /* Write magic header */
    if (fwrite(LOADER_DB_MAGIC, 1, LOADER_DB_MAGIC_LEN, fp) != LOADER_DB_MAGIC_LEN) {
        fclose(fp);
        return NPE_ERROR_IO;
    }

    /* Write timestamp */
    time_t now = time(NULL);
    fprintf(fp, "# Generated: %s", ctime(&now));
    fprintf(fp, "# Format: name|path|categories|checksum|"
                "prerule|hostrule|portrule|postrule|action|"
                "dependencies\n");

    /* Iterate over all scripts in the registry */
    size_t script_count = npe_registry_script_count(registry);
    npe_registry_iter_t *iter = npe_registry_script_iter_begin(registry);
    const npe_script_t *script;
    while ((script = npe_registry_script_iter_next(iter)) != NULL) {
        /* Build category string */
        char cat_buf[512];
        loader_categories_to_string(script->meta.categories,
                                    cat_buf, sizeof(cat_buf));

        /* Build dependency string */
        char dep_buf[2048];
        dep_buf[0] = '\0';
        size_t dep_off = 0;
        for (size_t d = 0; d < script->meta.dependency_count; d++) {
            int n = snprintf(dep_buf + dep_off, sizeof(dep_buf) - dep_off,
                             "%s%s",
                             d > 0 ? "," : "",
                             script->meta.dependencies[d]);
            if (n < 0 || (size_t)n >= sizeof(dep_buf) - dep_off) break;
            dep_off += (size_t)n;
        }

        /* Write entry line */
        fprintf(fp, "Entry %s %s %s %016llx %d %d %d %d %d %s\n",
                script->filename,
                script->source.path ? script->source.path : "",
                cat_buf[0] ? cat_buf : "none",
                (unsigned long long)script->source.checksum,
                script->meta.has_prerule  ? 1 : 0,
                script->meta.has_hostrule ? 1 : 0,
                script->meta.has_portrule ? 1 : 0,
                script->meta.has_postrule ? 1 : 0,
                script->meta.has_action   ? 1 : 0,
                dep_buf[0] ? dep_buf : "none");
    }
    npe_registry_script_iter_end(iter);


    fclose(fp);

    loader_log(loader, NPE_LOG_INFO,
               "Built script.db with %zu entries at '%s'",
               script_count, loader->script_db_path);

    return NPE_OK;
}

/*============================================================================
 * npe_loader_load_database
 *============================================================================*/

npe_error_t npe_loader_load_database(npe_loader_t   *loader,
                                     npe_registry_t *registry)
{
    if (!loader || !registry) return NPE_ERROR_INVALID_ARG;

    FILE *fp = fopen(loader->script_db_path, "rb");
    if (!fp) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Cannot open script.db for reading: '%s': %s",
                   loader->script_db_path, strerror(errno));
        return NPE_ERROR_IO;
    }

    /* Verify magic header */
    char magic[LOADER_DB_MAGIC_LEN + 1];
    memset(magic, 0, sizeof(magic));
    size_t nread = fread(magic, 1, LOADER_DB_MAGIC_LEN, fp);
    if (nread != LOADER_DB_MAGIC_LEN ||
        memcmp(magic, LOADER_DB_MAGIC, LOADER_DB_MAGIC_LEN) != 0) {
        loader_log(loader, NPE_LOG_ERROR,
                   "Invalid script.db magic header in '%s'",
                   loader->script_db_path);
        fclose(fp);
        return NPE_ERROR_PARSE;
    }

    double t_start = loader_time_ms();
    size_t loaded   = 0;
    size_t failed   = 0;

    char line[8192];
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        /* Parse "Entry" lines */
        if (strncmp(line, "Entry ", 6) != 0)
            continue;

        char name[NPE_MAX_SCRIPT_NAME];
        char path[4096];
        char cats[512];
        unsigned long long checksum;
        int prerule, hostrule, portrule, postrule, action;
        char deps[2048];

        int matched = sscanf(line, "Entry %255s %4095s %511s %llx %d %d %d %d %d %2047s",
                             name, path, cats, &checksum,
                             &prerule, &hostrule, &portrule, &postrule, &action,
                             deps);
        if (matched < 9) {
            loader_log(loader, NPE_LOG_WARN,
                       "Malformed script.db entry: %.80s...", line);
            failed++;
            continue;
        }
        if (matched < 10) {
            deps[0] = '\0';
        }

        /* Verify the file still exists and try to load it */
        struct stat st;
        if (stat(path, &st) != 0) {
            loader_log(loader, NPE_LOG_WARN,
                       "Script file no longer exists: '%s'", path);
            failed++;
            continue;
        }

        /* Load the script from disk to get full source and fresh metadata */
        npe_script_t *script = NULL;
        npe_error_t err = npe_loader_load_script(loader, path, &script);
        if (err != NPE_OK) {
            loader_log(loader, NPE_LOG_WARN,
                       "Failed to reload script '%s' from db entry: %s",
                       path, npe_error_string(err));
            failed++;
            continue;
        }

        /* Optionally cross-check the checksum to detect changes */
        if (script->source.checksum != (uint64_t)checksum) {
            loader_log(loader, NPE_LOG_WARN,
                       "Checksum mismatch for '%s': db=%016llx file=%016llx "
                       "(using fresh metadata)",
                       name, checksum,
                       (unsigned long long)script->source.checksum);
        }

        /* Validate */
        npe_error_t val_err = npe_loader_validate(loader, script);
        if (val_err != NPE_OK) {
            loader_log(loader, NPE_LOG_WARN,
                       "Validation failed for db entry '%s'", name);
            npe_script_destroy(&script);
            failed++;
            continue;
        }

        /* Register */
        npe_error_t reg_err = npe_registry_add_script(registry, script);
        if (reg_err != NPE_OK) {
            loader_log(loader, NPE_LOG_WARN,
                       "Failed to register script '%s' from db", name);
            npe_script_destroy(&script);
            failed++;
            continue;
        }

        loaded++;
    }

    fclose(fp);

    double t_end = loader_time_ms();

    loader->stats.files_found  = loaded + failed;
    loader->stats.files_loaded = loaded;
    loader->stats.files_failed = failed;
    loader->stats.load_time_ms = t_end - t_start;

    loader_log(loader, NPE_LOG_INFO,
               "Loaded %zu scripts from script.db (%zu failed), %.1f ms",
               loaded, failed, loader->stats.load_time_ms);

    return NPE_OK;
}

/*============================================================================
 * npe_loader_get_stats
 *============================================================================*/

npe_error_t npe_loader_get_stats(const npe_loader_t *loader,
                                 npe_loader_stats_t *stats)
{
    if (!loader || !stats) return NPE_ERROR_INVALID_ARG;

    *stats = loader->stats;
    return NPE_OK;
}
