/**
 * =============================================================================
 * @file npe_lib_fs.c
 * @brief NPE Filesystem Library Implementation — Sandboxed Read-Only Access
 * =============================================================================
 */

#include "npe_lib_fs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#ifdef _WIN32
    #include <windows.h>
    #define realpath(N,R) _fullpath((R),(N),NPE_FS_MAX_PATH_LEN)
    #define stat _stat
    #define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
    #define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#else
    #include <unistd.h>
#endif

/* Global sandbox pointer (set once during init) */
static const npe_fs_sandbox_t *g_sandbox = NULL;

/* =============================================================================
 * SANDBOX MANAGEMENT
 * =============================================================================*/

void npe_fs_sandbox_init(npe_fs_sandbox_t *sandbox) {
    memset(sandbox, 0, sizeof(*sandbox));
    sandbox->max_read_size = NPE_FS_MAX_READ_SIZE;
    sandbox->follow_symlinks = false;
}

npe_fs_error_t npe_fs_sandbox_allow(npe_fs_sandbox_t *sandbox, const char *dir) {
    if (!dir) return NPE_FS_ERR_NULL_PATH;
    if (sandbox->allowed_count >= NPE_FS_MAX_ALLOWED_DIRS) return NPE_FS_ERR_SANDBOX_FULL;

    char resolved[NPE_FS_MAX_PATH_LEN];
    if (!realpath(dir, resolved)) return NPE_FS_ERR_RESOLVE_FAILED;

    struct stat st;
    if (stat(resolved, &st) != 0 || !S_ISDIR(st.st_mode)) return NPE_FS_ERR_NOT_DIR;

    size_t len = strlen(resolved);
    if (len >= NPE_FS_MAX_PATH_LEN - 1) return NPE_FS_ERR_PATH_TOO_LONG;

    strcpy(sandbox->allowed_dirs[sandbox->allowed_count], resolved);
    if (resolved[len - 1] != '/') {
        sandbox->allowed_dirs[sandbox->allowed_count][len] = '/';
        sandbox->allowed_dirs[sandbox->allowed_count][len + 1] = '\0';
    }
    sandbox->allowed_count++;
    return NPE_FS_OK;
}

npe_fs_error_t npe_fs_sandbox_validate(const npe_fs_sandbox_t *sandbox,const char *path,
                                       char *resolved,
                                       size_t resolved_len) {
    if (!path) return NPE_FS_ERR_NULL_PATH;
    if (strlen(path) >= NPE_FS_MAX_PATH_LEN) return NPE_FS_ERR_PATH_TOO_LONG;
    if (path[0] == '/' || (path[0] && path[1] == ':')) return NPE_FS_ERR_ABSOLUTE_PATH;
    if (strstr(path, "..")) return NPE_FS_ERR_PATH_TRAVERSAL;

    if (!realpath(path, resolved)) return NPE_FS_ERR_RESOLVE_FAILED;

    bool allowed = false;
    for (size_t i = 0; i < sandbox->allowed_count; i++) {
        if (strncmp(resolved, sandbox->allowed_dirs[i], strlen(sandbox->allowed_dirs[i])) == 0) {
            allowed = true;
            break;
        }
    }
    if (!allowed) return NPE_FS_ERR_OUTSIDE_SANDBOX;

    return NPE_FS_OK;
}

void npe_fs_set_global_sandbox(const npe_fs_sandbox_t *sandbox) {
    g_sandbox = sandbox;
}

const npe_fs_sandbox_t *npe_fs_get_global_sandbox(void) {
    return g_sandbox;
}

/* =============================================================================
 * ERROR MESSAGES
 * =============================================================================*/

const char *npe_fs_strerror(npe_fs_error_t err) {
    switch (err) {
        case NPE_FS_OK: return "Success";
        case NPE_FS_ERR_NULL_PATH: return "NULL path";
        case NPE_FS_ERR_PATH_TOO_LONG: return "Path too long";
        case NPE_FS_ERR_ABSOLUTE_PATH: return "Absolute paths not allowed";
        case NPE_FS_ERR_PATH_TRAVERSAL: return "Path traversal (..) not allowed";
        case NPE_FS_ERR_OUTSIDE_SANDBOX: return "Path outside sandbox";
        case NPE_FS_ERR_SYMLINK_ESCAPE: return "Symlink escapes sandbox";
        case NPE_FS_ERR_NOT_FOUND: return "File not found";
        case NPE_FS_ERR_NOT_FILE: return "Not a regular file";
        case NPE_FS_ERR_NOT_DIR: return "Not a directory";
        case NPE_FS_ERR_TOO_LARGE: return "File too large";
        case NPE_FS_ERR_OPEN_FAILED: return "Failed to open file";
        case NPE_FS_ERR_READ_FAILED: return "Failed to read file";
        case NPE_FS_ERR_STAT_FAILED: return "stat() failed";
        case NPE_FS_ERR_DIR_OPEN_FAILED: return "Failed to open directory";
        case NPE_FS_ERR_ALLOC_FAILED: return "Memory allocation failed";
        case NPE_FS_ERR_SANDBOX_FULL: return "Sandbox whitelist full";
        case NPE_FS_ERR_RESOLVE_FAILED: return "Path resolution failed";
        default: return "Unknown error";
    }
}

/* =============================================================================
 * INTERNAL FILE OPERATIONS
 * =============================================================================*/

npe_fs_error_t npe_fs_read_file(const npe_fs_sandbox_t *sandbox,
                                const char *path,
                                char **buf, size_t *len) {
    *buf = NULL;
    *len = 0;

    char resolved[NPE_FS_MAX_PATH_LEN];
    npe_fs_error_t err = npe_fs_sandbox_validate(sandbox, path, resolved, sizeof(resolved));
    if (err != NPE_FS_OK) return err;

    struct stat st;
    if (stat(resolved, &st) != 0) return NPE_FS_ERR_NOT_FOUND;
    if (!S_ISREG(st.st_mode)) return NPE_FS_ERR_NOT_FILE;

    size_t max_size = sandbox->max_read_size ? sandbox->max_read_size : NPE_FS_MAX_READ_SIZE;
    if ((size_t)st.st_size > max_size) return NPE_FS_ERR_TOO_LARGE;

    FILE *fp = fopen(resolved, "rb");
    if (!fp) return NPE_FS_ERR_OPEN_FAILED;

    char *data = malloc(st.st_size + 1);
    if (!data) {
        fclose(fp);
        return NPE_FS_ERR_ALLOC_FAILED;
    }

    size_t nread = fread(data, 1, st.st_size, fp);
    fclose(fp);

    if (nread != (size_t)st.st_size) {
        free(data);
        return NPE_FS_ERR_READ_FAILED;
    }

    data[nread] = '\0';
    *buf = data;
    *len = nread;
    return NPE_FS_OK;
}

bool npe_fs_file_exists(const npe_fs_sandbox_t *sandbox, const char *path) {
    char resolved[NPE_FS_MAX_PATH_LEN];
    if (npe_fs_sandbox_validate(sandbox, path, resolved, sizeof(resolved)) != NPE_FS_OK) return false;
    struct stat st;
    return stat(resolved, &st) == 0;
}

npe_fs_error_t npe_fs_file_size(const npe_fs_sandbox_t *sandbox,
                                const char *path, size_t *size) {
    char resolved[NPE_FS_MAX_PATH_LEN];
    npe_fs_error_t err = npe_fs_sandbox_validate(sandbox, path, resolved, sizeof(resolved));
    if (err != NPE_FS_OK) return err;

    struct stat st;
    if (stat(resolved, &st) != 0) return NPE_FS_ERR_NOT_FOUND;
    if (!S_ISREG(st.st_mode)) return NPE_FS_ERR_NOT_FILE;

    *size = st.st_size;
    return NPE_FS_OK;
}

bool npe_fs_is_file(const npe_fs_sandbox_t *sandbox, const char *path) {
    char resolved[NPE_FS_MAX_PATH_LEN];
    if (npe_fs_sandbox_validate(sandbox, path, resolved, sizeof(resolved)) != NPE_FS_OK) return false;
    struct stat st;
    return stat(resolved, &st) == 0 && S_ISREG(st.st_mode);
}

bool npe_fs_is_dir(const npe_fs_sandbox_t *sandbox, const char *path) {
    char resolved[NPE_FS_MAX_PATH_LEN];
    if (npe_fs_sandbox_validate(sandbox, path, resolved, sizeof(resolved)) != NPE_FS_OK) return false;
    struct stat st;
    return stat(resolved, &st) == 0 && S_ISDIR(st.st_mode);
}

/* =============================================================================
 * PATH UTILITIES
 * =============================================================================*/

const char *npe_fs_basename(const char *path, char *buf, size_t buflen) {
    const char *last = strrchr(path, '/');
    if (!last) last = strrchr(path, '\\');
    const char *name = last ? last + 1 : path;
    if (strlen(name) >= buflen) return NULL;
    strcpy(buf, name);
    return buf;
}

const char *npe_fs_dirname(const char *path, char *buf, size_t buflen) {
    const char *last = strrchr(path, '/');
    if (!last) last = strrchr(path, '\\');
    if (!last) {
        if (buflen < 2) return NULL;
        strcpy(buf, ".");
        return buf;
    }
    size_t len = last - path;
    if (len >= buflen) return NULL;
    memcpy(buf, path, len);
    buf[len] = '\0';
    return buf;
}

const char *npe_fs_extension(const char *path, char *buf, size_t buflen) {
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    if (!slash) slash = strrchr(path, '\\');
    if (!dot || (slash && dot < slash)) {
        if (buflen < 1) return NULL;
        buf[0] = '\0';
        return buf;
    }
    if (strlen(dot) >= buflen) return NULL;
    strcpy(buf, dot);
    return buf;
}

/* =============================================================================
 * LUA API FUNCTIONS
 * =============================================================================*/

int npe_lua_fs_read(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    char *buf;
    size_t len;
    npe_fs_error_t err = npe_fs_read_file(g_sandbox, path, &buf, &len);
    if (err != NPE_FS_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_fs_strerror(err));
        return 2;
    }
    lua_pushlstring(L, buf, len);
    free(buf);
    return 1;
}

int npe_lua_fs_exists(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    lua_pushboolean(L, npe_fs_file_exists(g_sandbox, path));
    return 1;
}

int npe_lua_fs_size(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    size_t size;
    npe_fs_error_t err = npe_fs_file_size(g_sandbox, path, &size);
    if (err != NPE_FS_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_fs_strerror(err));
        return 2;
    }
    lua_pushinteger(L, size);
    return 1;
}

int npe_lua_fs_is_file(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    lua_pushboolean(L, npe_fs_is_file(g_sandbox, path));
    return 1;
}

int npe_lua_fs_is_dir(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    lua_pushboolean(L, npe_fs_is_dir(g_sandbox, path));
    return 1;
}

int npe_lua_fs_list(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    char resolved[NPE_FS_MAX_PATH_LEN];
    npe_fs_error_t err = npe_fs_sandbox_validate(g_sandbox, path, resolved, sizeof(resolved));
    if (err != NPE_FS_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_fs_strerror(err));
        return 2;
    }

    DIR *dir = opendir(resolved);
    if (!dir) {
        lua_pushnil(L);
        lua_pushstring(L, npe_fs_strerror(NPE_FS_ERR_DIR_OPEN_FAILED));
        return 2;
    }

    lua_newtable(L);
    int idx = 1;
    struct dirent *ent;
    while ((ent = readdir(dir)) && idx <= NPE_FS_MAX_DIR_ENTRIES) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        lua_pushstring(L, ent->d_name);
        lua_rawseti(L, -2, idx++);
    }
    closedir(dir);
    return 1;
}

int npe_lua_fs_basename(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    char buf[NPE_FS_MAX_PATH_LEN];
    if (!npe_fs_basename(path, buf, sizeof(buf))) {
        lua_pushstring(L, "");
    } else {
        lua_pushstring(L, buf);
    }
    return 1;
}

int npe_lua_fs_dirname(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    char buf[NPE_FS_MAX_PATH_LEN];
    if (!npe_fs_dirname(path, buf, sizeof(buf))) {
        lua_pushstring(L, ".");
    } else {
        lua_pushstring(L, buf);
    }
    return 1;
}

int npe_lua_fs_extension(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    char buf[NPE_FS_MAX_PATH_LEN];
    if (!npe_fs_extension(path, buf, sizeof(buf))) {
        lua_pushstring(L, "");
    } else {
        lua_pushstring(L, buf);
    }
    return 1;
}

/* =============================================================================
 * LINE ITERATOR
 * =============================================================================*/

int npe_lua_fs_line_iter_gc(lua_State *L) {
    npe_fs_line_iter_t *iter = luaL_checkudata(L, 1, NPE_FS_LINE_ITER_TYPENAME);
    if (iter->fp && !iter->closed) {
        fclose(iter->fp);
        iter->closed = true;
    }
    if (iter->buf) {
        free(iter->buf);
        iter->buf = NULL;
    }
    return 0;
}

int npe_lua_fs_line_iter_next(lua_State *L) {
    npe_fs_line_iter_t *iter = lua_touserdata(L, lua_upvalueindex(1));
    if (!iter->fp || iter->closed) {
        lua_pushnil(L);
        return 1;
    }

    if (!fgets(iter->buf, iter->buflen, iter->fp)) {
        fclose(iter->fp);
        iter->closed = true;
        lua_pushnil(L);
        return 1;
    }

    size_t len = strlen(iter->buf);
    if (len > 0 && iter->buf[len - 1] == '\n') iter->buf[--len] = '\0';
    if (len > 0 && iter->buf[len - 1] == '\r') iter->buf[--len] = '\0';

    lua_pushlstring(L, iter->buf, len);
    return 1;
}

int npe_lua_fs_lines(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    char resolved[NPE_FS_MAX_PATH_LEN];
    npe_fs_error_t err = npe_fs_sandbox_validate(g_sandbox, path, resolved, sizeof(resolved));
    if (err != NPE_FS_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_fs_strerror(err));
        return 2;
    }

    FILE *fp = fopen(resolved, "r");
    if (!fp) {
        lua_pushnil(L);
        lua_pushstring(L, npe_fs_strerror(NPE_FS_ERR_OPEN_FAILED));
        return 2;
    }

    npe_fs_line_iter_t *iter = lua_newuserdata(L, sizeof(npe_fs_line_iter_t));
    iter->fp = fp;
    iter->buf = malloc(NPE_FS_MAX_LINE_LEN);
    iter->buflen = NPE_FS_MAX_LINE_LEN;
    iter->closed = false;

    luaL_getmetatable(L, NPE_FS_LINE_ITER_TYPENAME);
    lua_setmetatable(L, -2);

    lua_pushcclosure(L, npe_lua_fs_line_iter_next, 1);
    return 1;
}

/* =============================================================================
 * LIBRARY REGISTRATION
 * =============================================================================*/

const luaL_Reg npe_lib_fs_funcs[] = {
    {"read", npe_lua_fs_read},
    {"exists", npe_lua_fs_exists},
    {"lines", npe_lua_fs_lines},
    {"size", npe_lua_fs_size},
    {"list", npe_lua_fs_list},
    {"is_file", npe_lua_fs_is_file},
    {"is_dir", npe_lua_fs_is_dir},
    {"basename", npe_lua_fs_basename},
    {"dirname", npe_lua_fs_dirname},
    {"extension", npe_lua_fs_extension},
    {NULL, NULL}
};

int npe_lib_fs_register(lua_State *L) {
    luaL_newmetatable(L, NPE_FS_LINE_ITER_TYPENAME);
    lua_pushcfunction(L, npe_lua_fs_line_iter_gc);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);

    luaL_newlib(L, npe_lib_fs_funcs);
    lua_setglobal(L, "fs");
    lua_getglobal(L, "fs");
    return 1;
}
