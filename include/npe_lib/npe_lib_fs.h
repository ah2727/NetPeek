/**
 * =============================================================================
 * @file npe_lib_fs.h
 * @brief NPE Filesystem Library — Sandboxed, Read-Only File Access
 * =============================================================================
 *
 * Provides strictly controlled, read-only filesystem access for NPE scripts.
 * This is the MOST security-sensitive library in the entire NPE stack.
 *
 * SECURITY MODEL:
 *
 *   1. READ-ONLY — No write, create, delete, rename, or chmod operations
 *      are exposed. There are no functions that modify the filesystem.
 *
 *   2. WHITELISTED DIRECTORIES — Files may only be read from explicitly
 *      approved base directories:
 *        - scripts/    (NPE script directory — for helper data)
 *        - data/       (wordlists, fingerprints, payloads)
 *
 *   3. NO ABSOLUTE PATHS — All paths MUST be relative. Any path beginning
 *      with '/' or containing a drive letter (e.g. "C:\") is rejected.
 *
 *   4. NO PATH TRAVERSAL — Paths containing ".." are rejected outright,
 *      BEFORE any further processing. This is a hard deny, not a
 *      canonicalization attempt.
 *
 *   5. NO SYMLINK FOLLOWING — After constructing the resolved path, the
 *      library verifies (via realpath()) that the final destination still
 *      resides within an allowed directory. Symlinks pointing outside
 *      the sandbox are rejected.
 *
 *   6. FILE SIZE CAP — Reads are limited to NPE_FS_MAX_READ_SIZE bytes.
 *      This prevents a script from consuming unbounded memory by reading
 *      a multi-gigabyte file.
 *
 * Lua API exposed as global table "fs":
 *
 *   fs.read(path)       Read entire file contents (string | nil, err)
 *   fs.exists(path)     Check if file exists (boolean)
 *   fs.lines(path)      Iterator over file lines (function | nil, err)
 *   fs.size(path)       Get file size in bytes (number | nil, err)
 *   fs.list(path)       List directory entries (table | nil, err)
 *   fs.is_file(path)    Check if path is a regular file (boolean)
 *   fs.is_dir(path)     Check if path is a directory (boolean)
 *   fs.basename(path)   Extract filename from path (string)
 *   fs.dirname(path)    Extract directory from path (string)
 *   fs.extension(path)  Extract file extension (string)
 *
 * All functions that accept a path will:
 *   1. Validate the path against sandbox rules.
 *   2. On violation, return nil + descriptive error (never crash).
 *   3. On I/O error, return nil + system error message.
 *
 * Thread Safety:
 *   All functions are thread-safe. No shared mutable state.
 *   File operations use stack-local FILE* handles.
 *
 * @author  NetPeek Team
 * @version 1.0.0
 * =============================================================================
 */

#ifndef NPE_LIB_FS_H
#define NPE_LIB_FS_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =============================================================================
 * CONSTANTS AND LIMITS
 * =============================================================================*/

/**
 * Maximum file size (bytes) that fs.read() will load into memory.
 * Files larger than this cause fs.read() to return nil + error.
 * Default: 8 MiB.
 */
#define NPE_FS_MAX_READ_SIZE       (8 * 1024 * 1024)

/**
 * Maximum path length accepted by the sandbox validator.
 * Paths longer than this are rejected immediately.
 */
#define NPE_FS_MAX_PATH_LEN        4096

/**
 * Maximum length of a single line returned by fs.lines() iterator.
 * Lines exceeding this are truncated at the boundary.
 */
#define NPE_FS_MAX_LINE_LEN        (64 * 1024)

/**
 * Maximum number of directory entries returned by fs.list().
 * Prevents memory exhaustion from listing enormous directories.
 */
#define NPE_FS_MAX_DIR_ENTRIES      4096

/**
 * Maximum number of whitelisted base directories.
 */
#define NPE_FS_MAX_ALLOWED_DIRS     8


/* =============================================================================
 * SANDBOX CONFIGURATION
 * =============================================================================*/

/**
 * Sandbox configuration controlling which directories are readable.
 *
 * Populated during engine initialization (npe_engine_init) and shared
 * across all script executions (read-only after init — no mutex needed).
 *
 * Usage:
 *   npe_fs_sandbox_t sandbox;
 *   npe_fs_sandbox_init(&sandbox);
 *   npe_fs_sandbox_allow(&sandbox, "scripts/");
 *   npe_fs_sandbox_allow(&sandbox, "data/");
 */
typedef struct npe_fs_sandbox {
    /**
     * Array of absolute, resolved allowed directory prefixes.
     * Stored as canonical paths (via realpath()) with trailing '/'.
     * e.g. "/home/user/NetPeek/scripts/"
     */
    char    allowed_dirs[NPE_FS_MAX_ALLOWED_DIRS][NPE_FS_MAX_PATH_LEN];

    /** Number of directories currently in the whitelist. */
    size_t  allowed_count;

    /** Maximum file read size override (0 = use NPE_FS_MAX_READ_SIZE). */
    size_t  max_read_size;

    /** Whether to follow symlinks (default: false for maximum safety). */
    bool    follow_symlinks;
} npe_fs_sandbox_t;


/* =============================================================================
 * ERROR CODES
 * =============================================================================*/

typedef enum npe_fs_error {
    NPE_FS_OK                      =  0,   /**< Success                    */
    NPE_FS_ERR_NULL_PATH           = -1,   /**< NULL path argument         */
    NPE_FS_ERR_PATH_TOO_LONG      = -2,   /**< Path exceeds max length    */
    NPE_FS_ERR_ABSOLUTE_PATH      = -3,   /**< Absolute path rejected     */
    NPE_FS_ERR_PATH_TRAVERSAL     = -4,   /**< ".." detected in path      */
    NPE_FS_ERR_OUTSIDE_SANDBOX    = -5,   /**< Path resolves outside allowed dirs */
    NPE_FS_ERR_SYMLINK_ESCAPE     = -6,   /**< Symlink resolves outside sandbox   */
    NPE_FS_ERR_NOT_FOUND          = -7,   /**< File or directory not found */
    NPE_FS_ERR_NOT_FILE           = -8,   /**< Path is not a regular file  */
    NPE_FS_ERR_NOT_DIR            = -9,   /**< Path is not a directory     */
    NPE_FS_ERR_TOO_LARGE          = -10,  /**< File exceeds max read size  */
    NPE_FS_ERR_OPEN_FAILED        = -11,  /**< fopen() failed              */
    NPE_FS_ERR_READ_FAILED        = -12,  /**< fread() failed              */
    NPE_FS_ERR_STAT_FAILED        = -13,  /**< stat() failed               */
    NPE_FS_ERR_DIR_OPEN_FAILED    = -14,  /**< opendir() failed            */
    NPE_FS_ERR_ALLOC_FAILED       = -15,  /**< Memory allocation failed    */
    NPE_FS_ERR_SANDBOX_FULL       = -16,  /**< Whitelist is at capacity    */
    NPE_FS_ERR_RESOLVE_FAILED     = -17   /**< realpath() failed           */
} npe_fs_error_t;


/* =============================================================================
 * SANDBOX MANAGEMENT (C API)
 *
 * Called by npe_engine.c during initialization.
 * =============================================================================*/

/**
 * Initialize a sandbox configuration to safe defaults.
 *
 * Sets allowed_count to 0, max_read_size to NPE_FS_MAX_READ_SIZE,
 * follow_symlinks to false.
 *
 * @param sandbox   Sandbox structure to initialize.
 */
void npe_fs_sandbox_init(npe_fs_sandbox_t *sandbox);

/**
 * Add a directory to the sandbox whitelist.
 *
 * The path is resolved to its canonical absolute form via realpath().
 * A trailing '/' is ensured for prefix matching.
 *
 * @param sandbox   Sandbox configuration.
 * @param dir       Relative or absolute directory path to allow.
 * @return          NPE_FS_OK on success, or:
 *                  NPE_FS_ERR_NULL_PATH        - dir is NULL
 *                  NPE_FS_ERR_RESOLVE_FAILED   - realpath() failed
 *                  NPE_FS_ERR_NOT_DIR          - path is not a directory
 *                  NPE_FS_ERR_SANDBOX_FULL     - whitelist at capacity
 */
npe_fs_error_t npe_fs_sandbox_allow(npe_fs_sandbox_t *sandbox,
                                    const char *dir);

/**
 * Validate a path against the sandbox rules.
 *
 * Performs the full validation chain:
 *   1. Non-NULL check
 *   2. Length check
 *   3. Absolute path rejection
 *   4. Path traversal rejection (..)
 *   5. Canonical resolution (realpath)
 *   6. Prefix match against allowed directories
 *   7. Symlink escape detection (if follow_symlinks is false)
 *
 * @param sandbox       Active sandbox configuration.
 * @param path          Path to validate (relative).
 * @param resolved      Buffer to receive the resolved absolute path.
 *                      Must be at least NPE_FS_MAX_PATH_LEN bytes.
 *                      Filled only on NPE_FS_OK.
 * @param resolved_len  Size of the resolved buffer.
 * @return              NPE_FS_OK if path is allowed, or specific error.
 */
npe_fs_error_t npe_fs_sandbox_validate(const npe_fs_sandbox_t *sandbox,
                                       const char *path,
                                       char *resolved,
                                       size_t resolved_len);

/**
 * Set the global sandbox used by all Lua fs.* calls.
 *
 * This must be called once during engine init, before any scripts run.
 * The pointer is stored globally (read-only after init).
 *
 * @param sandbox   Pointer to an initialized sandbox. Must remain valid
 *                  for the entire engine lifetime.
 */
void npe_fs_set_global_sandbox(const npe_fs_sandbox_t *sandbox);

/**
 * Get the currently active global sandbox.
 *
 * @return  Pointer to the active sandbox, or NULL if not yet set.
 */
const npe_fs_sandbox_t *npe_fs_get_global_sandbox(void);


/* =============================================================================
 * INTERNAL C FILE OPERATIONS
 *
 * Used by the Lua-facing functions and available to other NPE C modules
 * (e.g. npe_loader.c may use npe_fs_read_file to load script contents).
 * All functions enforce sandbox rules.
 * =============================================================================*/

/**
 * Read the entire contents of a sandboxed file into a newly allocated buffer.
 *
 * The caller is responsible for freeing the returned buffer via free().
 *
 * @param sandbox       Active sandbox configuration.
 * @param path          Relative path to the file.
 * @param[out] buf      Set to point at the allocated buffer on success.
 *                      Set to NULL on failure.
 * @param[out] len      Set to the file size in bytes on success.
 * @return              NPE_FS_OK on success, or specific error code.
 */
npe_fs_error_t npe_fs_read_file(const npe_fs_sandbox_t *sandbox,
                                const char *path,
                                char **buf, size_t *len);

/**
 * Check if a file exists within the sandbox.
 *
 * @param sandbox   Active sandbox configuration.
 * @param path      Relative path to check.
 * @return          true if the path exists and passes sandbox validation.
 */
bool npe_fs_file_exists(const npe_fs_sandbox_t *sandbox, const char *path);

/**
 * Get the size in bytes of a sandboxed file.
 *
 * @param sandbox       Active sandbox configuration.
 * @param path          Relative path.
 * @param[out] size     File size in bytes.
 * @return              NPE_FS_OK on success, or specific error code.
 */
npe_fs_error_t npe_fs_file_size(const npe_fs_sandbox_t *sandbox,
                                const char *path, size_t *size);

/**
 * Check whether a sandboxed path is a regular file.
 *
 * @param sandbox   Active sandbox configuration.
 * @param path      Relative path.
 * @return          true if the path is a regular file within the sandbox.
 */
bool npe_fs_is_file(const npe_fs_sandbox_t *sandbox, const char *path);

/**
 * Check whether a sandboxed path is a directory.
 *
 * @param sandbox   Active sandbox configuration.
 * @param path      Relative path.
 * @return          true if the path is a directory within the sandbox.
 */
bool npe_fs_is_dir(const npe_fs_sandbox_t *sandbox, const char *path);

/**
 * Return the human-readable error message for a filesystem error code.
 *
 * @param err   Error code.
 * @return      Static string. Never NULL.
 */
const char *npe_fs_strerror(npe_fs_error_t err);


/* =============================================================================
 * PATH UTILITY FUNCTIONS
 *
 * Pure string operations — no filesystem access, no sandbox needed.
 * =============================================================================*/

/**
 * Extract the filename (basename) component from a path.
 *
 * @param path      Input path string.
 * @param buf       Output buffer.
 * @param buflen    Size of output buffer.
 * @return          Pointer to buf on success, NULL if buf too small.
 *
 * Example: "scripts/default/banner-grab.npe" -> "banner-grab.npe"
 */
const char *npe_fs_basename(const char *path, char *buf, size_t buflen);

/**
 * Extract the directory component from a path.
 *
 * @param path      Input path string.
 * @param buf       Output buffer.
 * @param buflen    Size of output buffer.
 * @return          Pointer to buf on success, NULL if buf too small.
 *
 * Example: "scripts/default/banner-grab.npe" -> "scripts/default"
 */
const char *npe_fs_dirname(const char *path, char *buf, size_t buflen);

/**
 * Extract the file extension (including the dot).
 *
 * @param path      Input path string.
 * @param buf       Output buffer.
 * @param buflen    Size of output buffer.
 * @return          Pointer to buf, or "" if no extension found.
 *
 * Example: "banner-grab.npe" -> ".npe"
 */
const char *npe_fs_extension(const char *path, char *buf, size_t buflen);


/* =============================================================================
 * LUA-FACING API FUNCTIONS
 *
 * Each is a lua_CFunction suitable for luaL_Reg registration.
 * All sandbox enforcement is handled internally.
 *
 * Return conventions:
 *   - Success: pushes the result value.
 *   - Failure: pushes nil, then an error message string.
 *   - Boolean queries: always push a boolean (never nil).
 * =============================================================================*/

/**
 * fs.read(path) -> string | nil, errmsg
 *
 * Reads the entire contents of a file and returns it as a Lua string.
 * Subject to sandbox path validation and file size limits.
 *
 * Lua usage:
 *   local content, err = fs.read("data/wordlists/common.txt")
 *   if not content then
 *       print("Error: " .. err)
 *   end
 */
int npe_lua_fs_read(lua_State *L);

/**
 * fs.exists(path) -> boolean
 *
 * Returns true if the path exists within the sandbox, false otherwise.
 * Never returns nil — always a boolean.
 *
 * Lua usage:
 *   if fs.exists("data/wordlists/common.txt") then
 *       -- load it
 *   end
 */
int npe_lua_fs_exists(lua_State *L);

/**
 * fs.lines(path) -> iterator_function | nil, errmsg
 *
 * Returns an iterator function that yields one line per call,
 * stripping the trailing newline. Returns nil when EOF is reached.
 *
 * The internal FILE* handle is stored as a Lua userdata with a __gc
 * metamethod, ensuring the file is closed even if the loop is broken
 * early or an error occurs.
 *
 * Lua usage:
 *   for line in fs.lines("data/wordlists/common.txt") do
 *       -- process each line
 *   end
 */
int npe_lua_fs_lines(lua_State *L);

/**
 * fs.size(path) -> number | nil, errmsg
 *
 * Returns the file size in bytes as a Lua number.
 *
 * Lua usage:
 *   local sz, err = fs.size("data/wordlists/common.txt")
 *   print("File is " .. sz .. " bytes")
 */
int npe_lua_fs_size(lua_State *L);

/**
 * fs.list(path) -> table | nil, errmsg
 *
 * Returns a table (array) of filenames in the given directory.
 * Excludes "." and "..". Limited to NPE_FS_MAX_DIR_ENTRIES entries.
 * Each entry is a plain filename string (not a full path).
 *
 * Lua usage:
 *   local entries, err = fs.list("scripts/default/")
 *   for _, name in ipairs(entries) do
 *       print(name)
 *   end
 */
int npe_lua_fs_list(lua_State *L);

/**
 * fs.is_file(path) -> boolean
 *
 * Returns true if the path is a regular file within the sandbox.
 *
 * Lua usage:
 *   if fs.is_file("scripts/default/banner-grab.npe") then ...
 */
int npe_lua_fs_is_file(lua_State *L);

/**
 * fs.is_dir(path) -> boolean
 *
 * Returns true if the path is a directory within the sandbox.
 *
 * Lua usage:
 *   if fs.is_dir("scripts/vuln/") then ...
 */
int npe_lua_fs_is_dir(lua_State *L);

/**
 * fs.basename(path) -> string
 *
 * Extracts the filename from a path. Pure string operation.
 *
 * Lua usage:
 *   local name = fs.basename("scripts/default/banner-grab.npe")
 *   -- name == "banner-grab.npe"
 */
int npe_lua_fs_basename(lua_State *L);

/**
 * fs.dirname(path) -> string
 *
 * Extracts the directory portion from a path. Pure string operation.
 *
 * Lua usage:
 *   local dir = fs.dirname("scripts/default/banner-grab.npe")
 *   -- dir == "scripts/default"
 */
int npe_lua_fs_dirname(lua_State *L);

/**
 * fs.extension(path) -> string
 *
 * Extracts the file extension (including the dot). Pure string operation.
 * Returns empty string if no extension is present.
 *
 * Lua usage:
 *   local ext = fs.extension("banner-grab.npe")
 *   -- ext == ".npe"
 */
int npe_lua_fs_extension(lua_State *L);


/* =============================================================================
 * LINE ITERATOR INTERNALS
 *
 * The fs.lines() function returns a closure that captures a FILE* handle
 * wrapped in a Lua full userdata. These structures and helpers manage
 * the lifecycle of that handle.
 * =============================================================================*/

/**
 * Userdata type name for the line iterator FILE* handle.
 * Used with luaL_checkudata() / luaL_newmetatable().
 */
#define NPE_FS_LINE_ITER_TYPENAME  "npe.fs.line_iter"

/**
 * Internal structure stored as Lua userdata for the line iterator.
 */
typedef struct npe_fs_line_iter {
    FILE   *fp;         /**< Open file handle (NULL after close)     */
    char   *buf;        /**< Reusable line buffer                    */
    size_t  buflen;     /**< Allocated size of buf                   */
    bool    closed;     /**< Set to true after fclose()              */
} npe_fs_line_iter_t;

/**
 * __gc metamethod for the line iterator userdata.
 * Ensures the FILE* handle is closed when the iterator is collected.
 */
int npe_lua_fs_line_iter_gc(lua_State *L);

/**
 * Iterator function called by Lua's generic for loop.
 * Reads one line, pushes it as a string, or returns nil at EOF.
 */
int npe_lua_fs_line_iter_next(lua_State *L);


/* =============================================================================
 * LIBRARY REGISTRATION
 * =============================================================================*/

/**
 * Lua function table for the "fs" library.
 *
 * Exposed here so the engine can enumerate available functions.
 * Terminated by {NULL, NULL} sentinel.
 */
extern const luaL_Reg npe_lib_fs_funcs[];

/**
 * Register the "fs" library into a Lua state.
 *
 * Creates a global table named "fs" with all filesystem functions.
 * Also registers the line iterator metatable for __gc handling.
 *
 * Must be called after luaL_newstate() and after the sandbox has been
 * configured via npe_fs_set_global_sandbox().
 *
 * Typical call site (npe_runtime.c):
 *   npe_lib_fs_register(L);
 *
 * @param L     Active Lua state.
 * @return      1 (the library table is left on the Lua stack).
 */
int npe_lib_fs_register(lua_State *L);


#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_FS_H */
