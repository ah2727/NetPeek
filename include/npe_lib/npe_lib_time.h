/**
 * =============================================================================
 * @file npe_lib_time.h
 * @brief NPE Time Library — Timing, Delays, and Elapsed Measurement
 * =============================================================================
 *
 * Provides high-resolution timing primitives for NPE scripts. All functions
 * are designed to be safe inside the sandbox — they never call system(),
 * exec(), or perform any privileged operation.
 *
 * Lua API exposed as global table "time":
 *
 *   time.now()              Current UNIX timestamp (float seconds)
 *   time.now_ms()           Current timestamp in milliseconds (integer)
 *   time.sleep(seconds)     Sleep for N seconds (float, e.g. 0.5)
 *   time.sleep_ms(ms)       Sleep for N milliseconds (integer)
 *   time.elapsed(start)     Seconds elapsed since 'start' (from time.now())
 *   time.monotonic()        Monotonic clock reading (not wall-clock)
 *   time.format(ts, fmt)    Format timestamp to string (strftime)
 *   time.parse(str, fmt)    Parse time string to timestamp
 *
 * Safety:
 *   - sleep functions clamp to a maximum of NPE_TIME_MAX_SLEEP_SEC to
 *     prevent scripts from blocking the engine indefinitely.
 *   - All clock access uses CLOCK_MONOTONIC where possible for elapsed
 *     measurements to avoid issues with system clock adjustments.
 *
 * Thread Safety:
 *   All functions are thread-safe. No shared mutable state.
 *
 * @author  NetPeek Team
 * @version 1.0.0
 * =============================================================================
 */

#ifndef NPE_LIB_TIME_H
#define NPE_LIB_TIME_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =============================================================================
 * CONSTANTS AND LIMITS
 * =============================================================================*/

/**
 * Maximum sleep duration a script may request (seconds).
 * Any value larger than this is silently clamped.
 * Prevents a rogue script from blocking the worker thread forever.
 */
#define NPE_TIME_MAX_SLEEP_SEC      30

/**
 * Maximum sleep duration in milliseconds (derived from above).
 */
#define NPE_TIME_MAX_SLEEP_MS       (NPE_TIME_MAX_SLEEP_SEC * 1000)

/**
 * Maximum format string length accepted by time.format().
 * Prevents unreasonably large format expansions.
 */
#define NPE_TIME_MAX_FMT_LEN       128

/**
 * Maximum formatted output length from time.format().
 */
#define NPE_TIME_MAX_FMT_OUTPUT     256

/**
 * Minimum sleep granularity in milliseconds.
 * Requests below this threshold are ignored (return immediately).
 */
#define NPE_TIME_MIN_SLEEP_MS       1

/**
 * Clock source preference for monotonic readings.
 * Falls back to CLOCK_REALTIME if CLOCK_MONOTONIC is unavailable.
 */
#ifdef CLOCK_MONOTONIC
#define NPE_TIME_CLOCK_SOURCE       CLOCK_MONOTONIC
#else
#define NPE_TIME_CLOCK_SOURCE       CLOCK_REALTIME
#endif


/* =============================================================================
 * ERROR CODES
 * =============================================================================*/

typedef enum npe_time_error {
    NPE_TIME_OK                 = 0,    /**< Success                         */
    NPE_TIME_ERR_INVALID_ARG   = -1,   /**< Bad argument (negative, NaN)    */
    NPE_TIME_ERR_CLOCK_FAIL    = -2,   /**< clock_gettime() failed          */
    NPE_TIME_ERR_SLEEP_FAIL    = -3,   /**< nanosleep() / usleep() failed   */
    NPE_TIME_ERR_FORMAT_FAIL   = -4,   /**< strftime() returned 0           */
    NPE_TIME_ERR_PARSE_FAIL    = -5,   /**< strptime() failed               */
    NPE_TIME_ERR_OVERFLOW      = -6    /**< Value would overflow            */
} npe_time_error_t;


/* =============================================================================
 * INTERNAL UTILITY STRUCTURES
 * =============================================================================*/

/**
 * High-resolution timestamp used internally.
 * Wraps struct timespec for easy arithmetic.
 */
typedef struct npe_time_stamp {
    int64_t     sec;        /**< Whole seconds                  */
    int64_t     nsec;       /**< Nanosecond fraction (0–999999999) */
} npe_time_stamp_t;


/* =============================================================================
 * INTERNAL C UTILITY FUNCTIONS
 *
 * These may be called by other NPE C modules (scheduler, engine).
 * They do NOT touch the Lua stack.
 * =============================================================================*/

/**
 * Read the current monotonic clock.
 *
 * @param[out] ts   Filled with current monotonic time.
 * @return          NPE_TIME_OK or NPE_TIME_ERR_CLOCK_FAIL.
 */
npe_time_error_t npe_time_monotonic_now(npe_time_stamp_t *ts);

/**
 * Read the current wall-clock (UNIX epoch) time.
 *
 * @param[out] ts   Filled with current real time.
 * @return          NPE_TIME_OK or NPE_TIME_ERR_CLOCK_FAIL.
 */
npe_time_error_t npe_time_realtime_now(npe_time_stamp_t *ts);

/**
 * Compute elapsed seconds between two timestamps.
 *
 * @param start     Earlier timestamp.
 * @param end       Later timestamp.
 * @return          Elapsed time in seconds (double precision).
 *                  Returns 0.0 if end <= start.
 */
double npe_time_elapsed_sec(const npe_time_stamp_t *start,
                            const npe_time_stamp_t *end);

/**
 * Compute elapsed milliseconds between two timestamps.
 *
 * @param start     Earlier timestamp.
 * @param end       Later timestamp.
 * @return          Elapsed time in milliseconds.
 *                  Returns 0 if end <= start.
 */
int64_t npe_time_elapsed_ms(const npe_time_stamp_t *start,
                            const npe_time_stamp_t *end);

/**
 * Sleep for the given duration (clamped to NPE_TIME_MAX_SLEEP_SEC).
 *
 * Handles EINTR by restarting the sleep for the remaining duration.
 *
 * @param seconds   Duration in fractional seconds. Clamped to max.
 *                  Negative values are treated as zero (immediate return).
 * @return          NPE_TIME_OK or NPE_TIME_ERR_SLEEP_FAIL.
 */
npe_time_error_t npe_time_sleep_sec(double seconds);

/**
 * Sleep for the given duration in milliseconds (clamped).
 *
 * @param ms        Duration in milliseconds.
 * @return          NPE_TIME_OK or NPE_TIME_ERR_SLEEP_FAIL.
 */
npe_time_error_t npe_time_sleep_msec(int64_t ms);

/**
 * Convert a UNIX epoch timestamp to a formatted string.
 *
 * @param ts        UNIX epoch seconds.
 * @param fmt       strftime format string (e.g. "%Y-%m-%d %H:%M:%S").
 * @param buf       Output buffer.
 * @param buflen    Size of output buffer.
 * @return          NPE_TIME_OK or error code.
 */
npe_time_error_t npe_time_format(double ts, const char *fmt,
                                 char *buf, size_t buflen);

/**
 * Parse a time string into a UNIX epoch timestamp.
 *
 * @param str       Input time string.
 * @param fmt       strptime format string.
 * @param[out] ts   Parsed UNIX timestamp.
 * @return          NPE_TIME_OK or NPE_TIME_ERR_PARSE_FAIL.
 */
npe_time_error_t npe_time_parse(const char *str, const char *fmt, double *ts);

/**
 * Return the human-readable error message for a time error code.
 *
 * @param err       Error code.
 * @return          Static string describing the error. Never NULL.
 */
const char *npe_time_strerror(npe_time_error_t err);


/* =============================================================================
 * LUA-FACING API FUNCTIONS
 *
 * Each of these is a lua_CFunction suitable for luaL_Reg registration.
 * They validate arguments from the Lua stack, call internal C functions,
 * and push results (or nil + error string) back to Lua.
 *
 * Lua signatures:
 *   time.now()              -> number (float seconds since epoch)
 *   time.now_ms()           -> integer (milliseconds since epoch)
 *   time.sleep(seconds)     -> nil  (sleeps, then returns)
 *   time.sleep_ms(ms)       -> nil
 *   time.elapsed(start)     -> number (seconds elapsed since start)
 *   time.monotonic()        -> number (monotonic clock seconds)
 *   time.format(ts, fmt)    -> string | nil, errmsg
 *   time.parse(str, fmt)    -> number | nil, errmsg
 * =============================================================================*/

/**
 * time.now() -> number
 *
 * Returns the current UNIX epoch timestamp as a floating-point number
 * with sub-second precision.
 *
 * Lua usage:
 *   local ts = time.now()
 *   print(ts)  -- e.g. 1710604800.123456
 */
int npe_lua_time_now(lua_State *L);

/**
 * time.now_ms() -> integer
 *
 * Returns the current UNIX epoch timestamp in whole milliseconds.
 *
 * Lua usage:
 *   local ms = time.now_ms()
 *   print(ms)  -- e.g. 1710604800123
 */
int npe_lua_time_now_ms(lua_State *L);

/**
 * time.sleep(seconds) -> nil
 *
 * Sleeps the current thread for the specified duration.
 * Accepts fractional seconds. Clamped to NPE_TIME_MAX_SLEEP_SEC.
 * Negative values and NaN are treated as zero (no sleep).
 *
 * Lua usage:
 *   time.sleep(0.5)   -- sleep 500ms
 *   time.sleep(2)     -- sleep 2 seconds
 */
int npe_lua_time_sleep(lua_State *L);

/**
 * time.sleep_ms(ms) -> nil
 *
 * Sleeps the current thread for the specified milliseconds.
 * Clamped to NPE_TIME_MAX_SLEEP_MS.
 *
 * Lua usage:
 *   time.sleep_ms(250)   -- sleep 250ms
 */
int npe_lua_time_sleep_ms(lua_State *L);

/**
 * time.elapsed(start) -> number
 *
 * Returns the wall-clock seconds elapsed since the given start timestamp
 * (as previously returned by time.now()).
 *
 * Lua usage:
 *   local start = time.now()
 *   -- ... do work ...
 *   local dt = time.elapsed(start)
 *   print("Took " .. dt .. " seconds")
 */
int npe_lua_time_elapsed(lua_State *L);

/**
 * time.monotonic() -> number
 *
 * Returns a monotonic clock reading in fractional seconds.
 * This clock is NOT related to wall-clock time — it only goes forward
 * and is suitable for measuring durations without being affected by
 * NTP adjustments or manual clock changes.
 *
 * Lua usage:
 *   local m1 = time.monotonic()
 *   -- ... do work ...
 *   local m2 = time.monotonic()
 *   print("Duration: " .. (m2 - m1))
 */
int npe_lua_time_monotonic(lua_State *L);

/**
 * time.format(ts, fmt) -> string | nil, errmsg
 *
 * Formats a UNIX timestamp into a human-readable string using
 * strftime-compatible format codes.
 *
 * @param ts    UNIX timestamp (number).
 * @param fmt   Format string (string), e.g. "%Y-%m-%d %H:%M:%S".
 *
 * Returns the formatted string on success, or nil + error message.
 *
 * Lua usage:
 *   local s = time.format(time.now(), "%Y-%m-%d %H:%M:%S")
 *   print(s)  -- e.g. "2026-03-16 14:30:00"
 */
int npe_lua_time_format(lua_State *L);

/**
 * time.parse(str, fmt) -> number | nil, errmsg
 *
 * Parses a time string into a UNIX epoch timestamp using
 * strptime-compatible format codes.
 *
 * @param str   Time string (string).
 * @param fmt   Format string (string).
 *
 * Returns the UNIX timestamp on success, or nil + error message.
 *
 * Lua usage:
 *   local ts = time.parse("2026-03-16 14:30:00", "%Y-%m-%d %H:%M:%S")
 */
int npe_lua_time_parse(lua_State *L);


/* =============================================================================
 * LIBRARY REGISTRATION
 * =============================================================================*/

/**
 * Lua function table for the "time" library.
 *
 * Used internally by npe_lib_time_register() but exposed here so
 * that the engine can inspect available functions at compile time.
 *
 * Terminated by a {NULL, NULL} sentinel entry.
 */
extern const luaL_Reg npe_lib_time_funcs[];

/**
 * Register the "time" library into a Lua state.
 *
 * Creates a global table named "time" containing all timing functions.
 * Must be called after luaL_newstate() and before script execution.
 *
 * Typical call site (npe_runtime.c):
 *   npe_lib_time_register(L);
 *
 * @param L     Active Lua state.
 * @return      1 (the library table is left on top of the stack).
 */
int npe_lib_time_register(lua_State *L);


#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_TIME_H */
