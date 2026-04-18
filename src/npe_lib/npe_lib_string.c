/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_lib_string.c — String Operations Library Implementation
 * =============================================================================
 */

#include "npe_lib_string.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <regex.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * CONSTANTS AND DEFINES
 * ============================================================================ */

#define NPE_STRING_MAX_LENGTH      (16 * 1024 * 1024)  /* 16MB max string */
#define NPE_STRING_MAX_SPLIT_PARTS 1024                /* Max split parts */
#define NPE_STRING_MAX_REPLACEMENTS 4096               /* Max replacements */

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static char *npe_string_duplicate(const char *str, size_t len) {
    char *dup = malloc(len + 1);
    if (!dup) return NULL;
    memcpy(dup, str, len);
    dup[len] = '\0';
    return dup;
}

static bool npe_string_starts_with(const char *str, const char *prefix) {
    size_t str_len = strlen(str);
    size_t prefix_len = strlen(prefix);
    
    if (prefix_len > str_len) return false;
    return strncmp(str, prefix, prefix_len) == 0;
}

static bool npe_string_ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return false;
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

/* ============================================================================
 * STRING SPLITTING
 * ============================================================================ */

int npe_lua_string_split(lua_State *L) {
    size_t str_len, delim_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *delim = luaL_checklstring(L, 2, &delim_len);
    int max_parts = luaL_optinteger(L, 3, NPE_STRING_MAX_SPLIT_PARTS);
    
    if (str_len > NPE_STRING_MAX_LENGTH) {
        lua_pushnil(L);
        lua_pushstring(L, "String too long");
        return 2;
    }
    
    if (delim_len == 0) {
        lua_pushnil(L);
        lua_pushstring(L, "Empty delimiter");
        return 2;
    }
    
    if (max_parts <= 0) {
        max_parts = NPE_STRING_MAX_SPLIT_PARTS;
    }
    
    lua_newtable(L);
    
    if (str_len == 0) {
        lua_pushstring(L, "");
        lua_rawseti(L, -2, 1);
        return 1;
    }
    
    const char *current = str;
    const char *end = str + str_len;
    int part_count = 0;
    
    while (current < end && part_count < max_parts - 1) {
        const char *found = strstr(current, delim);
        
        if (!found) {
            /* Last part */
            size_t remaining = end - current;
            lua_pushlstring(L, current, remaining);
            lua_rawseti(L, -2, ++part_count);
            break;
        } else {
            /* Found delimiter */
            size_t part_len = found - current;
            lua_pushlstring(L, current, part_len);
            lua_rawseti(L, -2, ++part_count);
            current = found + delim_len;
        }
    }
    
    /* Handle remaining as last part if we hit max_parts limit */
    if (current < end && part_count == max_parts - 1) {
        size_t remaining = end - current;
        lua_pushlstring(L, current, remaining);
        lua_rawseti(L, -2, ++part_count);
    }
    
    return 1;
}

/* ============================================================================
 * STRING TRIMMING
 * ============================================================================ */

int npe_lua_string_trim(lua_State *L) {
    size_t str_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *charset = luaL_optstring(L, 2, " \t\n\r\f\v");
    
    if (str_len == 0) {
        lua_pushstring(L, "");
        return 1;
    }
    
    /* Find start of non-whitespace */
    const char *start = str;
    while (start < str + str_len && strchr(charset, *start)) {
        start++;
    }
    
    /* Find end of non-whitespace */
    const char *end = str + str_len - 1;
    while (end >= start && strchr(charset, *end)) {
        end--;
    }
    
    if (end < start) {
        /* All whitespace */
        lua_pushstring(L, "");
        return 1;
    }
    
    size_t trimmed_len = end - start + 1;
    lua_pushlstring(L, start, trimmed_len);
    return 1;
}

int npe_lua_string_ltrim(lua_State *L) {
    size_t str_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *charset = luaL_optstring(L, 2, " \t\n\r\f\v");
    
    const char *start = str;
    while (start < str + str_len && strchr(charset, *start)) {
        start++;
    }
    
    size_t trimmed_len = (str + str_len) - start;
    lua_pushlstring(L, start, trimmed_len);
    return 1;
}

int npe_lua_string_rtrim(lua_State *L) {
    size_t str_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *charset = luaL_optstring(L, 2, " \t\n\r\f\v");
    
    if (str_len == 0) {
        lua_pushstring(L, "");
        return 1;
    }
    
    const char *end = str + str_len - 1;
    while (end >= str && strchr(charset, *end)) {
        end--;
    }
    
    if (end < str) {
        lua_pushstring(L, "");
        return 1;
    }
    
    size_t trimmed_len = end - str + 1;
    lua_pushlstring(L, str, trimmed_len);
    return 1;
}

/* ============================================================================
 * STRING MATCHING
 * ============================================================================ */

int npe_lua_string_contains(lua_State *L) {
    size_t str_len, pattern_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *pattern = luaL_checklstring(L, 2, &pattern_len);
    bool ignore_case = lua_toboolean(L, 3);
    
    if (pattern_len == 0) {
        lua_pushboolean(L, 1);
        return 1;
    }
    
    if (ignore_case) {
        /* Case-insensitive search */
        for (size_t i = 0; i <= str_len - pattern_len; i++) {
            if (strncasecmp(str + i, pattern, pattern_len) == 0) {
                lua_pushboolean(L, 1);
                return 1;
            }
        }
        lua_pushboolean(L, 0);
    } else {
        /* Case-sensitive search */
        bool found = (strstr(str, pattern) != NULL);
        lua_pushboolean(L, found);
    }
    
    return 1;
}

int npe_lua_string_starts_with(lua_State *L) {
    size_t str_len, prefix_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *prefix = luaL_checklstring(L, 2, &prefix_len);
    bool ignore_case = lua_toboolean(L, 3);
    
    if (prefix_len > str_len) {
        lua_pushboolean(L, 0);
        return 1;
    }
    
    bool result;
    if (ignore_case) {
        result = (strncasecmp(str, prefix, prefix_len) == 0);
    } else {
        result = (strncmp(str, prefix, prefix_len) == 0);
    }
    
    lua_pushboolean(L, result);
    return 1;
}

int npe_lua_string_ends_with(lua_State *L) {
    size_t str_len, suffix_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *suffix = luaL_checklstring(L, 2, &suffix_len);
    bool ignore_case = lua_toboolean(L, 3);
    
    if (suffix_len > str_len) {
        lua_pushboolean(L, 0);
        return 1;
    }
    
    const char *start = str + str_len - suffix_len;
    bool result;
    if (ignore_case) {
        result = (strncasecmp(start, suffix, suffix_len) == 0);
    } else {
        result = (strncmp(start, suffix, suffix_len) == 0);
    }
    
    lua_pushboolean(L, result);
    return 1;
}

int npe_lua_string_regex_match(lua_State *L) {
    size_t str_len, pattern_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *pattern = luaL_checklstring(L, 2, &pattern_len);
    int flags = luaL_optinteger(L, 3, 0);
    
    regex_t regex;
    int cflags = REG_EXTENDED;
    
    if (flags & 1) cflags |= REG_ICASE;    /* Case insensitive */
    if (flags & 2) cflags |= REG_NOSUB;    /* No subexpressions */
    if (flags & 4) cflags |= REG_NEWLINE;  /* Newline sensitive */
    
    int ret = regcomp(&regex, pattern, cflags);
    if (ret != 0) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "Invalid regex pattern");
        return 2;
    }
    
    regmatch_t matches[10];  /* Support up to 9 submatches */
    ret = regexec(&regex, str, 10, matches, 0);
    
    if (ret == 0) {
        /* Match found */
        lua_pushboolean(L, 1);
        
        /* Create matches table */
        lua_newtable(L);
        
        for (int i = 0; i < 10 && matches[i].rm_so != -1; i++) {
            int start = matches[i].rm_so;
            int end = matches[i].rm_eo;
            
            lua_newtable(L);
            lua_pushlstring(L, str + start, end - start);
            lua_setfield(L, -2, "match");
            lua_pushinteger(L, start + 1);  /* Lua is 1-indexed */
            lua_setfield(L, -2, "start");
            lua_pushinteger(L, end);
            lua_setfield(L, -2, "end");
            
            lua_rawseti(L, -2, i + 1);
        }
        
        regfree(&regex);
        return 2;
    } else {
        /* No match */
        regfree(&regex);
        lua_pushboolean(L, 0);
        return 1;
    }
}

/* ============================================================================
 * STRING REPLACEMENT
 * ============================================================================ */

int npe_lua_string_replace(lua_State *L) {
    size_t str_len, old_len, new_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    const char *old_str = luaL_checklstring(L, 2, &old_len);
    const char *new_str = luaL_checklstring(L, 3, &new_len);
    int max_replacements = luaL_optinteger(L, 4, NPE_STRING_MAX_REPLACEMENTS);
    bool ignore_case = lua_toboolean(L, 5);
    
    if (old_len == 0) {
        lua_pushvalue(L, 1);  /* Return original string */
        return 1;
    }
    
    if (str_len > NPE_STRING_MAX_LENGTH) {
        lua_pushnil(L);
        lua_pushstring(L, "String too long");
        return 2;
    }
    
    /* Count occurrences first */
    int count = 0;
    const char *pos = str;
    const char *end = str + str_len;
    
    while (pos <= end - old_len && count < max_replacements) {
        const char *found = NULL;
        
        if (ignore_case) {
            /* Manual case-insensitive search */
            for (const char *p = pos; p <= end - old_len; p++) {
                if (strncasecmp(p, old_str, old_len) == 0) {
                    found = p;
                    break;
                }
            }
        } else {
            found = strstr(pos, old_str);
        }
        
        if (!found || found > end - old_len) {
            break;
        }
        
        count++;
        pos = found + old_len;
    }
    
    if (count == 0) {
        lua_pushvalue(L, 1);  /* Return original string */
        return 1;
    }
    
    /* Calculate new string length */
    size_t new_str_len = str_len + count * (new_len - old_len);
    
    if (new_str_len > NPE_STRING_MAX_LENGTH) {
        lua_pushnil(L);
        lua_pushstring(L, "Result string would be too long");
        return 2;
    }
    
    /* Build new string */
    char *result = malloc(new_str_len + 1);
    if (!result) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    char *dest = result;
    const char *src = str;
    int replacements_done = 0;
    
    while (src < end && replacements_done < max_replacements) {
        const char *found = NULL;
        
        if (ignore_case) {
            for (const char *p = src; p <= end - old_len; p++) {
                if (strncasecmp(p, old_str, old_len) == 0) {
                    found = p;
                    break;
                }
            }
        } else {
            found = strstr(src, old_str);
        }
        
        if (!found || found > end - old_len) {
            /* Copy remaining */
            size_t remaining = end - src;
            memcpy(dest, src, remaining);
            dest += remaining;
            break;
        }
        
        /* Copy before match */
        size_t before_len = found - src;
        memcpy(dest, src, before_len);
        dest += before_len;
        
        /* Copy replacement */
        memcpy(dest, new_str, new_len);
        dest += new_len;
        
        /* Move past match */
        src = found + old_len;
        replacements_done++;
    }
    
    /* Copy any remaining part */
    if (src < end) {
        size_t remaining = end - src;
        memcpy(dest, src, remaining);
        dest += remaining;
    }
    
    *dest = '\0';
    
    lua_pushlstring(L, result, dest - result);
    free(result);
    
    return 1;
}

/* ============================================================================
 * STRING UTILITIES
 * ============================================================================ */

int npe_lua_string_reverse(lua_State *L) {
    size_t str_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    
    char *reversed = malloc(str_len + 1);
    if (!reversed) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    for (size_t i = 0; i < str_len; i++) {
        reversed[i] = str[str_len - 1 - i];
    }
    reversed[str_len] = '\0';
    
    lua_pushlstring(L, reversed, str_len);
    free(reversed);
    
    return 1;
}

int npe_lua_string_upper(lua_State *L) {
    size_t str_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    
    char *upper = malloc(str_len + 1);
    if (!upper) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    for (size_t i = 0; i < str_len; i++) {
        upper[i] = toupper((unsigned char)str[i]);
    }
    upper[str_len] = '\0';
    
    lua_pushlstring(L, upper, str_len);
    free(upper);
    
    return 1;
}

int npe_lua_string_lower(lua_State *L) {
    size_t str_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    
    char *lower = malloc(str_len + 1);
    if (!lower) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    for (size_t i = 0; i < str_len; i++) {
        lower[i] = tolower((unsigned char)str[i]);
    }
    lower[str_len] = '\0';
    
    lua_pushlstring(L, lower, str_len);
    free(lower);
    
    return 1;
}

int npe_lua_string_repeat(lua_State *L) {
    size_t str_len;
    const char *str = luaL_checklstring(L, 1, &str_len);
    int count = (int)luaL_checkinteger(L, 2);
    
    if (count < 0) {
        lua_pushstring(L, "");
        return 1;
    }
    
    if (count == 0) {
        lua_pushstring(L, "");
        return 1;
    }
    
    if (str_len == 0) {
        lua_pushstring(L, "");
        return 1;
    }
    
    /* Check for overflow */
    if (str_len > NPE_STRING_MAX_LENGTH / count) {
        lua_pushnil(L);
        lua_pushstring(L, "Result string would be too long");
        return 2;
    }
    
    size_t total_len = str_len * count;
    char *result = malloc(total_len + 1);
    if (!result) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    char *dest = result;
    for (int i = 0; i < count; i++) {
        memcpy(dest, str, str_len);
        dest += str_len;
    }
    *dest = '\0';
    
    lua_pushlstring(L, result, total_len);
    free(result);
    
    return 1;
}

int npe_lua_string_join(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    const char *separator = luaL_optstring(L, 2, "");
    size_t sep_len = strlen(separator);
    
    /* Count table elements */
    int count = 0;
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        count++;
        lua_pop(L, 1);
    }
    
    if (count == 0) {
        lua_pushstring(L, "");
        return 1;
    }
    
    /* Calculate total length needed */
    size_t total_len = 0;
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        size_t len;
        const char *str = lua_tolstring(L, -1, &len);
        if (str) {
            total_len += len;
        }
        lua_pop(L, 1);
    }
    
    /* Add separator lengths */
    if (count > 1) {
        total_len += (count - 1) * sep_len;
    }
    
    if (total_len > NPE_STRING_MAX_LENGTH) {
        lua_pushnil(L);
        lua_pushstring(L, "Result string would be too long");
        return 2;
    }
    
    /* Build result string */
    char *result = malloc(total_len + 1);
    if (!result) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    char *dest = result;
    bool first = true;
    
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        if (!first && sep_len > 0) {
            memcpy(dest, separator, sep_len);
            dest += sep_len;
        }
        
        size_t len;
        const char *str = lua_tolstring(L, -1, &len);
        if (str) {
            memcpy(dest, str, len);
            dest += len;
        }
        
        first = false;
        lua_pop(L, 1);
    }
    
    *dest = '\0';
    
    lua_pushlstring(L, result, dest - result);
    free(result);
    
    return 1;
}

/* ============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================ */

static const luaL_Reg string_functions[] = {
    /* Splitting */
    {"split",        npe_lua_string_split},
    
    /* Trimming */
    {"trim",         npe_lua_string_trim},
    {"ltrim",        npe_lua_string_ltrim},
    {"rtrim",        npe_lua_string_rtrim},
    
    /* Matching */
    {"contains",     npe_lua_string_contains},
    {"starts_with",  npe_lua_string_starts_with},
    {"ends_with",    npe_lua_string_ends_with},
    {"regex_match",  npe_lua_string_regex_match},
    
    /* Replacement */
    {"replace",      npe_lua_string_replace},
    
    /* Utilities */
    {"reverse",      npe_lua_string_reverse},
    {"upper",        npe_lua_string_upper},
    {"lower",        npe_lua_string_lower},
    {"repeat_str",   npe_lua_string_repeat},
    {"join",         npe_lua_string_join},
    
    {NULL, NULL}
};

int npe_lib_string_register(lua_State *L) {
    /* Create string module table */
    luaL_newlib(L, string_functions);
    
    /* Add constants */
    lua_pushinteger(L, NPE_STRING_MAX_LENGTH);
    lua_setfield(L, -2, "MAX_LENGTH");
    
    lua_pushinteger(L, NPE_STRING_MAX_SPLIT_PARTS);
    lua_setfield(L, -2, "MAX_SPLIT_PARTS");
    
    /* Regex flags */
    lua_pushinteger(L, 1);  /* Case insensitive */
    lua_setfield(L, -2, "REGEX_ICASE");
    
    lua_pushinteger(L, 2);  /* No subexpressions */
    lua_setfield(L, -2, "REGEX_NOSUB");
    
    lua_pushinteger(L, 4);  /* Newline sensitive */
    lua_setfield(L, -2, "REGEX_NEWLINE");
    
    return 1;
}
