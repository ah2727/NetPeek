#include <lua.h>
#include <lauxlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct brute_list {
    char **items;
    size_t count;
} brute_list_t;

static void brute_list_free(brute_list_t *list)
{
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static int brute_list_add(brute_list_t *list, const char *value)
{
    if (!list || !value || value[0] == '\0') return 0;

    char **next = realloc(list->items, (list->count + 1) * sizeof(char *));
    if (!next) return -1;
    list->items = next;

    list->items[list->count] = strdup(value);
    if (!list->items[list->count]) return -1;

    list->count++;
    return 0;
}

static void trim_line(char *line)
{
    size_t len;
    if (!line) return;

    while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') {
        memmove(line, line + 1, strlen(line));
    }

    len = strlen(line);
    while (len > 0) {
        char c = line[len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        line[len - 1] = '\0';
        len--;
    }
}

static int load_list_from_file(const char *path, brute_list_t *out)
{
    FILE *fp;
    char line[2048];

    if (!path || !out) return -1;

    fp = fopen(path, "r");
    if (!fp) return -1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_line(line);
        if (line[0] == '\0') continue;
        if (brute_list_add(out, line) != 0) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static int load_list_from_table(lua_State *L, int idx, brute_list_t *out)
{
    int abs = lua_absindex(L, idx);

    lua_pushnil(L);
    while (lua_next(L, abs) != 0) {
        if (lua_type(L, -1) == LUA_TSTRING) {
            const char *entry = lua_tostring(L, -1);
            if (entry && brute_list_add(out, entry) != 0) {
                lua_pop(L, 2);
                return -1;
            }
        }
        lua_pop(L, 1);
    }

    return 0;
}

static int load_list_from_field(lua_State *L,
                                int options_idx,
                                const char *field,
                                brute_list_t *out,
                                char *errbuf,
                                size_t errlen)
{
    int rc = 0;

    lua_getfield(L, options_idx, field);
    if (lua_type(L, -1) == LUA_TTABLE) {
        rc = load_list_from_table(L, -1, out);
        if (rc != 0) {
            snprintf(errbuf, errlen, "failed to parse '%s' table", field);
        }
    } else if (lua_type(L, -1) == LUA_TSTRING) {
        const char *path = lua_tostring(L, -1);
        if (load_list_from_file(path, out) != 0) {
            snprintf(errbuf, errlen, "failed to load '%s' file: %s", field, path ? path : "");
            rc = -1;
        }
    } else if (!lua_isnil(L, -1)) {
        snprintf(errbuf, errlen, "'%s' must be a table or file path", field);
        rc = -1;
    }

    lua_pop(L, 1);
    return rc;
}

static int l_brute_start(lua_State *L)
{
    int options_idx;
    int callback_idx;
    brute_list_t users = {0};
    brute_list_t passwords = {0};
    unsigned int delay_ms = 0;
    unsigned int max_attempts = 0;
    unsigned int attempts = 0;
    char errbuf[256] = {0};

    luaL_checktype(L, 1, LUA_TTABLE);
    options_idx = lua_absindex(L, 1);

    lua_getfield(L, options_idx, "login_function");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushstring(L, "brute.start requires login_function");
        return 2;
    }
    callback_idx = lua_absindex(L, -1);

    if (load_list_from_field(L, options_idx, "username_list", &users, errbuf, sizeof(errbuf)) != 0) {
        lua_pop(L, 1);
        brute_list_free(&users);
        brute_list_free(&passwords);
        lua_pushnil(L);
        lua_pushstring(L, errbuf[0] ? errbuf : "failed to load username_list");
        return 2;
    }

    if (load_list_from_field(L, options_idx, "password_list", &passwords, errbuf, sizeof(errbuf)) != 0) {
        lua_pop(L, 1);
        brute_list_free(&users);
        brute_list_free(&passwords);
        lua_pushnil(L);
        lua_pushstring(L, errbuf[0] ? errbuf : "failed to load password_list");
        return 2;
    }

    if (users.count == 0 || passwords.count == 0) {
        lua_pop(L, 1);
        brute_list_free(&users);
        brute_list_free(&passwords);
        lua_pushnil(L);
        lua_pushstring(L, "username_list and password_list must be provided and non-empty");
        return 2;
    }

    lua_getfield(L, options_idx, "delay");
    if (lua_isnumber(L, -1)) {
        long delay_val = lua_tointeger(L, -1);
        if (delay_val > 0) delay_ms = (unsigned int)delay_val;
    }
    lua_pop(L, 1);

    lua_getfield(L, options_idx, "max_attempts");
    if (lua_isnumber(L, -1)) {
        long max_val = lua_tointeger(L, -1);
        if (max_val > 0) max_attempts = (unsigned int)max_val;
    }
    lua_pop(L, 1);

    for (size_t ui = 0; ui < users.count; ui++) {
        for (size_t pi = 0; pi < passwords.count; pi++) {
            int pcall_rc;
            int success;

            if (max_attempts > 0 && attempts >= max_attempts) {
                goto done;
            }

            attempts++;

            lua_pushvalue(L, callback_idx);
            lua_pushstring(L, users.items[ui]);
            lua_pushstring(L, passwords.items[pi]);

            pcall_rc = lua_pcall(L, 2, 2, 0);
            if (pcall_rc != 0) {
                const char *lua_err = lua_tostring(L, -1);
                snprintf(errbuf, sizeof(errbuf), "login_function failed: %s", lua_err ? lua_err : "unknown error");
                lua_pop(L, 1);
                lua_pop(L, 1);
                brute_list_free(&users);
                brute_list_free(&passwords);
                lua_pushnil(L);
                lua_pushstring(L, errbuf);
                return 2;
            }

            success = lua_toboolean(L, -2);
            lua_pop(L, 2);

            if (success) {
                lua_pop(L, 1);
                lua_newtable(L);
                lua_pushboolean(L, 1);
                lua_setfield(L, -2, "success");
                lua_pushstring(L, users.items[ui]);
                lua_setfield(L, -2, "username");
                lua_pushstring(L, passwords.items[pi]);
                lua_setfield(L, -2, "password");
                lua_pushinteger(L, (lua_Integer)attempts);
                lua_setfield(L, -2, "attempts");
                brute_list_free(&users);
                brute_list_free(&passwords);
                return 1;
            }

            if (delay_ms > 0) {
                usleep((useconds_t)(delay_ms * 1000u));
            }
        }
    }

done:
    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "success");
    lua_pushinteger(L, (lua_Integer)attempts);
    lua_setfield(L, -2, "attempts");

    brute_list_free(&users);
    brute_list_free(&passwords);
    return 1;
}

int luaopen_npe_brute(lua_State *L)
{
    luaL_Reg funcs[] = {
        {"start", l_brute_start},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
