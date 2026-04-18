#include <lua.h>
#include <lauxlib.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool str_eq_ci(const char *a, const char *b)
{
    if (!a || !b) return false;
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if ((char)tolower(ca) != (char)tolower(cb)) return false;
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

static bool str_contains_ci(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return false;
    if (*needle == '\0') return true;

    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i] != '\0'; i++) {
        size_t j = 0;
        while (j < needle_len && haystack[i + j] != '\0') {
            unsigned char hc = (unsigned char)haystack[i + j];
            unsigned char nc = (unsigned char)needle[j];
            if ((char)tolower(hc) != (char)tolower(nc)) {
                break;
            }
            j++;
        }
        if (j == needle_len) {
            return true;
        }
    }
    return false;
}

static const char *scheme_for_service_port(const char *service, lua_Integer port)
{
    if (service && (str_eq_ci(service, "https") || str_eq_ci(service, "ssl") || str_eq_ci(service, "tls"))) {
        return "https";
    }
    if (port == 443 || port == 8443) {
        return "https";
    }
    return "http";
}

static void normalize_path_value(const char *in, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;

    if (!in || in[0] == '\0') {
        snprintf(out, out_sz, "/");
        return;
    }

    while (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n') {
        in++;
    }

    if (*in == '\0') {
        snprintf(out, out_sz, "/");
        return;
    }

    if (in[0] != '/') {
        snprintf(out, out_sz, "/%s", in);
    } else {
        snprintf(out, out_sz, "%s", in);
    }
}

static int l_scheme_for_port(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);

    const char *service = NULL;
    lua_Integer port = 0;

    lua_getfield(L, 1, "service");
    if (lua_isstring(L, -1)) {
        service = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, 1, "number");
    if (lua_isinteger(L, -1)) {
        port = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);

    lua_pushstring(L, scheme_for_service_port(service, port));
    return 1;
}

static int l_build_url(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);
    luaL_checktype(L, 2, LUA_TTABLE);
    const char *path_arg = luaL_optstring(L, 3, "/");

    const char *ip = NULL;
    const char *service = NULL;
    lua_Integer port = 0;

    lua_getfield(L, 1, "ip");
    if (lua_isstring(L, -1)) ip = lua_tostring(L, -1);
    lua_pop(L, 1);

    if (!ip || ip[0] == '\0') {
        lua_getfield(L, 1, "hostname");
        if (lua_isstring(L, -1)) ip = lua_tostring(L, -1);
        lua_pop(L, 1);
    }

    lua_getfield(L, 2, "service");
    if (lua_isstring(L, -1)) service = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, 2, "number");
    if (lua_isinteger(L, -1)) port = lua_tointeger(L, -1);
    lua_pop(L, 1);

    if (!ip || ip[0] == '\0') {
        return luaL_error(L, "build_url: host.ip or host.hostname is required");
    }
    if (port <= 0 || port > 65535) {
        return luaL_error(L, "build_url: valid port.number is required");
    }

    char path[1024];
    normalize_path_value(path_arg, path, sizeof(path));

    char url[2048];
    snprintf(url, sizeof(url), "%s://%s:%lld%s",
             scheme_for_service_port(service, port), ip, (long long)port, path);
    lua_pushstring(L, url);
    return 1;
}

static int l_target(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);
    luaL_checktype(L, 2, LUA_TTABLE);

    const char *ip = NULL;
    lua_Integer port = 0;

    lua_getfield(L, 1, "ip");
    if (lua_isstring(L, -1)) ip = lua_tostring(L, -1);
    lua_pop(L, 1);

    if (!ip || ip[0] == '\0') {
        lua_getfield(L, 1, "hostname");
        if (lua_isstring(L, -1)) ip = lua_tostring(L, -1);
        lua_pop(L, 1);
    }

    lua_getfield(L, 2, "number");
    if (lua_isinteger(L, -1)) port = lua_tointeger(L, -1);
    lua_pop(L, 1);

    if (!ip || ip[0] == '\0' || port <= 0 || port > 65535) {
        return luaL_error(L, "target: host.ip and port.number are required");
    }

    char out[1024];
    snprintf(out, sizeof(out), "%s:%lld", ip, (long long)port);
    lua_pushstring(L, out);
    return 1;
}

static int l_normalize_path(lua_State *L)
{
    const char *in = luaL_optstring(L, 1, "/");
    char out[1024];
    normalize_path_value(in, out, sizeof(out));
    lua_pushstring(L, out);
    return 1;
}

static void trim_in_place(char *s)
{
    if (!s) return;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        memmove(s, s + 1, strlen(s));
    }
    size_t len = strlen(s);
    while (len > 0) {
        char c = s[len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        s[len - 1] = '\0';
        len--;
    }
}

static int l_csv_to_table(lua_State *L)
{
    const char *csv = luaL_optstring(L, 1, "");
    char *copy = strdup(csv ? csv : "");
    if (!copy) {
        return luaL_error(L, "csv_to_table: out of memory");
    }

    lua_newtable(L);
    int idx = 1;

    char *cursor = copy;
    while (cursor && *cursor) {
        char *comma = strchr(cursor, ',');
        if (comma) {
            *comma = '\0';
        }

        trim_in_place(cursor);
        if (cursor[0] != '\0') {
            lua_pushstring(L, cursor);
            lua_rawseti(L, -2, idx++);
        }

        if (!comma) break;
        cursor = comma + 1;
    }

    free(copy);
    return 1;
}

static int l_arg_number(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);
    const char *key = luaL_checkstring(L, 2);
    lua_Number def = luaL_optnumber(L, 3, 0);

    bool has_min = !lua_isnoneornil(L, 4);
    bool has_max = !lua_isnoneornil(L, 5);
    lua_Number min_v = has_min ? luaL_checknumber(L, 4) : 0;
    lua_Number max_v = has_max ? luaL_checknumber(L, 5) : 0;

    lua_Number value = def;
    lua_getfield(L, 1, key);
    if (lua_isnumber(L, -1)) {
        value = lua_tonumber(L, -1);
    } else if (lua_isstring(L, -1)) {
        size_t slen = 0;
        const char *s = lua_tolstring(L, -1, &slen);
        if (s && slen > 0) {
            char *endptr = NULL;
            double parsed = strtod(s, &endptr);
            if (endptr && endptr != s) {
                value = (lua_Number)parsed;
            }
        }
    }
    lua_pop(L, 1);

    if (has_min && value < min_v) value = min_v;
    if (has_max && value > max_v) value = max_v;

    lua_pushnumber(L, value);
    return 1;
}

static int l_arg_bool(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);
    const char *key = luaL_checkstring(L, 2);
    int def = lua_toboolean(L, 3);

    int value = def;
    lua_getfield(L, 1, key);
    if (lua_isboolean(L, -1)) {
        value = lua_toboolean(L, -1);
    } else if (lua_isnumber(L, -1)) {
        value = (lua_tonumber(L, -1) != 0);
    } else if (lua_isstring(L, -1)) {
        const char *s = lua_tostring(L, -1);
        if (s) {
            if (str_eq_ci(s, "1") || str_eq_ci(s, "true") || str_eq_ci(s, "yes") || str_eq_ci(s, "on")) {
                value = 1;
            } else if (str_eq_ci(s, "0") || str_eq_ci(s, "false") || str_eq_ci(s, "no") || str_eq_ci(s, "off")) {
                value = 0;
            }
        }
    }
    lua_pop(L, 1);

    lua_pushboolean(L, value);
    return 1;
}

static int l_indicator_match(lua_State *L)
{
    const char *text = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);

    size_t n = lua_rawlen(L, 2);
    for (size_t i = 1; i <= n; i++) {
        lua_rawgeti(L, 2, (lua_Integer)i);
        if (lua_isstring(L, -1)) {
            const char *needle = lua_tostring(L, -1);
            if (needle && needle[0] != '\0' && str_contains_ci(text, needle)) {
                lua_pop(L, 1);
                lua_pushboolean(L, 1);
                lua_pushstring(L, needle);
                return 2;
            }
        }
        lua_pop(L, 1);
    }

    lua_pushboolean(L, 0);
    lua_pushnil(L);
    return 2;
}

static int l_default_wordlist_small(lua_State *L)
{
    static const char *paths[] = {
        "/admin", "/admin/", "/admin/login", "/login", "/dashboard",
        "/manage", "/manager", "/backup", "/backups", "/config",
        "/.env", "/.git/", "/phpinfo.php", "/test", "/dev",
        "/staging", "/api", "/api/v1", "/uploads", "/private",
        "/old", "/db", "/server-status", "/status", "/console",
        NULL
    };

    lua_newtable(L);
    for (size_t i = 0; paths[i] != NULL; i++) {
        lua_pushstring(L, paths[i]);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

static int l_extract_forms(lua_State *L)
{
    size_t html_len = 0;
    const char *html = luaL_checklstring(L, 1, &html_len);

    char *lower = (char *)malloc(html_len + 1);
    if (!lower) {
        return luaL_error(L, "extract_forms: out of memory");
    }

    for (size_t i = 0; i < html_len; i++) {
        lower[i] = (char)tolower((unsigned char)html[i]);
    }
    lower[html_len] = '\0';

    lua_newtable(L);
    int out_idx = 1;
    size_t cursor = 0;

    while (cursor < html_len) {
        char *start_ptr = strstr(lower + cursor, "<form");
        if (!start_ptr) break;

        size_t start = (size_t)(start_ptr - lower);
        char *end_ptr = strstr(lower + start, "</form>");
        size_t end;

        if (end_ptr) {
            end = (size_t)(end_ptr - lower) + strlen("</form>");
        } else {
            char *tag_end = strchr(lower + start, '>');
            if (!tag_end) {
                break;
            }
            end = (size_t)(tag_end - lower) + 1;
        }

        if (end > start && end <= html_len) {
            lua_pushlstring(L, html + start, end - start);
            lua_rawseti(L, -2, out_idx++);
        }

        cursor = end;
    }

    free(lower);
    return 1;
}

static int l_has_csrf_token(lua_State *L)
{
    const char *form = luaL_checkstring(L, 1);
    static const char *token_markers[] = {
        "csrf",
        "_token",
        "authenticity_token",
        "xsrf",
        "requestverificationtoken",
        "__requestverificationtoken",
        NULL
    };

    for (size_t i = 0; token_markers[i] != NULL; i++) {
        if (str_contains_ci(form, token_markers[i])) {
            lua_pushboolean(L, 1);
            return 1;
        }
    }

    lua_pushboolean(L, 0);
    return 1;
}

int luaopen_npe_intrusive(lua_State *L)
{
    static const luaL_Reg funcs[] = {
        {"scheme_for_port", l_scheme_for_port},
        {"build_url", l_build_url},
        {"target", l_target},
        {"normalize_path", l_normalize_path},
        {"csv_to_table", l_csv_to_table},
        {"arg_number", l_arg_number},
        {"arg_bool", l_arg_bool},
        {"indicator_match", l_indicator_match},
        {"default_wordlist_small", l_default_wordlist_small},
        {"extract_forms", l_extract_forms},
        {"has_csrf_token", l_has_csrf_token},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
