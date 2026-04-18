#define _POSIX_C_SOURCE 200809L

#include "subenum/wordlist.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *np_builtin_words[] = {
    "www", "mail", "api", "dev", "staging", "test", "beta", "portal",
    "admin", "app", "cdn", "m", "blog", "vpn", "mx", "ns1", "ns2",
    "gateway", "auth", "sso", "ftp", "git", "jenkins", "grafana"
};

static int is_valid_label(const char *s)
{
    size_t i;
    size_t len;
    if (!s)
        return 0;
    len = strlen(s);
    if (len == 0 || len > 63)
        return 0;
    for (i = 0; i < len; i++)
    {
        char c = s[i];
        if (!(isalnum((unsigned char)c) || c == '-'))
            return 0;
    }
    return 1;
}

static int ensure_cap(np_wordlist_t *wl, size_t needed)
{
    char **tmp;
    size_t new_cap;
    if (wl->capacity >= needed)
        return 1;

    new_cap = wl->capacity ? wl->capacity * 2 : 128;
    while (new_cap < needed)
        new_cap *= 2;

    tmp = realloc(wl->words, new_cap * sizeof(*tmp));
    if (!tmp)
        return 0;
    wl->words = tmp;
    wl->capacity = new_cap;
    return 1;
}

static int append_word(np_wordlist_t *wl, const char *word)
{
    char *dup;
    if (!is_valid_label(word))
        return 1;
    if (!ensure_cap(wl, wl->count + 1))
        return 0;
    dup = strdup(word);
    if (!dup)
        return 0;
    wl->words[wl->count++] = dup;
    return 1;
}

np_wordlist_t *np_wordlist_load_file(const char *path)
{
    FILE *fp;
    np_wordlist_t *wl;
    char line[512];

    if (!path)
        return NULL;

    fp = fopen(path, "r");
    if (!fp)
        return NULL;

    wl = calloc(1, sizeof(*wl));
    if (!wl)
    {
        fclose(fp);
        return NULL;
    }

    while (fgets(line, sizeof(line), fp))
    {
        char *p = line;
        char *nl;
        while (*p && isspace((unsigned char)*p))
            p++;
        if (*p == '#' || *p == '\0')
            continue;
        nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (!append_word(wl, p))
            break;
    }

    fclose(fp);
    return wl;
}

np_wordlist_t *np_wordlist_load_builtin(void)
{
    size_t i;
    np_wordlist_t *wl = calloc(1, sizeof(*wl));
    if (!wl)
        return NULL;

    for (i = 0; i < sizeof(np_builtin_words) / sizeof(np_builtin_words[0]); i++)
    {
        if (!append_word(wl, np_builtin_words[i]))
            break;
    }

    return wl;
}

void np_wordlist_free(np_wordlist_t *wl)
{
    size_t i;
    if (!wl)
        return;

    for (i = 0; i < wl->count; i++)
        free(wl->words[i]);
    free(wl->words);
    free(wl);
}
