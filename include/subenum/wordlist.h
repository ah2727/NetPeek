#ifndef NP_SUBENUM_WORDLIST_H
#define NP_SUBENUM_WORDLIST_H

#include <stddef.h>

typedef struct
{
    char **words;
    size_t count;
    size_t capacity;
} np_wordlist_t;

np_wordlist_t *np_wordlist_load_file(const char *path);
np_wordlist_t *np_wordlist_load_builtin(void);
void np_wordlist_free(np_wordlist_t *wl);

#endif
