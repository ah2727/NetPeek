#ifndef NP_SIG_LOADER_H
#define NP_SIG_LOADER_H

#include "os_sigload.h"

/*
 * Load multi-line block signatures (Nmap-style fingerprint blocks).
 *
 * Return values:
 *   1 => parsed at least one block signature
 *   0 => file does not look like block format (caller may fallback)
 *  -1 => parse/runtime error
 */
int np_sigloader_load_blocks(np_os_sigdb_t *db, const char *path);

#endif

